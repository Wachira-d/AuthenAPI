using AuthenAPI.Data;
using AuthenAPI.Models;
using AuthenAPI.Utilities;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using Microsoft.EntityFrameworkCore;
using System.Text.Json;

namespace AuthenAPI.Services;

/// <summary>
/// Absolute paths used for persisted admin data
/// </summary>
public sealed class DataPaths
{
    public DataPaths(string dataDirectory) => DataDirectory = dataDirectory;

    public string DataDirectory { get; }
    public string RuntimeSettingsFile => Path.Combine(DataDirectory, "settings.runtime.json");
    public string ApiKeysFile => Path.Combine(DataDirectory, "api-keys.json");
    public string BackupsDirectory => Path.Combine(DataDirectory, "backups");
    public string DataProtectionKeysDirectory => Path.Combine(DataDirectory, "keys");
}

/// <summary>
/// Settings changed through the admin portal. Each section replaces the matching
/// appsettings.json section as a whole (lists are replaced, not merged).
/// </summary>
public class RuntimeOverrides
{
    public LdapSettingsDto? Ldap { get; set; }

    /// <summary>Service account password encrypted with ASP.NET Data Protection</summary>
    public string? LdapPasswordProtected { get; set; }

    public SecuritySettingsDto? Security { get; set; }
    public AuditSettingsDto? Audit { get; set; }
    public AdminSettingsDto? Admin { get; set; }
    public DateTime? UpdatedAt { get; set; }
    public string? UpdatedBy { get; set; }
}

/// <summary>
/// Loads and saves runtime setting overrides and notifies IOptionsMonitor consumers on change
/// </summary>
public sealed class RuntimeSettingsStore
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };
    private const int MaxBackups = 20;

    private readonly DataPaths _paths;
    private readonly Database _database;
    private readonly Timer? _pollTimer;
    private int _version;
    private readonly IDataProtector _protector;
    private readonly ILogger<RuntimeSettingsStore> _logger;
    private readonly object _lock = new();
    private RuntimeOverrides _current = new();
    private string? _ldapPassword;
    private CancellationTokenSource _changeSource = new();

    public RuntimeSettingsStore(DataPaths paths, Database database, IDataProtectionProvider dataProtection, ILogger<RuntimeSettingsStore> logger)
    {
        _paths = paths;
        _database = database;
        _protector = dataProtection.CreateProtector("AuthenAPI.RuntimeSettings.v1");
        _logger = logger;
        Load();

        if (_database.Enabled)
        {
            // Apply changes saved on other servers (and recover if the database was down at startup).
            _pollTimer = new Timer(_ => PollDatabase(), null, TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(30));
        }
    }

    public bool UsesDatabase => _database.Enabled;

    public RuntimeOverrides Current => _current;

    /// <summary>Decrypted service account password override, if any</summary>
    public string? LdapPasswordOverride => _ldapPassword;

    public IChangeToken GetChangeToken() => new CancellationChangeToken(_changeSource.Token);

    /// <summary>
    /// Apply a change and persist it. The previous file is copied to the backups folder first.
    /// </summary>
    public void Update(Action<RuntimeOverrides> mutate, string updatedBy, string? newLdapPassword = null)
    {
        lock (_lock)
        {
            var copy = Clone(_current);
            mutate(copy);

            if (!string.IsNullOrEmpty(newLdapPassword))
            {
                copy.LdapPasswordProtected = _protector.Protect(newLdapPassword);
            }

            copy.UpdatedAt = DateTime.UtcNow;
            copy.UpdatedBy = updatedBy;

            if (_database.Enabled)
            {
                _version = SaveToDatabase(copy, updatedBy);
                SaveCacheFile(copy);
            }
            else
            {
                Save(copy);
            }
            _current = copy;
            _ldapPassword = Unprotect(copy.LdapPasswordProtected);
        }

        NotifyChanged();
    }

    private void NotifyChanged()
    {
        var previous = Interlocked.Exchange(ref _changeSource, new CancellationTokenSource());
        previous.Cancel();
        previous.Dispose();
    }

    private void Load()
    {
        if (_database.Enabled && TryLoadFromDatabase(importFile: true)) return;
        LoadFromFile();
    }

    private bool TryLoadFromDatabase(bool importFile)
    {
        try
        {
            using var db = _database.CreateContext();
            var row = db.RuntimeSettings.AsNoTracking().FirstOrDefault(r => r.Id == 1);

            if (row == null)
            {
                if (importFile && File.Exists(_paths.RuntimeSettingsFile))
                {
                    var fromFile = JsonSerializer.Deserialize<RuntimeOverrides>(File.ReadAllText(_paths.RuntimeSettingsFile)) ?? new();
                    lock (_lock)
                    {
                        _version = SaveToDatabase(fromFile, fromFile.UpdatedBy ?? "import");
                        _current = fromFile;
                        _ldapPassword = Unprotect(fromFile.LdapPasswordProtected);
                    }
                    _logger.LogInformation("Imported runtime settings from {Path} into the database", _paths.RuntimeSettingsFile);
                }
                _database.ReportOk();
                return true;
            }

            var loaded = JsonSerializer.Deserialize<RuntimeOverrides>(row.Json) ?? new();
            lock (_lock)
            {
                _current = loaded;
                _version = row.Version;
                _ldapPassword = Unprotect(loaded.LdapPasswordProtected);
                SaveCacheFile(loaded);
            }
            _database.ReportOk();
            _logger.LogInformation("Loaded runtime settings v{Version} from the database (last change {UpdatedAt} by {UpdatedBy})",
                row.Version, row.UpdatedAt, row.UpdatedBy);
            return true;
        }
        catch (Exception ex)
        {
            _database.ReportError(ex);
            _logger.LogWarning("Could not load runtime settings from the database ({Error}); using the local copy",
                ex.GetBaseException().Message);
            return false;
        }
    }

    private void PollDatabase()
    {
        try
        {
            using var db = _database.CreateContext();
            var version = db.RuntimeSettings.Where(r => r.Id == 1).Select(r => (int?)r.Version).FirstOrDefault();
            if (version.HasValue && version.Value != _version && TryLoadFromDatabase(importFile: false))
            {
                _logger.LogInformation("Runtime settings changed on another server; applied v{Version}", version);
                NotifyChanged();
            }
        }
        catch (Exception ex)
        {
            _database.ReportError(ex);
        }
    }

    /// <summary>Upsert the single settings row and append a history entry; returns the new version</summary>
    private int SaveToDatabase(RuntimeOverrides overrides, string updatedBy)
    {
        using var db = _database.CreateContext();
        var json = JsonSerializer.Serialize(overrides);
        var row = db.RuntimeSettings.FirstOrDefault(r => r.Id == 1);
        if (row == null)
        {
            row = new RuntimeSettingsRow { Id = 1, Version = 0 };
            db.RuntimeSettings.Add(row);
        }

        row.Version++;
        row.Json = json;
        row.UpdatedAt = DateTime.UtcNow;
        row.UpdatedBy = updatedBy;
        db.RuntimeSettingsHistory.Add(new RuntimeSettingsHistoryRow
        {
            Version = row.Version,
            Json = json,
            ChangedAt = row.UpdatedAt,
            ChangedBy = updatedBy
        });
        db.SaveChanges();
        _database.ReportOk();
        return row.Version;
    }

    /// <summary>Local copy used when the database cannot be reached at startup</summary>
    private void SaveCacheFile(RuntimeOverrides overrides)
    {
        try
        {
            Directory.CreateDirectory(_paths.DataDirectory);
            var temp = _paths.RuntimeSettingsFile + ".tmp";
            File.WriteAllText(temp, JsonSerializer.Serialize(overrides, JsonOptions));
            File.Move(temp, _paths.RuntimeSettingsFile, overwrite: true);
        }
        catch (Exception ex)
        {
            _logger.LogWarning("Could not write local settings cache: {Error}", ex.Message);
        }
    }

    private void LoadFromFile()
    {
        try
        {
            if (!File.Exists(_paths.RuntimeSettingsFile)) return;

            var json = File.ReadAllText(_paths.RuntimeSettingsFile);
            _current = JsonSerializer.Deserialize<RuntimeOverrides>(json) ?? new RuntimeOverrides();
            _ldapPassword = Unprotect(_current.LdapPasswordProtected);
            _logger.LogInformation("Loaded runtime settings overrides from {Path} (last change {UpdatedAt} by {UpdatedBy})",
                _paths.RuntimeSettingsFile, _current.UpdatedAt, _current.UpdatedBy);
        }
        catch (Exception ex)
        {
            // A corrupt override file must not stop the API: fall back to appsettings.json.
            _logger.LogError(ex, "Failed to read runtime settings from {Path}. Using appsettings.json only.",
                _paths.RuntimeSettingsFile);
            _current = new RuntimeOverrides();
        }
    }

    private void Save(RuntimeOverrides overrides)
    {
        Directory.CreateDirectory(_paths.DataDirectory);

        if (File.Exists(_paths.RuntimeSettingsFile))
        {
            Directory.CreateDirectory(_paths.BackupsDirectory);
            var backup = Path.Combine(_paths.BackupsDirectory, $"settings.runtime.{DateTime.UtcNow:yyyyMMddHHmmssfff}.json");
            File.Copy(_paths.RuntimeSettingsFile, backup, overwrite: true);

            foreach (var old in Directory.GetFiles(_paths.BackupsDirectory, "settings.runtime.*.json")
                         .OrderByDescending(f => f).Skip(MaxBackups))
            {
                File.Delete(old);
            }
        }

        var temp = _paths.RuntimeSettingsFile + ".tmp";
        File.WriteAllText(temp, JsonSerializer.Serialize(overrides, JsonOptions));
        File.Move(temp, _paths.RuntimeSettingsFile, overwrite: true);
    }

    private string? Unprotect(string? value)
    {
        if (string.IsNullOrEmpty(value)) return null;
        try
        {
            return _protector.Unprotect(value);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex,
                "Cannot decrypt the service account password stored in runtime settings " +
                "(Data Protection keys changed?). Re-enter it in the admin portal.");
            return null;
        }
    }

    private static RuntimeOverrides Clone(RuntimeOverrides source) =>
        JsonSerializer.Deserialize<RuntimeOverrides>(JsonSerializer.Serialize(source)) ?? new RuntimeOverrides();
}

/// <summary>
/// Applies runtime overrides on top of the options bound from appsettings.json
/// </summary>
public sealed class RuntimeOverridesPostConfigure :
    IPostConfigureOptions<LdapSettings>,
    IPostConfigureOptions<SecuritySettings>,
    IPostConfigureOptions<AuditSettings>,
    IPostConfigureOptions<AdminSettings>
{
    private readonly RuntimeSettingsStore _store;

    public RuntimeOverridesPostConfigure(RuntimeSettingsStore store) => _store = store;

    public void PostConfigure(string? name, LdapSettings options)
    {
        if (_store.Current.Ldap is { } dto) SettingsMapper.Apply(dto, options);
        if (_store.LdapPasswordOverride is { Length: > 0 } password) options.ServiceAccountPassword = password;
    }

    public void PostConfigure(string? name, SecuritySettings options)
    {
        if (_store.Current.Security is { } dto) SettingsMapper.Apply(dto, options);
    }

    public void PostConfigure(string? name, AuditSettings options)
    {
        if (_store.Current.Audit is { } dto) SettingsMapper.Apply(dto, options);
    }

    public void PostConfigure(string? name, AdminSettings options)
    {
        if (_store.Current.Admin is { } dto) SettingsMapper.Apply(dto, options);
    }
}

/// <summary>
/// Tells IOptionsMonitor to rebuild options when runtime overrides are saved
/// </summary>
public sealed class RuntimeOverridesChangeTokenSource<T> : IOptionsChangeTokenSource<T>
{
    private readonly RuntimeSettingsStore _store;

    public RuntimeOverridesChangeTokenSource(RuntimeSettingsStore store) => _store = store;

    public string? Name => Options.DefaultName;

    public IChangeToken GetChangeToken() => _store.GetChangeToken();
}

/// <summary>
/// Converts between settings classes and the admin DTOs, and validates DTOs
/// </summary>
public static class SettingsMapper
{
    public static LdapSettingsDto ToDto(LdapSettings s) => new()
    {
        Server = s.Server,
        FallbackServers = s.FallbackServers.ToList(),
        Port = s.Port,
        UseSSL = s.UseSSL,
        BaseDN = s.BaseDN,
        Domain = s.Domain,
        NetBiosDomain = string.IsNullOrWhiteSpace(s.NetBiosDomain) ? null : s.NetBiosDomain,
        ServiceAccountUsername = s.ServiceAccountUsername,
        ServiceAccountPassword = string.Empty,
        ServiceAccountPasswordSet = !string.IsNullOrEmpty(s.ServiceAccountPassword),
        ConnectionTimeout = s.ConnectionTimeout,
        SkipCertificateValidation = s.SkipCertificateValidation,
        AllowInsecureFallback = s.AllowInsecureFallback,
        ChaseReferrals = s.ChaseReferrals,
        EnableCache = s.EnableCache,
        CacheDurationMinutes = s.CacheDurationMinutes
    };

    public static void Apply(LdapSettingsDto d, LdapSettings s)
    {
        s.Server = d.Server.Trim();
        s.FallbackServers = Clean(d.FallbackServers);
        s.Port = d.Port;
        s.UseSSL = d.UseSSL;
        s.BaseDN = d.BaseDN.Trim();
        s.Domain = d.Domain.Trim();
        s.NetBiosDomain = string.IsNullOrWhiteSpace(d.NetBiosDomain) ? null : d.NetBiosDomain.Trim();
        s.ServiceAccountUsername = d.ServiceAccountUsername.Trim();
        s.ConnectionTimeout = d.ConnectionTimeout;
        s.SkipCertificateValidation = d.SkipCertificateValidation;
        s.AllowInsecureFallback = d.AllowInsecureFallback;
        s.ChaseReferrals = d.ChaseReferrals;
        s.EnableCache = d.EnableCache;
        s.CacheDurationMinutes = d.CacheDurationMinutes;
    }

    public static SecuritySettingsDto ToDto(SecuritySettings s) => new()
    {
        EnableIpWhitelist = s.EnableIpWhitelist,
        AllowedIpAddresses = s.AllowedIpAddresses.ToList(),
        EnableApiKeyAuth = s.EnableApiKeyAuth,
        ApiKeyHeaderName = s.ApiKeyHeaderName,
        EnableRateLimiting = s.EnableRateLimiting,
        RateLimitMaxRequests = s.RateLimitMaxRequests,
        RateLimitWindowSeconds = s.RateLimitWindowSeconds
    };

    public static void Apply(SecuritySettingsDto d, SecuritySettings s)
    {
        s.EnableIpWhitelist = d.EnableIpWhitelist;
        s.AllowedIpAddresses = Clean(d.AllowedIpAddresses);
        s.EnableApiKeyAuth = d.EnableApiKeyAuth;
        s.ApiKeyHeaderName = d.ApiKeyHeaderName.Trim();
        s.EnableRateLimiting = d.EnableRateLimiting;
        s.RateLimitMaxRequests = d.RateLimitMaxRequests;
        s.RateLimitWindowSeconds = d.RateLimitWindowSeconds;
    }

    public static AuditSettingsDto ToDto(AuditSettings s) => new()
    {
        Enabled = s.Enabled,
        EnableFileLogging = s.EnableFileLogging,
        RetentionDays = s.RetentionDays,
        FailedLoginThreshold = s.FailedLoginThreshold,
        FailedLoginWindowMinutes = s.FailedLoginWindowMinutes,
        AutoPurgeEnabled = s.AutoPurgeEnabled,
        RequestLogRetentionDays = s.RequestLogRetentionDays
    };

    public static void Apply(AuditSettingsDto d, AuditSettings s)
    {
        s.Enabled = d.Enabled;
        s.EnableFileLogging = d.EnableFileLogging;
        s.RetentionDays = d.RetentionDays;
        s.FailedLoginThreshold = d.FailedLoginThreshold;
        s.FailedLoginWindowMinutes = d.FailedLoginWindowMinutes;
        s.AutoPurgeEnabled = d.AutoPurgeEnabled;
        s.RequestLogRetentionDays = d.RequestLogRetentionDays;
    }

    public static AdminSettingsDto ToDto(AdminSettings s) => new()
    {
        AdminUsers = s.AdminUsers.ToList(),
        ViewerUsers = s.ViewerUsers.ToList(),
        AdminGroups = s.AdminGroups.ToList(),
        ViewerGroups = s.ViewerGroups.ToList(),
        AllowedIpAddresses = s.AllowedIpAddresses.ToList(),
        SessionTimeoutMinutes = s.SessionTimeoutMinutes
    };

    public static void Apply(AdminSettingsDto d, AdminSettings s)
    {
        s.AdminUsers = Clean(d.AdminUsers);
        s.ViewerUsers = Clean(d.ViewerUsers);
        s.AdminGroups = Clean(d.AdminGroups);
        s.ViewerGroups = Clean(d.ViewerGroups);
        s.AllowedIpAddresses = Clean(d.AllowedIpAddresses);
        s.SessionTimeoutMinutes = d.SessionTimeoutMinutes;
    }

    public static List<string> Validate(LdapSettingsDto d)
    {
        var errors = new List<string>();
        if (string.IsNullOrWhiteSpace(d.Server)) errors.Add("server is required");
        if (d.Port is < 1 or > 65535) errors.Add("port must be 1-65535");
        if (string.IsNullOrWhiteSpace(d.BaseDN)) errors.Add("baseDN is required");
        if (string.IsNullOrWhiteSpace(d.Domain)) errors.Add("domain is required");
        if (string.IsNullOrWhiteSpace(d.ServiceAccountUsername)) errors.Add("serviceAccountUsername is required");
        if (d.ConnectionTimeout is < 1 or > 120) errors.Add("connectionTimeout must be 1-120 seconds");
        if (d.CacheDurationMinutes is < 0 or > 1440) errors.Add("cacheDurationMinutes must be 0-1440");
        return errors;
    }

    public static List<string> Validate(SecuritySettingsDto d)
    {
        var errors = ValidateIps(d.AllowedIpAddresses, "allowedIpAddresses");
        if (string.IsNullOrWhiteSpace(d.ApiKeyHeaderName) || !d.ApiKeyHeaderName.Trim().All(c => char.IsLetterOrDigit(c) || c == '-' || c == '_'))
        {
            errors.Add("apiKeyHeaderName must contain only letters, digits, '-' or '_'");
        }
        if (d.RateLimitMaxRequests is < 1 or > 1_000_000) errors.Add("rateLimitMaxRequests must be 1-1000000");
        if (d.RateLimitWindowSeconds is < 1 or > 3600) errors.Add("rateLimitWindowSeconds must be 1-3600");
        return errors;
    }

    public static List<string> Validate(AuditSettingsDto d)
    {
        var errors = new List<string>();
        if (d.RetentionDays is < 1 or > 3650) errors.Add("retentionDays must be 1-3650");
        if (d.RequestLogRetentionDays is < 1 or > 3650) errors.Add("requestLogRetentionDays must be 1-3650");
        if (d.FailedLoginThreshold is < 1 or > 1000) errors.Add("failedLoginThreshold must be 1-1000");
        if (d.FailedLoginWindowMinutes is < 1 or > 1440) errors.Add("failedLoginWindowMinutes must be 1-1440");
        return errors;
    }

    public static List<string> Validate(AdminSettingsDto d)
    {
        var errors = ValidateIps(d.AllowedIpAddresses, "allowedIpAddresses");
        if (d.SessionTimeoutMinutes is < 5 or > 1440) errors.Add("sessionTimeoutMinutes must be 5-1440");
        return errors;
    }

    public static List<string> ValidateIps(IEnumerable<string>? entries, string field)
    {
        return (entries ?? Enumerable.Empty<string>())
            .Where(e => !string.IsNullOrWhiteSpace(e) && !IpNetworkMatcher.TryParseEntry(e, out _, out _))
            .Select(e => $"{field}: '{e}' is not a valid IP address or CIDR range")
            .ToList();
    }

    private static List<string> Clean(IEnumerable<string>? values) =>
        (values ?? Enumerable.Empty<string>())
            .Select(v => v?.Trim() ?? string.Empty)
            .Where(v => v.Length > 0)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
}
