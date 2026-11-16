using AuthenAPI.Data;
using AuthenAPI.Models;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace AuthenAPI.Services;

/// <summary>
/// Registry of applications allowed to use single sign-on. Stored in App_Data/sso-clients.json,
/// or in dbo.SsoClients when the database is configured (reloaded every 30 s so servers stay in sync).
/// </summary>
public sealed partial class SsoClientService : IHostedService, IDisposable
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    private readonly DataPaths _paths;
    private readonly Database _database;
    private readonly ILogger<SsoClientService> _logger;
    private readonly object _lock = new();
    private readonly ConcurrentDictionary<string, long> _pendingLogins = new();
    private Dictionary<string, SsoClient> _clients = new(StringComparer.Ordinal);
    private Timer? _timer;

    public SsoClientService(DataPaths paths, Database database, ILogger<SsoClientService> logger)
    {
        _paths = paths;
        _database = database;
        _logger = logger;
        Load();
    }

    private string FilePath => Path.Combine(_paths.DataDirectory, "sso-clients.json");

    [GeneratedRegex("^[a-z0-9][a-z0-9._-]{1,63}$")]
    private static partial Regex ClientIdRegex();

    #region Queries used by the OIDC endpoints

    public SsoClient? FindActive(string? clientId)
    {
        if (string.IsNullOrEmpty(clientId)) return null;
        lock (_lock)
        {
            return _clients.TryGetValue(clientId, out var c) && c.IsActive ? c : null;
        }
    }

    public bool VerifySecret(SsoClient client, string? secret)
    {
        if (client.Type != SsoClientTypes.Confidential || client.SecretHash == null || string.IsNullOrEmpty(secret)) return false;
        return CryptographicOperations.FixedTimeEquals(Convert.FromHexString(Hash(secret)), Convert.FromHexString(client.SecretHash));
    }

    /// <summary>True when some active client registered this exact post-logout redirect URI</summary>
    public SsoClient? FindByPostLogoutUri(string uri, string? clientId)
    {
        lock (_lock)
        {
            return _clients.Values.FirstOrDefault(c => c.IsActive &&
                (clientId == null || c.ClientId == clientId) &&
                c.PostLogoutRedirectUris.Contains(uri, StringComparer.Ordinal));
        }
    }

    public void RecordLogin(string clientId) => _pendingLogins.AddOrUpdate(clientId, 1, (_, n) => n + 1);

    #endregion

    #region Management

    public List<SsoClientView> List()
    {
        lock (_lock)
        {
            return _clients.Values.OrderBy(c => c.DisplayName, StringComparer.OrdinalIgnoreCase).Select(ToView).ToList();
        }
    }

    public SsoClientView? Get(string clientId)
    {
        lock (_lock)
        {
            return _clients.TryGetValue(clientId, out var c) ? ToView(c) : null;
        }
    }

    public List<string> Validate(SsoClientInput input, bool creating)
    {
        var errors = new List<string>();
        if (creating)
        {
            if (string.IsNullOrWhiteSpace(input.ClientId) || !ClientIdRegex().IsMatch(input.ClientId.Trim()))
            {
                errors.Add("clientId must be 2-64 characters: lower-case letters, digits, '.', '_' or '-'");
            }
            else
            {
                lock (_lock)
                {
                    if (_clients.ContainsKey(input.ClientId.Trim())) errors.Add($"clientId '{input.ClientId}' already exists");
                }
            }
            if (input.Type is not (SsoClientTypes.Confidential or SsoClientTypes.Public))
            {
                errors.Add("type must be 'confidential' or 'public'");
            }
        }

        if (string.IsNullOrWhiteSpace(input.DisplayName) || input.DisplayName.Trim().Length > 100)
        {
            errors.Add("displayName is required (max 100 characters)");
        }

        var redirects = Clean(input.RedirectUris);
        if (redirects.Count == 0) errors.Add("redirectUris: at least one is required");
        errors.AddRange(redirects.Where(u => !IsAllowedUri(u)).Select(u => $"redirectUris: '{u}' must be an absolute https URL (http only for localhost) without a fragment"));
        errors.AddRange(Clean(input.PostLogoutRedirectUris).Where(u => !IsAllowedUri(u)).Select(u => $"postLogoutRedirectUris: '{u}' must be an absolute https URL"));
        if (!string.IsNullOrWhiteSpace(input.FrontChannelLogoutUri) && !IsAllowedUri(input.FrontChannelLogoutUri.Trim()))
        {
            errors.Add("frontChannelLogoutUri must be an absolute https URL");
        }
        return errors;
    }

    public static bool IsAllowedUri(string value)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) || !string.IsNullOrEmpty(uri.Fragment)) return false;
        if (uri.Scheme == Uri.UriSchemeHttps) return true;
        return uri.Scheme == Uri.UriSchemeHttp && uri.IsLoopback;
    }

    public SsoClientSecretResponse Create(SsoClientInput input, string by)
    {
        var client = new SsoClient
        {
            ClientId = input.ClientId!.Trim(),
            Type = input.Type!,
            CreatedBy = by
        };
        Apply(client, input);

        string? secret = null;
        if (client.Type == SsoClientTypes.Confidential)
        {
            secret = NewSecret();
            client.SecretHash = Hash(secret);
            client.SecretRotatedAt = DateTime.UtcNow;
        }
        else
        {
            client.RequirePkce = true;
        }

        Persist(client);
        lock (_lock)
        {
            _clients[client.ClientId] = client;
            SaveFile();
        }
        return new SsoClientSecretResponse { Client = ToView(client), ClientSecret = secret };
    }

    public SsoClientView? Update(string clientId, SsoClientInput input, string by)
    {
        SsoClient copy;
        lock (_lock)
        {
            if (!_clients.TryGetValue(clientId, out var existing)) return null;
            copy = Clone(existing);
        }

        Apply(copy, input);
        if (copy.Type == SsoClientTypes.Public) copy.RequirePkce = true;
        copy.UpdatedAt = DateTime.UtcNow;
        copy.UpdatedBy = by;

        Persist(copy);
        lock (_lock)
        {
            _clients[clientId] = copy;
            SaveFile();
        }
        return ToView(copy);
    }

    public SsoClientSecretResponse? RotateSecret(string clientId, string by)
    {
        SsoClient copy;
        lock (_lock)
        {
            if (!_clients.TryGetValue(clientId, out var existing) || existing.Type != SsoClientTypes.Confidential) return null;
            copy = Clone(existing);
        }

        var secret = NewSecret();
        copy.SecretHash = Hash(secret);
        copy.SecretRotatedAt = DateTime.UtcNow;
        copy.UpdatedAt = DateTime.UtcNow;
        copy.UpdatedBy = by;

        Persist(copy);
        lock (_lock)
        {
            _clients[clientId] = copy;
            SaveFile();
        }
        return new SsoClientSecretResponse { Client = ToView(copy), ClientSecret = secret };
    }

    public bool Delete(string clientId)
    {
        lock (_lock)
        {
            if (!_clients.ContainsKey(clientId)) return false;
        }

        if (_database.Enabled)
        {
            using var db = _database.CreateContext();
            db.SsoClients.Where(c => c.ClientId == clientId).ExecuteDelete();
        }
        lock (_lock)
        {
            _clients.Remove(clientId);
            SaveFile();
        }
        return true;
    }

    private static void Apply(SsoClient c, SsoClientInput input)
    {
        c.DisplayName = input.DisplayName.Trim();
        c.RedirectUris = Clean(input.RedirectUris);
        c.PostLogoutRedirectUris = Clean(input.PostLogoutRedirectUris);
        c.FrontChannelLogoutUri = string.IsNullOrWhiteSpace(input.FrontChannelLogoutUri) ? null : input.FrontChannelLogoutUri.Trim();
        c.AllowedGroups = Clean(input.AllowedGroups);
        c.RequirePkce = input.RequirePkce;
        c.IsActive = input.IsActive;
    }

    #endregion

    #region Persistence

    private void Load()
    {
        if (_database.Enabled && TryLoadFromDatabase(importFile: true)) return;

        try
        {
            if (!File.Exists(FilePath)) return;
            var list = JsonSerializer.Deserialize<List<SsoClient>>(File.ReadAllText(FilePath)) ?? new();
            lock (_lock) _clients = list.ToDictionary(c => c.ClientId, StringComparer.Ordinal);
            _logger.LogInformation("Loaded {Count} SSO applications from {Path}", list.Count, FilePath);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to load SSO applications from {Path}", FilePath);
        }
    }

    private bool TryLoadFromDatabase(bool importFile)
    {
        try
        {
            using var db = _database.CreateContext();
            var rows = db.SsoClients.AsNoTracking().ToList();
            if (importFile && rows.Count == 0 && File.Exists(FilePath))
            {
                var fromFile = JsonSerializer.Deserialize<List<SsoClient>>(File.ReadAllText(FilePath)) ?? new();
                if (fromFile.Count > 0)
                {
                    db.SsoClients.AddRange(fromFile);
                    db.SaveChanges();
                    rows = fromFile;
                    _logger.LogInformation("Imported {Count} SSO applications into the database", rows.Count);
                }
            }

            lock (_lock)
            {
                _clients = rows.ToDictionary(c => c.ClientId, StringComparer.Ordinal);
                SaveFile();
            }
            return true;
        }
        catch (Exception ex)
        {
            _database.ReportError(ex);
            _logger.LogWarning("Could not load SSO applications from the database: {Error}", ex.GetBaseException().Message);
            return false;
        }
    }

    /// <summary>Insert or update management fields (login counters are incremented separately)</summary>
    private void Persist(SsoClient c)
    {
        if (!_database.Enabled) return;

        using var db = _database.CreateContext();
        var row = db.SsoClients.FirstOrDefault(x => x.ClientId == c.ClientId);
        if (row == null)
        {
            db.SsoClients.Add(Clone(c));
        }
        else
        {
            row.DisplayName = c.DisplayName;
            row.SecretHash = c.SecretHash;
            row.RedirectUris = c.RedirectUris.ToList();
            row.PostLogoutRedirectUris = c.PostLogoutRedirectUris.ToList();
            row.FrontChannelLogoutUri = c.FrontChannelLogoutUri;
            row.AllowedGroups = c.AllowedGroups.ToList();
            row.RequirePkce = c.RequirePkce;
            row.IsActive = c.IsActive;
            row.UpdatedAt = c.UpdatedAt;
            row.UpdatedBy = c.UpdatedBy;
            row.SecretRotatedAt = c.SecretRotatedAt;
        }
        db.SaveChanges();
        _database.ReportOk();
    }

    /// <summary>Caller holds _lock. The store in file mode, a startup cache in database mode.</summary>
    private void SaveFile()
    {
        try
        {
            Directory.CreateDirectory(_paths.DataDirectory);
            var temp = FilePath + ".tmp";
            File.WriteAllText(temp, JsonSerializer.Serialize(_clients.Values.OrderBy(c => c.ClientId).ToList(), JsonOptions));
            File.Move(temp, FilePath, overwrite: true);
        }
        catch (Exception ex) when (_database.Enabled)
        {
            _logger.LogWarning("Could not write local SSO application cache: {Error}", ex.Message);
        }
    }

    private void Tick()
    {
        try
        {
            foreach (var (clientId, _) in _pendingLogins)
            {
                if (!_pendingLogins.TryRemove(clientId, out var count) || count == 0) continue;
                var now = DateTime.UtcNow;
                if (_database.Enabled)
                {
                    using var db = _database.CreateContext();
                    db.SsoClients.Where(c => c.ClientId == clientId).ExecuteUpdate(u => u
                        .SetProperty(c => c.LoginCount, c => c.LoginCount + count)
                        .SetProperty(c => c.LastLoginAt, now));
                }
                lock (_lock)
                {
                    if (_clients.TryGetValue(clientId, out var c))
                    {
                        c.LoginCount += count;
                        c.LastLoginAt = now;
                    }
                    if (!_database.Enabled) SaveFile();
                }
            }

            if (_database.Enabled) TryLoadFromDatabase(importFile: false);
        }
        catch (Exception ex)
        {
            _logger.LogWarning("SSO application sync failed: {Error}", ex.GetBaseException().Message);
        }
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        _timer = new Timer(_ => Tick(), null, TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(30));
        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        _timer?.Change(Timeout.Infinite, Timeout.Infinite);
        Tick();
        return Task.CompletedTask;
    }

    public void Dispose() => _timer?.Dispose();

    #endregion

    #region Helpers

    private static SsoClientView ToView(SsoClient c) => new()
    {
        ClientId = c.ClientId,
        DisplayName = c.DisplayName,
        Type = c.Type,
        RedirectUris = c.RedirectUris.ToList(),
        PostLogoutRedirectUris = c.PostLogoutRedirectUris.ToList(),
        FrontChannelLogoutUri = c.FrontChannelLogoutUri,
        AllowedGroups = c.AllowedGroups.ToList(),
        RequirePkce = c.RequirePkce,
        IsActive = c.IsActive,
        CreatedAt = c.CreatedAt,
        CreatedBy = c.CreatedBy,
        UpdatedAt = c.UpdatedAt,
        SecretRotatedAt = c.SecretRotatedAt,
        LastLoginAt = c.LastLoginAt,
        LoginCount = c.LoginCount
    };

    private static SsoClient Clone(SsoClient c) => JsonSerializer.Deserialize<SsoClient>(JsonSerializer.Serialize(c))!;

    private static string NewSecret() =>
        Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static string Hash(string secret) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(secret)));

    private static List<string> Clean(IEnumerable<string>? values) =>
        (values ?? Enumerable.Empty<string>()).Select(v => v.Trim()).Where(v => v.Length > 0).Distinct(StringComparer.Ordinal).ToList();

    #endregion
}

/// <summary>
/// RSA signing key and AES encryption key for OpenID Connect tokens. Created once, protected with
/// ASP.NET Data Protection, stored in App_Data/sso-keys.json or dbo.SsoKeys (shared by all servers).
/// </summary>
public sealed class SsoKeyStore
{
    private readonly Lazy<SsoKeyMaterial> _keys;

    public SsoKeyStore(DataPaths paths, Database database, IDataProtectionProvider dataProtection, ILogger<SsoKeyStore> logger)
    {
        var protector = dataProtection.CreateProtector("AuthenAPI.SsoKeys.v1");
        var file = Path.Combine(paths.DataDirectory, "sso-keys.json");

        _keys = new Lazy<SsoKeyMaterial>(() =>
        {
            if (database.Enabled)
            {
                try
                {
                    using var db = database.CreateContext();
                    var row = db.SsoKeys.AsNoTracking().FirstOrDefault(k => k.Id == 1);
                    if (row == null)
                    {
                        var created = Generate();
                        db.SsoKeys.Add(new SsoKeyRow { Id = 1, ProtectedJson = protector.Protect(JsonSerializer.Serialize(created)), CreatedAt = DateTime.UtcNow });
                        try
                        {
                            db.SaveChanges();
                            logger.LogInformation("Created SSO signing/encryption keys in the database");
                        }
                        catch (DbUpdateException)
                        {
                            // Another server created them first: use those.
                        }
                        row = db.SsoKeys.AsNoTracking().First(k => k.Id == 1);
                    }
                    var keys = JsonSerializer.Deserialize<SsoKeyMaterial>(protector.Unprotect(row.ProtectedJson))!;
                    File.WriteAllText(file, protector.Protect(JsonSerializer.Serialize(keys)));
                    return keys;
                }
                catch (Exception ex) when (File.Exists(file))
                {
                    logger.LogWarning("Could not read SSO keys from the database ({Error}); using the local copy", ex.GetBaseException().Message);
                }
            }

            if (File.Exists(file))
            {
                return JsonSerializer.Deserialize<SsoKeyMaterial>(protector.Unprotect(File.ReadAllText(file)))!;
            }

            var generated = Generate();
            Directory.CreateDirectory(paths.DataDirectory);
            File.WriteAllText(file, protector.Protect(JsonSerializer.Serialize(generated)));
            logger.LogInformation("Created SSO signing/encryption keys in {Path}", file);
            return generated;
        });
    }

    public SsoKeyMaterial Keys => _keys.Value;

    private static SsoKeyMaterial Generate()
    {
        using var rsa = RSA.Create(2048);
        return new SsoKeyMaterial
        {
            SigningKeyId = Convert.ToHexString(RandomNumberGenerator.GetBytes(8)).ToLowerInvariant(),
            SigningRsaPrivateKey = Convert.ToBase64String(rsa.ExportPkcs8PrivateKey()),
            EncryptionKeyId = Convert.ToHexString(RandomNumberGenerator.GetBytes(8)).ToLowerInvariant(),
            EncryptionKey = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))
        };
    }
}
