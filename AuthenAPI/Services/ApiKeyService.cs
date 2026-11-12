using AuthenAPI.Data;
using AuthenAPI.Models;
using AuthenAPI.Utilities;
using Microsoft.Extensions.Options;
using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;

namespace AuthenAPI.Services;

/// <summary>
/// Stores, validates and tracks API keys. Managed keys live in App_Data/api-keys.json as SHA-256 hashes;
/// keys listed in appsettings.json (SecuritySettings:ApiKeys) keep working and are shown read-only.
/// </summary>
public sealed class ApiKeyService : IHostedService, IDisposable
{
    private const string KeyPrefix = "ak_";
    private const int DisplayPrefixLength = 10;
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    private readonly DataPaths _paths;
    private readonly Database _database;
    private Timer? _reloadTimer;
    private readonly IOptionsMonitor<SecuritySettings> _security;
    private readonly ILogger<ApiKeyService> _logger;
    private readonly object _lock = new();
    private readonly ConcurrentDictionary<string, UsageCounter> _usage = new();
    private readonly ConcurrentDictionary<string, RateWindow> _rateWindows = new();
    private readonly ConcurrentDictionary<string, IpNetworkMatcher> _ipMatchers = new();

    private Dictionary<string, ManagedApiKey> _byId = new();
    private Dictionary<string, ManagedApiKey> _byHash = new();
    private Timer? _flushTimer;

    public ApiKeyService(DataPaths paths, Database database, IOptionsMonitor<SecuritySettings> security, ILogger<ApiKeyService> logger)
    {
        _paths = paths;
        _database = database;
        _security = security;
        _logger = logger;
        Load();
    }

    #region Validation

    /// <summary>
    /// Validate a presented key for a request. Updates usage counters on success.
    /// </summary>
    public ApiKeyValidationResult Validate(string? presentedKey, IPAddress? clientIp, string? requiredScope)
    {
        if (string.IsNullOrWhiteSpace(presentedKey))
        {
            return new ApiKeyValidationResult { Failure = ApiKeyFailure.Missing };
        }

        var hash = Hash(presentedKey.Trim());

        ManagedApiKey? managed;
        lock (_lock)
        {
            _byHash.TryGetValue(hash, out managed);
        }

        if (managed != null)
        {
            return ValidateManaged(managed, clientIp, requiredScope);
        }

        // Legacy keys from appsettings.json: compare hashes in constant time.
        var hashBytes = Convert.FromHexString(hash);
        foreach (var legacy in _security.CurrentValue.ApiKeys)
        {
            if (string.IsNullOrEmpty(legacy.Key)) continue;
            if (!CryptographicOperations.FixedTimeEquals(hashBytes, Convert.FromHexString(Hash(legacy.Key)))) continue;

            var id = LegacyId(legacy.Key);
            if (!legacy.IsActive) return Fail(ApiKeyFailure.Disabled, id, legacy.Description);
            if (legacy.ExpiresAt.HasValue && legacy.ExpiresAt.Value < DateTime.UtcNow) return Fail(ApiKeyFailure.Expired, id, legacy.Description);

            TrackUsage(id, clientIp);
            return new ApiKeyValidationResult { Failure = ApiKeyFailure.None, KeyId = id, KeyName = legacy.Description };
        }

        return new ApiKeyValidationResult { Failure = ApiKeyFailure.Invalid };
    }

    private ApiKeyValidationResult ValidateManaged(ManagedApiKey key, IPAddress? clientIp, string? requiredScope)
    {
        if (key.RevokedAt.HasValue) return Fail(ApiKeyFailure.Revoked, key.Id, key.Name);
        if (!key.IsActive) return Fail(ApiKeyFailure.Disabled, key.Id, key.Name);
        if (key.ExpiresAt.HasValue && key.ExpiresAt.Value < DateTime.UtcNow) return Fail(ApiKeyFailure.Expired, key.Id, key.Name);

        if (key.AllowedIps.Count > 0)
        {
            var matcher = _ipMatchers.GetOrAdd(key.Id, _ => IpNetworkMatcher.Parse(key.AllowedIps));
            var isLoopback = clientIp != null && IPAddress.IsLoopback(clientIp);
            if (!isLoopback && !matcher.Contains(clientIp)) return Fail(ApiKeyFailure.IpDenied, key.Id, key.Name);
        }

        if (requiredScope != null && key.Scopes.Count > 0 &&
            !key.Scopes.Contains(requiredScope, StringComparer.OrdinalIgnoreCase))
        {
            return Fail(ApiKeyFailure.ScopeDenied, key.Id, key.Name);
        }

        if (key.RateLimitPerMinute is > 0)
        {
            var window = _rateWindows.GetOrAdd(key.Id, _ => new RateWindow());
            if (!window.TryAcquire(key.RateLimitPerMinute.Value, out var retryAfter))
            {
                return new ApiKeyValidationResult
                {
                    Failure = ApiKeyFailure.RateLimited,
                    KeyId = key.Id,
                    KeyName = key.Name,
                    RetryAfterSeconds = retryAfter
                };
            }
        }

        TrackUsage(key.Id, clientIp);
        return new ApiKeyValidationResult { Failure = ApiKeyFailure.None, KeyId = key.Id, KeyName = key.Name };
    }

    private static ApiKeyValidationResult Fail(ApiKeyFailure failure, string id, string? name) =>
        new() { Failure = failure, KeyId = id, KeyName = name };

    private void TrackUsage(string id, IPAddress? ip)
    {
        var counter = _usage.GetOrAdd(id, _ => new UsageCounter());
        counter.Increment(ip?.ToString());
    }

    #endregion

    #region Management

    public List<ApiKeyView> List()
    {
        List<ManagedApiKey> managed;
        lock (_lock)
        {
            managed = _byId.Values.ToList();
        }

        var views = managed.Select(ToView).ToList();

        foreach (var legacy in _security.CurrentValue.ApiKeys.Where(k => !string.IsNullOrEmpty(k.Key)))
        {
            var id = LegacyId(legacy.Key);
            _usage.TryGetValue(id, out var usage);
            var status = !legacy.IsActive ? "Disabled"
                : legacy.ExpiresAt.HasValue && legacy.ExpiresAt.Value < DateTime.UtcNow ? "Expired"
                : "Active";

            views.Add(new ApiKeyView
            {
                Id = id,
                Name = string.IsNullOrWhiteSpace(legacy.Description) ? "(appsettings key)" : legacy.Description,
                Description = "Defined in appsettings.json (SecuritySettings:ApiKeys). Edit that file to change it.",
                Prefix = legacy.Key.Length > 4 ? legacy.Key[..4] : string.Empty,
                Source = "appsettings",
                IsActive = legacy.IsActive,
                Status = status,
                ExpiresAt = legacy.ExpiresAt,
                LastUsedAt = usage?.LastUsedAt,
                LastUsedIp = usage?.LastIp,
                UsageCount = usage?.Count ?? 0
            });
        }

        return views.OrderBy(v => v.Source).ThenByDescending(v => v.CreatedAt).ToList();
    }

    public ApiKeyView? Get(string id) => List().FirstOrDefault(v => v.Id == id);

    public bool IsLegacy(string id) => id.StartsWith("cfg_", StringComparison.Ordinal);

    public List<string> ValidateInput(ApiKeyInput input)
    {
        var errors = new List<string>();
        if (string.IsNullOrWhiteSpace(input.Name)) errors.Add("name is required");
        else if (input.Name.Trim().Length > 100) errors.Add("name must be at most 100 characters");
        if (input.Description?.Length > 500) errors.Add("description must be at most 500 characters");

        foreach (var scope in input.Scopes ?? new List<string>())
        {
            if (!ApiKeyScopes.All.ContainsKey(scope)) errors.Add($"unknown scope '{scope}'");
        }

        errors.AddRange(SettingsMapper.ValidateIps(input.AllowedIps, "allowedIps"));

        if (input.RateLimitPerMinute is < 1 or > 100_000) errors.Add("rateLimitPerMinute must be 1-100000 or empty");
        if (input.ExpiresAt.HasValue && input.ExpiresAt.Value.ToUniversalTime() <= DateTime.UtcNow)
        {
            errors.Add("expiresAt must be in the future");
        }
        return errors;
    }

    public ApiKeySecretResponse Create(ApiKeyInput input, string createdBy)
    {
        var plain = GenerateKey();
        var key = new ManagedApiKey
        {
            Name = input.Name.Trim(),
            Description = input.Description?.Trim(),
            Prefix = plain[..DisplayPrefixLength],
            KeyHash = Hash(plain),
            Scopes = CleanList(input.Scopes),
            AllowedIps = CleanList(input.AllowedIps),
            RateLimitPerMinute = input.RateLimitPerMinute,
            ExpiresAt = input.ExpiresAt?.ToUniversalTime(),
            CreatedBy = createdBy
        };

        lock (_lock)
        {
            Persist(key);
            _byId[key.Id] = key;
            Reindex();
            SaveCache();
        }

        return new ApiKeySecretResponse { Key = ToView(key), PlainTextKey = plain };
    }

    public ApiKeyView? Update(string id, ApiKeyInput input, string updatedBy)
    {
        lock (_lock)
        {
            if (!_byId.TryGetValue(id, out var key)) return null;

            key.Name = input.Name.Trim();
            key.Description = input.Description?.Trim();
            key.Scopes = CleanList(input.Scopes);
            key.AllowedIps = CleanList(input.AllowedIps);
            key.RateLimitPerMinute = input.RateLimitPerMinute;
            key.ExpiresAt = input.ExpiresAt?.ToUniversalTime();
            if (input.IsActive.HasValue && !key.RevokedAt.HasValue) key.IsActive = input.IsActive.Value;
            key.UpdatedAt = DateTime.UtcNow;
            key.UpdatedBy = updatedBy;

            _ipMatchers.TryRemove(id, out _);
            Persist(key);
            SaveCache();
            return ToView(key);
        }
    }

    public ApiKeySecretResponse? Rotate(string id, string updatedBy)
    {
        lock (_lock)
        {
            if (!_byId.TryGetValue(id, out var key) || key.RevokedAt.HasValue) return null;

            var plain = GenerateKey();
            key.KeyHash = Hash(plain);
            key.Prefix = plain[..DisplayPrefixLength];
            key.UpdatedAt = DateTime.UtcNow;
            key.UpdatedBy = updatedBy;

            Persist(key);
            Reindex();
            SaveCache();
            return new ApiKeySecretResponse { Key = ToView(key), PlainTextKey = plain };
        }
    }

    public ApiKeyView? Revoke(string id, string revokedBy)
    {
        lock (_lock)
        {
            if (!_byId.TryGetValue(id, out var key)) return null;

            key.IsActive = false;
            key.RevokedAt ??= DateTime.UtcNow;
            key.RevokedBy ??= revokedBy;
            Persist(key);
            SaveCache();
            return ToView(key);
        }
    }

    public bool Delete(string id)
    {
        lock (_lock)
        {
            if (!_byId.ContainsKey(id)) return false;
            PersistDelete(id);
            _byId.Remove(id);
            Reindex();
            SaveCache();
        }

        _usage.TryRemove(id, out _);
        _rateWindows.TryRemove(id, out _);
        _ipMatchers.TryRemove(id, out _);
        return true;
    }

    #endregion

    #region Persistence

    private void Load()
    {
        if (_database.Enabled && TryLoadFromDatabase(importFromCache: true)) return;
        LoadFromFile();
    }

    private void LoadFromFile()
    {
        try
        {
            if (!File.Exists(_paths.ApiKeysFile)) return;

            var keys = JsonSerializer.Deserialize<List<ManagedApiKey>>(File.ReadAllText(_paths.ApiKeysFile)) ?? new();
            lock (_lock)
            {
                _byId = keys.ToDictionary(k => k.Id);
                Reindex();
            }
            _logger.LogInformation("Loaded {Count} managed API keys from {Path}{Note}", keys.Count, _paths.ApiKeysFile,
                _database.Enabled ? " (local cache: database unavailable)" : string.Empty);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to load managed API keys from {Path}", _paths.ApiKeysFile);
        }
    }

    /// <summary>Load all keys from the database. On the first run, keys from api-keys.json are imported.</summary>
    private bool TryLoadFromDatabase(bool importFromCache)
    {
        try
        {
            using var db = _database.CreateContext();
            var keys = db.ApiKeys.AsNoTracking().ToList();

            if (importFromCache && keys.Count == 0 && File.Exists(_paths.ApiKeysFile))
            {
                var fileKeys = JsonSerializer.Deserialize<List<ManagedApiKey>>(File.ReadAllText(_paths.ApiKeysFile)) ?? new();
                if (fileKeys.Count > 0)
                {
                    db.ApiKeys.AddRange(fileKeys);
                    db.SaveChanges();
                    keys = fileKeys;
                    _logger.LogInformation("Imported {Count} API keys from {Path} into the database", fileKeys.Count, _paths.ApiKeysFile);
                }
            }

            lock (_lock)
            {
                _byId = keys.ToDictionary(k => k.Id);
                Reindex();
                _ipMatchers.Clear();
                SaveCache();
            }
            _database.ReportOk();
            return true;
        }
        catch (Exception ex)
        {
            _database.ReportError(ex);
            _logger.LogWarning("Could not load API keys from the database: {Error}", ex.GetBaseException().Message);
            return false;
        }
    }

    /// <summary>
    /// Write one key to the database (insert or update management fields; usage counters are
    /// updated separately so servers do not overwrite each other's counts). Throws when the database is down.
    /// </summary>
    private void Persist(ManagedApiKey key)
    {
        if (!_database.Enabled) return;

        using var db = _database.CreateContext();
        var row = db.ApiKeys.FirstOrDefault(k => k.Id == key.Id);
        if (row == null)
        {
            db.ApiKeys.Add(Copy(key));
        }
        else
        {
            row.Name = key.Name;
            row.Description = key.Description;
            row.Prefix = key.Prefix;
            row.KeyHash = key.KeyHash;
            row.Scopes = key.Scopes.ToList();
            row.AllowedIps = key.AllowedIps.ToList();
            row.RateLimitPerMinute = key.RateLimitPerMinute;
            row.IsActive = key.IsActive;
            row.ExpiresAt = key.ExpiresAt;
            row.UpdatedAt = key.UpdatedAt;
            row.UpdatedBy = key.UpdatedBy;
            row.RevokedAt = key.RevokedAt;
            row.RevokedBy = key.RevokedBy;
        }
        db.SaveChanges();
        _database.ReportOk();
    }

    private void PersistDelete(string id)
    {
        if (!_database.Enabled) return;

        using var db = _database.CreateContext();
        db.ApiKeys.Where(k => k.Id == id).ExecuteDelete();
        _database.ReportOk();
    }

    private static ManagedApiKey Copy(ManagedApiKey k) =>
        JsonSerializer.Deserialize<ManagedApiKey>(JsonSerializer.Serialize(k))!;

    /// <summary>
    /// Caller must hold _lock. Writes api-keys.json: the store itself in file mode, a local cache
    /// (used when the database is unreachable at startup) in database mode.
    /// </summary>
    private void SaveCache()
    {
        try
        {
            if (!_database.Enabled) ApplyPendingUsage();
            Directory.CreateDirectory(_paths.DataDirectory);
            var temp = _paths.ApiKeysFile + ".tmp";
            File.WriteAllText(temp, JsonSerializer.Serialize(_byId.Values.OrderBy(k => k.CreatedAt).ToList(), JsonOptions));
            File.Move(temp, _paths.ApiKeysFile, overwrite: true);
        }
        catch (Exception ex) when (_database.Enabled)
        {
            _logger.LogWarning("Could not write local API key cache: {Error}", ex.Message);
        }
    }

    /// <summary>Caller must hold _lock</summary>
    private void Reindex() => _byHash = _byId.Values.ToDictionary(k => k.KeyHash);

    /// <summary>Caller must hold _lock. Moves in-memory usage counters into the stored keys.</summary>
    private bool ApplyPendingUsage()
    {
        var changed = false;
        foreach (var (id, counter) in _usage)
        {
            if (!_byId.TryGetValue(id, out var key)) continue;
            var (delta, lastUsed, lastIp) = counter.TakePending();
            if (delta == 0) continue;

            key.UsageCount += delta;
            key.LastUsedAt = lastUsed;
            key.LastUsedIp = lastIp;
            changed = true;
        }
        return changed;
    }

    private void FlushUsage()
    {
        try
        {
            if (_database.Enabled)
            {
                FlushUsageToDatabase();
                return;
            }

            lock (_lock)
            {
                if (ApplyPendingUsage()) SaveCache();
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to persist API key usage counters");
        }
    }

    /// <summary>Increment counters in place (UPDATE ... SET UsageCount = UsageCount + n) so several servers add up</summary>
    private void FlushUsageToDatabase()
    {
        foreach (var (id, counter) in _usage)
        {
            var (delta, lastUsed, lastIp) = counter.TakePending();
            if (delta == 0) continue;

            try
            {
                using var db = _database.CreateContext();
                db.ApiKeys.Where(k => k.Id == id).ExecuteUpdate(u => u
                    .SetProperty(k => k.UsageCount, k => k.UsageCount + delta)
                    .SetProperty(k => k.LastUsedAt, lastUsed)
                    .SetProperty(k => k.LastUsedIp, lastIp));

                lock (_lock)
                {
                    if (_byId.TryGetValue(id, out var key))
                    {
                        key.UsageCount += delta;
                        key.LastUsedAt = lastUsed;
                        key.LastUsedIp = lastIp;
                    }
                }
            }
            catch (Exception ex)
            {
                counter.Restore(delta);
                _database.ReportError(ex);
                _logger.LogWarning("Failed to write API key usage to the database: {Error}", ex.GetBaseException().Message);
                return;
            }
        }
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        _flushTimer = new Timer(_ => FlushUsage(), null, TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(1));
        if (_database.Enabled)
        {
            // Pick up keys created or changed on other servers (and recover after a database outage).
            _reloadTimer = new Timer(_ => TryLoadFromDatabase(importFromCache: false), null, TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(30));
        }
        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        _flushTimer?.Change(Timeout.Infinite, Timeout.Infinite);
        _reloadTimer?.Change(Timeout.Infinite, Timeout.Infinite);
        FlushUsage();
        return Task.CompletedTask;
    }

    public void Dispose()
    {
        _flushTimer?.Dispose();
        _reloadTimer?.Dispose();
    }

    #endregion

    #region Helpers

    private ApiKeyView ToView(ManagedApiKey key)
    {
        _usage.TryGetValue(key.Id, out var usage);
        var pending = usage?.PeekPending() ?? 0;

        var status = key.RevokedAt.HasValue ? "Revoked"
            : !key.IsActive ? "Disabled"
            : key.ExpiresAt.HasValue && key.ExpiresAt.Value < DateTime.UtcNow ? "Expired"
            : "Active";

        return new ApiKeyView
        {
            Id = key.Id,
            Name = key.Name,
            Description = key.Description,
            Prefix = key.Prefix,
            Source = "managed",
            Scopes = key.Scopes.ToList(),
            AllowedIps = key.AllowedIps.ToList(),
            RateLimitPerMinute = key.RateLimitPerMinute,
            IsActive = key.IsActive,
            Status = status,
            ExpiresAt = key.ExpiresAt,
            CreatedAt = key.CreatedAt,
            CreatedBy = key.CreatedBy,
            LastUsedAt = pending > 0 ? usage!.LastUsedAt : key.LastUsedAt,
            LastUsedIp = pending > 0 ? usage!.LastIp : key.LastUsedIp,
            UsageCount = key.UsageCount + pending,
            RevokedAt = key.RevokedAt,
            RevokedBy = key.RevokedBy
        };
    }

    private static string GenerateKey() =>
        KeyPrefix + Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static string Hash(string key) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(key)));

    private static string LegacyId(string key) => "cfg_" + Hash(key)[..12].ToLowerInvariant();

    private static List<string> CleanList(IEnumerable<string>? values) =>
        (values ?? Enumerable.Empty<string>())
            .Select(v => v.Trim())
            .Where(v => v.Length > 0)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

    private sealed class UsageCounter
    {
        private long _pending;
        public long Count;
        public DateTime? LastUsedAt;
        public string? LastIp;

        public void Increment(string? ip)
        {
            Interlocked.Increment(ref _pending);
            Interlocked.Increment(ref Count);
            LastUsedAt = DateTime.UtcNow;
            LastIp = ip;
        }

        public long PeekPending() => Interlocked.Read(ref _pending);

        public void Restore(long delta) => Interlocked.Add(ref _pending, delta);

        public (long Delta, DateTime? LastUsed, string? LastIp) TakePending() =>
            (Interlocked.Exchange(ref _pending, 0), LastUsedAt, LastIp);
    }

    /// <summary>Fixed one-minute window counter</summary>
    private sealed class RateWindow
    {
        private long _windowStart;
        private int _count;

        public bool TryAcquire(int limit, out int retryAfterSeconds)
        {
            lock (this)
            {
                var minute = DateTime.UtcNow.Ticks / TimeSpan.TicksPerMinute;
                if (minute != _windowStart)
                {
                    _windowStart = minute;
                    _count = 0;
                }

                retryAfterSeconds = 60 - DateTime.UtcNow.Second;
                if (_count >= limit) return false;

                _count++;
                return true;
            }
        }
    }

    #endregion
}
