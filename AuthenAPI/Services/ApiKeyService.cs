using AuthenAPI.Models;
using AuthenAPI.Utilities;
using Microsoft.Extensions.Options;
using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

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
    private readonly IOptionsMonitor<SecuritySettings> _security;
    private readonly ILogger<ApiKeyService> _logger;
    private readonly object _lock = new();
    private readonly ConcurrentDictionary<string, UsageCounter> _usage = new();
    private readonly ConcurrentDictionary<string, RateWindow> _rateWindows = new();
    private readonly ConcurrentDictionary<string, IpNetworkMatcher> _ipMatchers = new();

    private Dictionary<string, ManagedApiKey> _byId = new();
    private Dictionary<string, ManagedApiKey> _byHash = new();
    private Timer? _flushTimer;

    public ApiKeyService(DataPaths paths, IOptionsMonitor<SecuritySettings> security, ILogger<ApiKeyService> logger)
    {
        _paths = paths;
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
            _byId[key.Id] = key;
            Reindex();
            Save();
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
            Save();
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

            Reindex();
            Save();
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
            Save();
            return ToView(key);
        }
    }

    public bool Delete(string id)
    {
        lock (_lock)
        {
            if (!_byId.Remove(id)) return false;
            Reindex();
            Save();
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
        try
        {
            if (!File.Exists(_paths.ApiKeysFile)) return;

            var keys = JsonSerializer.Deserialize<List<ManagedApiKey>>(File.ReadAllText(_paths.ApiKeysFile)) ?? new();
            lock (_lock)
            {
                _byId = keys.ToDictionary(k => k.Id);
                Reindex();
            }
            _logger.LogInformation("Loaded {Count} managed API keys from {Path}", keys.Count, _paths.ApiKeysFile);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to load managed API keys from {Path}", _paths.ApiKeysFile);
        }
    }

    /// <summary>Caller must hold _lock</summary>
    private void Save()
    {
        ApplyPendingUsage();
        Directory.CreateDirectory(_paths.DataDirectory);
        var temp = _paths.ApiKeysFile + ".tmp";
        File.WriteAllText(temp, JsonSerializer.Serialize(_byId.Values.OrderBy(k => k.CreatedAt).ToList(), JsonOptions));
        File.Move(temp, _paths.ApiKeysFile, overwrite: true);
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
            lock (_lock)
            {
                if (ApplyPendingUsage()) Save();
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to persist API key usage counters");
        }
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        _flushTimer = new Timer(_ => FlushUsage(), null, TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(1));
        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        _flushTimer?.Change(Timeout.Infinite, Timeout.Infinite);
        FlushUsage();
        return Task.CompletedTask;
    }

    public void Dispose() => _flushTimer?.Dispose();

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
