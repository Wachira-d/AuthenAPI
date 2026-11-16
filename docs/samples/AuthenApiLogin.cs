// AuthenAPI client reference implementation (.NET 6+; does not build on .NET Framework 4.x).
// Copy into your project and implement ICredentialCache against your database (see the guide, section 6).
// NuGet: System.DirectoryServices.Protocols (only for the optional direct-AD fallback).
//
// Registration (ASP.NET Core):
//   services.AddSingleton(options);                              // AuthenApiOptions
//   services.AddHttpClient("AuthenAPI", c => c.BaseAddress = new Uri(options.BaseUrl))
//           .ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler { AllowAutoRedirect = false });
//   services.AddScoped<AuthenLoginService>();                    // the circuit breaker inside is shared (static)
//   // Do NOT add Polly / AddStandardResilienceHandler retries to this client: every retry is another AD bind.
//
// Login order (see docs/CLIENT_INTEGRATION_GUIDE.md):
//   1. AuthenAPI                       - always first
//   2. Direct LDAPS bind to AD         - only when AuthenAPI certainly did NOT check the password
//   3. Offline credential cache        - only when there is evidence the directory is unreachable
//   4. "Authentication service unavailable"

using System.Collections.Concurrent;
using System.DirectoryServices.Protocols;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace AuthenApiClient;

// =============================================================================================
// Configuration
// =============================================================================================

public sealed class AuthenApiOptions
{
    /// <summary>https://authen.hondacx.me (https only, no path).</summary>
    public string BaseUrl { get; set; } = "";

    /// <summary>Your system's own API key. Server-side config/secret store only.</summary>
    public string ApiKey { get; set; } = "";

    /// <summary>
    /// Must be longer than AuthenAPI's own worst case (LdapSettings.ConnectionTimeout x strategies + search).
    /// A timeout is treated as "unknown" (the server may still be checking the password), so it never falls back.
    /// </summary>
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(45);

    public int BreakAfterFailures { get; set; } = 3;
    public TimeSpan BreakDuration { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>Offline login only within this time since the last online verification. 0 = disabled (safest).</summary>
    public TimeSpan OfflineWindow { get; set; } = TimeSpan.FromHours(24);

    /// <summary>Failed offline attempts per user before offline login is refused until the next online login.</summary>
    public int OfflineMaxFailuresPerUser { get; set; } = 5;

    /// <summary>Failed offline attempts per minute across ALL users (stops password spraying while AD is down).</summary>
    public int OfflineMaxFailuresPerMinute { get; set; } = 20;

    /// <summary>
    /// Secret mixed into offline hashes (HMAC) and kept OUTSIDE the database (config / secret store),
    /// so a stolen database alone cannot be cracked. Changing it invalidates all offline entries.
    /// </summary>
    public string OfflinePepper { get; set; } = "";

    /// <summary>Optional: verify against AD directly when AuthenAPI is unreachable.</summary>
    public DirectAdOptions? DirectAd { get; set; }
}

public sealed class DirectAdOptions
{
    /// <summary>Domain controller FQDN (LDAPS certificates are issued for the name, not the IP).</summary>
    public string Server { get; set; } = "";
    public int Port { get; set; } = 636;
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(5);
}

// =============================================================================================
// AuthenAPI contract
// =============================================================================================

public sealed class AdUser
{
    public string? SamAccountName { get; set; }
    public string? UserPrincipalName { get; set; }
    public string? DisplayName { get; set; }
    public string? FirstName { get; set; }
    public string? LastName { get; set; }
    public string? Email { get; set; }
    public string? Department { get; set; }
    public string? Title { get; set; }
    public string? EmployeeId { get; set; }
    public string? Company { get; set; }
    public bool IsEnabled { get; set; }
    public bool IsLocked { get; set; }
    public List<string> Groups { get; set; } = new();
}

public enum LoginSource { AuthenApi, DirectAd, OfflineCache }

public enum LoginOutcome
{
    Success,
    InvalidCredentials,     // "ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง"
    TooManyAttempts,        // "ลองใหม่ภายหลัง"
    ServiceUnavailable,     // "ระบบยืนยันตัวตนขัดข้องชั่วคราว" - never "wrong password"
    ConfigurationError      // key / IP / URL problem: alert your team, show "ติดต่อผู้ดูแลระบบ"
}

public sealed class LoginResult
{
    public LoginOutcome Outcome { get; init; }
    public LoginSource? Source { get; init; }
    public AdUser? User { get; init; }

    /// <summary>Stable identity for your own tables (lower-cased UPN, else sAMAccountName). Never the typed text.</summary>
    public string? UserKey { get; init; }

    public int? RetryAfterSeconds { get; init; }

    /// <summary>For your logs only. Never show it to the user.</summary>
    public string? Detail { get; init; }

    /// <summary>
    /// DirectAd / OfflineCache logins: group data may be stale or missing. Give minimal rights,
    /// block sensitive actions, and re-verify through AuthenAPI when it is back.
    /// </summary>
    public bool IsDegraded => Source is LoginSource.DirectAd or LoginSource.OfflineCache;
}

// =============================================================================================
// Storage you implement (guide section 6 has the table and SQL)
// =============================================================================================

public sealed class CachedCredential
{
    public string UserKey { get; set; } = "";              // lower-cased UPN (primary key)
    public string PasswordHash { get; set; } = "";         // OfflinePasswordHasher output
    public string ProfileJson { get; set; } = "";          // last AdUser from AuthenAPI
    public DateTime LastOnlineVerifiedUtc { get; set; }    // UTC! (SYSUTCDATETIME, not GETDATE)
    public int OfflineFailures { get; set; }
}

public interface ICredentialCache
{
    /// <summary>Find by any login name previously seen for the user (alias table, lower-cased).</summary>
    Task<CachedCredential?> FindByLoginNameAsync(string loginName, CancellationToken ct);

    /// <summary>Insert/replace the row for entry.UserKey and record loginName as an alias of it.</summary>
    Task SaveAsync(CachedCredential entry, string loginName, CancellationToken ct);

    /// <summary>Delete the user's row and all aliases.</summary>
    Task DeleteByUserKeyAsync(string userKey, CancellationToken ct);

    /// <summary>
    /// Atomically: UPDATE ... SET OfflineFailures = OfflineFailures + 1 WHERE UserKey = @k AND OfflineFailures &lt; @max.
    /// Returns false when no attempt is left. Called BEFORE checking the hash.
    /// </summary>
    Task<bool> TryReserveOfflineAttemptAsync(string userKey, int max, CancellationToken ct);

    /// <summary>Give the reserved attempt back after a correct password (sets OfflineFailures to 0).</summary>
    Task ResetOfflineFailuresAsync(string userKey, CancellationToken ct);
}

// =============================================================================================
// Login service
// =============================================================================================

public sealed class AuthenLoginService
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    // Shared across requests/scopes: a per-instance breaker would never open.
    private static readonly ConcurrentDictionary<string, CircuitBreaker> Breakers = new();
    private static readonly RateWindow OfflineFailureWindow = new();

    private readonly HttpClient _http;
    private readonly AuthenApiOptions _options;
    private readonly ICredentialCache _cache;
    private readonly DirectAdVerifier? _directAd;
    private readonly CircuitBreaker _breaker;
    private readonly OfflinePasswordHasher _hasher;

    public AuthenLoginService(HttpClient http, AuthenApiOptions options, ICredentialCache cache)
    {
        if (!Uri.TryCreate(options.BaseUrl, UriKind.Absolute, out var baseUri) || baseUri.Scheme != Uri.UriSchemeHttps)
        {
            throw new ArgumentException("AuthenApiOptions.BaseUrl must be an absolute https:// URL");
        }

        _http = http;
        _options = options;
        _cache = cache;
        _directAd = options.DirectAd is { Server.Length: > 0 } ad ? new DirectAdVerifier(ad) : null;
        _breaker = Breakers.GetOrAdd(baseUri.GetLeftPart(UriPartial.Authority),
            _ => new CircuitBreaker(options.BreakAfterFailures, options.BreakDuration));
        _hasher = new OfflinePasswordHasher(options.OfflinePepper);
    }

    public async Task<LoginResult> LoginAsync(string typedUsername, string password, CancellationToken ct = default)
    {
        // Send exactly what the user typed (trim spaces only). Do NOT strip "@ipsos.com", do NOT
        // lower-case, do NOT hash: AuthenAPI resolves every name format and AD needs the real password.
        var username = typedUsername.Trim();
        if (username.Length == 0 || password.Length == 0)
        {
            return new LoginResult { Outcome = LoginOutcome.InvalidCredentials };
        }
        var loginName = username.ToLowerInvariant();

        // ---- 1. AuthenAPI ------------------------------------------------------------------
        ApiCall api;
        if (_breaker.TryEnter())
        {
            api = await CallAuthenApiAsync(username, password, ct);
            _breaker.Report(api.Kind is ApiKind.NotReached or ApiKind.DirectoryDown);
        }
        else
        {
            api = new ApiCall(ApiKind.NotReached, Detail: "circuit open");
        }

        switch (api.Kind)
        {
            case ApiKind.Success:
                var key = UserKeyOf(api.User!);
                if (key == null)
                {
                    return new LoginResult { Outcome = LoginOutcome.ServiceUnavailable, Detail = "AuthenAPI returned no UPN/sAMAccountName" };
                }
                await RememberAsync(key, loginName, password, api.User!, ct);
                return Ok(LoginSource.AuthenApi, api.User!, key);

            case ApiKind.Rejected:
                // AD said no. Final: never try elsewhere, and drop the offline copy for every name of this user.
                await ForgetAsync(loginName, ct);
                return new LoginResult { Outcome = LoginOutcome.InvalidCredentials, Detail = api.Detail };

            case ApiKind.RateLimited:
                return new LoginResult { Outcome = LoginOutcome.TooManyAttempts, RetryAfterSeconds = api.RetryAfter };

            case ApiKind.ConfigError:
                return new LoginResult { Outcome = LoginOutcome.ConfigurationError, Detail = api.Detail };

            case ApiKind.Unknown:
                // Timeout / 500 / 504: AuthenAPI may still be binding to AD with this password.
                // Any further attempt could count a second bad password, so stop here.
                return new LoginResult { Outcome = LoginOutcome.ServiceUnavailable, Detail = api.Detail };
        }

        // Here: NotReached (request never processed) or DirectoryDown (AuthenAPI cannot reach AD).
        var cached = await _cache.FindByLoginNameAsync(loginName, ct);

        // ---- 2. Direct AD ------------------------------------------------------------------
        if (_directAd != null)
        {
            // Bind with the user's real UPN when we know it; a guessed UPN that does not exist
            // returns the same "52e" as a wrong password.
            var knownUpn = cached != null && cached.UserKey.Contains('@');
            var bindName = knownUpn ? cached!.UserKey : username;
            var ad = await _directAd.VerifyAsync(bindName, password, ct);

            if (ad.Kind == AdKind.Success)
            {
                var profile = FreshProfile(cached) ?? new AdUser { UserPrincipalName = bindName.Contains('@') ? bindName : null };
                var adKey = cached?.UserKey ?? (bindName.Contains('@') ? bindName.ToLowerInvariant() : null);
                if (adKey == null)
                {
                    return new LoginResult { Outcome = LoginOutcome.ServiceUnavailable, Detail = "direct AD ok but identity unknown" };
                }
                return Ok(LoginSource.DirectAd, profile, adKey);
            }

            if (ad.Kind == AdKind.Rejected)
            {
                if (!knownUpn && ad.Detail == "52e")
                {
                    // The name was a guess (typed text): 52e may just mean "no such UPN". Don't claim a wrong password.
                    return new LoginResult { Outcome = LoginOutcome.ServiceUnavailable, Detail = "direct AD: unverified name" };
                }
                if (knownUpn) await _cache.DeleteByUserKeyAsync(cached!.UserKey, ct);
                return new LoginResult { Outcome = LoginOutcome.InvalidCredentials, Detail = "direct AD: " + ad.Detail };
            }
        }

        // ---- 3. Offline cache ----------------------------------------------------------------
        // Reached only with evidence that nothing can check the password right now: AuthenAPI was not
        // reached (refused / DNS / TLS / IIS 502-503 / open circuit, which counts only these) or reported
        // AD down, and direct AD (if configured) was unreachable too. Timeouts never get here.
        return await OfflineLoginAsync(cached, password, api.Detail, ct);
    }

    private async Task<LoginResult> OfflineLoginAsync(CachedCredential? entry, string password, string? why, CancellationToken ct)
    {
        var unavailable = new LoginResult { Outcome = LoginOutcome.ServiceUnavailable, Detail = why };
        if (_options.OfflineWindow <= TimeSpan.Zero || entry == null) return unavailable;
        if (DateTime.UtcNow - entry.LastOnlineVerifiedUtc > _options.OfflineWindow) return unavailable;
        if (!OfflineFailureWindow.Allows(_options.OfflineMaxFailuresPerMinute)) return unavailable;

        // Reserve the attempt first so parallel requests cannot all pass a "failures < max" check.
        if (!await _cache.TryReserveOfflineAttemptAsync(entry.UserKey, _options.OfflineMaxFailuresPerUser, ct))
        {
            return unavailable;
        }

        if (!_hasher.Verify(password, entry.PasswordHash))
        {
            OfflineFailureWindow.Add();
            return new LoginResult { Outcome = LoginOutcome.InvalidCredentials, Detail = "offline mismatch" };
        }

        await _cache.ResetOfflineFailuresAsync(entry.UserKey, ct);
        return Ok(LoginSource.OfflineCache, FreshProfile(entry) ?? new AdUser { UserPrincipalName = entry.UserKey }, entry.UserKey);
    }

    private async Task RememberAsync(string userKey, string loginName, string password, AdUser user, CancellationToken ct)
    {
        if (_options.OfflineWindow <= TimeSpan.Zero) return;
        await _cache.SaveAsync(new CachedCredential
        {
            UserKey = userKey,
            PasswordHash = _hasher.Hash(password),
            ProfileJson = JsonSerializer.Serialize(user, Json),
            LastOnlineVerifiedUtc = DateTime.UtcNow,
            OfflineFailures = 0
        }, loginName, ct);
    }

    private async Task ForgetAsync(string loginName, CancellationToken ct)
    {
        var entry = await _cache.FindByLoginNameAsync(loginName, ct);
        if (entry != null) await _cache.DeleteByUserKeyAsync(entry.UserKey, ct);
    }

    /// <summary>Cached profile only while it is younger than the offline window; otherwise its groups may be stale.</summary>
    private AdUser? FreshProfile(CachedCredential? c)
    {
        if (c == null || DateTime.UtcNow - c.LastOnlineVerifiedUtc > _options.OfflineWindow) return null;
        try { return JsonSerializer.Deserialize<AdUser>(c.ProfileJson, Json); }
        catch (JsonException) { return null; }
    }

    private static LoginResult Ok(LoginSource source, AdUser user, string key) =>
        new() { Outcome = LoginOutcome.Success, Source = source, User = user, UserKey = key };

    /// <summary>AuthenAPI sends "" (not null) for missing fields, so check for blank, not null.</summary>
    public static string? UserKeyOf(AdUser u)
    {
        var key = !string.IsNullOrWhiteSpace(u.UserPrincipalName) ? u.UserPrincipalName
                : !string.IsNullOrWhiteSpace(u.SamAccountName) ? u.SamAccountName
                : null;
        return key?.Trim().ToLowerInvariant();
    }

    // ---- AuthenAPI call ------------------------------------------------------------------------

    private enum ApiKind
    {
        Success,
        Rejected,       // JSON 401 / 400: AD (or validation) said no
        RateLimited,    // 429
        ConfigError,    // key/IP/scope/URL problem
        DirectoryDown,  // JSON 503: AuthenAPI is up but cannot reach AD (the password was not checked)
        NotReached,     // connection refused/reset before sending, DNS, TLS, IIS 502/503 HTML: request not processed
        Unknown         // timeout, 500, 504, unreadable body: the password may or may not have been checked
    }

    private sealed record ApiCall(ApiKind Kind, AdUser? User = null, int? RetryAfter = null, string? Detail = null);

    private async Task<ApiCall> CallAuthenApiAsync(string username, string password, CancellationToken ct)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(_options.Timeout);

        using var request = new HttpRequestMessage(HttpMethod.Post, "api/ldap/authenticate")
        {
            Content = new StringContent(JsonSerializer.Serialize(new { username, password }, Json), Encoding.UTF8, "application/json")
        };
        request.Headers.Add("X-API-Key", _options.ApiKey);

        HttpResponseMessage response;
        try
        {
            response = await _http.SendAsync(request, timeout.Token);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return new ApiCall(ApiKind.Unknown, Detail: "timeout");
        }
        catch (HttpRequestException ex) when (ex.InnerException is System.Net.Sockets.SocketException or System.Security.Authentication.AuthenticationException)
        {
            return new ApiCall(ApiKind.NotReached, Detail: ex.Message); // refused, DNS, TLS handshake
        }
        catch (HttpRequestException ex)
        {
            return new ApiCall(ApiKind.Unknown, Detail: ex.Message);    // e.g. connection reset mid-request
        }

        using (response)
        {
            string body;
            try
            {
                body = await response.Content.ReadAsStringAsync(timeout.Token);
            }
            catch (Exception ex)
            {
                return new ApiCall(ApiKind.Unknown, Detail: "could not read response: " + ex.Message);
            }

            var json = TryParse(body);
            var status = (int)response.StatusCode;

            switch (status)
            {
                case 200:
                    if (json?.RootElement.TryGetProperty("success", out var ok) == true && ok.ValueKind == JsonValueKind.True &&
                        json.RootElement.TryGetProperty("data", out var data) && data.ValueKind == JsonValueKind.Object)
                    {
                        try { return new ApiCall(ApiKind.Success, data.Deserialize<AdUser>(Json)); }
                        catch (JsonException) { /* fall through */ }
                    }
                    return new ApiCall(ApiKind.Unknown, Detail: "200 without a valid AuthenAPI body (proxy page?)");

                case 401 when json != null && json.RootElement.TryGetProperty("reason", out var reason):
                    return new ApiCall(ApiKind.ConfigError, Detail: "API key problem: " + reason);

                case 401 when IsApiResponse(json):
                case 400 when json != null:
                    return new ApiCall(ApiKind.Rejected);

                case 401: // HTML 401 = IIS authentication in front of the app, not AD
                case 403:
                case 404:
                case 405:
                case >= 300 and < 400:
                    return new ApiCall(ApiKind.ConfigError, Detail: $"HTTP {status}: check BaseUrl, API key, IP whitelist and IIS settings");

                case 429:
                    return new ApiCall(ApiKind.RateLimited, RetryAfter: (int?)response.Headers.RetryAfter?.Delta?.TotalSeconds ?? 60);

                case 503 when IsApiResponse(json):
                    return new ApiCall(ApiKind.DirectoryDown, Detail: "AuthenAPI cannot reach Active Directory");

                case 502:
                case 503:
                    return new ApiCall(ApiKind.NotReached, Detail: $"HTTP {status} from IIS/proxy (app not running)");

                default: // 500, 504...
                    return new ApiCall(ApiKind.Unknown, Detail: $"HTTP {status}");
            }
        }
    }

    private static JsonDocument? TryParse(string body)
    {
        try { return JsonDocument.Parse(body); }
        catch (JsonException) { return null; }
    }

    private static bool IsApiResponse(JsonDocument? json) =>
        json != null && json.RootElement.ValueKind == JsonValueKind.Object && json.RootElement.TryGetProperty("success", out _);
}

// =============================================================================================
// Direct AD fallback: ONE simple bind over LDAPS
// =============================================================================================

public enum AdKind { Success, Rejected, Unreachable }

public sealed record AdVerifyResult(AdKind Kind, string? Detail = null);

public sealed class DirectAdVerifier
{
    private readonly DirectAdOptions _options;

    public DirectAdVerifier(DirectAdOptions options) => _options = options;

    public Task<AdVerifyResult> VerifyAsync(string bindName, string password, CancellationToken ct) =>
        Task.Run(() => Verify(bindName, password), ct);

    private AdVerifyResult Verify(string bindName, string password)
    {
        // Exactly one bind: every extra attempt with another name format is another bad-password count.
        try
        {
            using var connection = new LdapConnection(new LdapDirectoryIdentifier(_options.Server, _options.Port))
            {
                AuthType = AuthType.Basic,
                Timeout = _options.Timeout,
                Credential = new NetworkCredential(bindName, password)
            };
            connection.SessionOptions.ProtocolVersion = 3;
            connection.SessionOptions.SecureSocketLayer = true; // LDAPS only
            connection.Bind();
            return new AdVerifyResult(AdKind.Success);
        }
        catch (LdapException ex) when (ex.ErrorCode == 49)
        {
            // data 52e wrong password (or unknown name), 775 locked, 533 disabled, 701 expired, 532/773 password
            var code = Regex.Match(ex.ServerErrorMessage ?? "", @"data\s+([0-9a-fA-F]{3})").Groups[1].Value;
            return new AdVerifyResult(AdKind.Rejected, string.IsNullOrEmpty(code) ? "49" : code);
        }
        catch (Exception ex)
        {
            return new AdVerifyResult(AdKind.Unreachable, ex.Message);
        }
    }
}

// =============================================================================================
// Helpers
// =============================================================================================

/// <summary>HMAC-SHA256 with a pepper kept outside the DB, then PBKDF2-SHA256 600k with a per-user salt.</summary>
public sealed class OfflinePasswordHasher
{
    private const int Iterations = 600_000;
    private const int MaxIterations = 5_000_000;
    private readonly byte[] _pepper;

    public OfflinePasswordHasher(string pepper) => _pepper = Encoding.UTF8.GetBytes(pepper ?? "");

    public string Hash(string password)
    {
        var salt = RandomNumberGenerator.GetBytes(16);
        var hash = Rfc2898DeriveBytes.Pbkdf2(Peppered(password), salt, Iterations, HashAlgorithmName.SHA256, 32);
        return $"pbkdf2-sha256${Iterations}${Convert.ToBase64String(salt)}${Convert.ToBase64String(hash)}";
    }

    public bool Verify(string password, string stored)
    {
        try
        {
            var p = stored.Split('$');
            if (p.Length != 4 || p[0] != "pbkdf2-sha256" || !int.TryParse(p[1], out var iterations) ||
                iterations < 100_000 || iterations > MaxIterations)
            {
                return false;
            }
            var salt = Convert.FromBase64String(p[2]);
            var expected = Convert.FromBase64String(p[3]);
            var actual = Rfc2898DeriveBytes.Pbkdf2(Peppered(password), salt, iterations, HashAlgorithmName.SHA256, expected.Length);
            return CryptographicOperations.FixedTimeEquals(actual, expected);
        }
        catch (FormatException)
        {
            return false;
        }
    }

    private byte[] Peppered(string password) =>
        _pepper.Length == 0 ? Encoding.UTF8.GetBytes(password) : HMACSHA256.HashData(_pepper, Encoding.UTF8.GetBytes(password));
}

/// <summary>
/// Opens after N consecutive "not reached / directory down" results; while open, logins skip AuthenAPI.
/// After the break, exactly one request probes AuthenAPI (half-open) instead of all of them at once.
/// </summary>
public sealed class CircuitBreaker
{
    private readonly int _threshold;
    private readonly TimeSpan _duration;
    private readonly object _lock = new();
    private int _failures;
    private DateTime _openUntil = DateTime.MinValue;
    private bool _probeInFlight;

    public CircuitBreaker(int threshold, TimeSpan duration)
    {
        _threshold = Math.Max(1, threshold);
        _duration = duration;
    }

    public bool TryEnter()
    {
        lock (_lock)
        {
            if (DateTime.UtcNow < _openUntil) return false;
            if (_failures >= _threshold)          // break elapsed: half-open
            {
                if (_probeInFlight) return false;
                _probeInFlight = true;
            }
            return true;
        }
    }

    public void Report(bool failed)
    {
        lock (_lock)
        {
            _probeInFlight = false;
            if (!failed)
            {
                _failures = 0;
                return;
            }
            _failures++;
            if (_failures >= _threshold) _openUntil = DateTime.UtcNow.Add(_duration);
        }
    }
}

/// <summary>Counts failures in the current minute (process-wide).</summary>
public sealed class RateWindow
{
    private long _minute;
    private int _count;

    public bool Allows(int max)
    {
        lock (this)
        {
            Roll();
            return _count < max;
        }
    }

    public void Add()
    {
        lock (this)
        {
            Roll();
            _count++;
        }
    }

    private void Roll()
    {
        var minute = DateTime.UtcNow.Ticks / TimeSpan.TicksPerMinute;
        if (minute != _minute) { _minute = minute; _count = 0; }
    }
}

/// <summary>Short-lived cache for profile/group lookups between logins (no passwords).</summary>
public sealed class ProfileCache
{
    private readonly ConcurrentDictionary<string, (DateTime Until, AdUser User)> _items = new();
    private readonly TimeSpan _ttl;

    public ProfileCache(TimeSpan ttl) => _ttl = ttl;

    public bool TryGet(string userKey, out AdUser? user)
    {
        user = null;
        if (_items.TryGetValue(userKey, out var e) && e.Until > DateTime.UtcNow)
        {
            user = e.User;
            return true;
        }
        return false;
    }

    public void Set(string userKey, AdUser user) => _items[userKey] = (DateTime.UtcNow.Add(_ttl), user);
}
