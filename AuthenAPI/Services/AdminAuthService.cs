using AuthenAPI.Models;
using AuthenAPI.Utilities;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.Options;
using System.Security.Claims;

namespace AuthenAPI.Services;

public enum AdminLoginStatus
{
    Success,
    InvalidCredentials,
    NotAuthorized,
    LockedOut,
    Busy,
    DirectoryUnavailable
}

public sealed class AdminLoginResult
{
    public AdminLoginStatus Status { get; init; }
    public AdminSession? Session { get; init; }
    public ClaimsPrincipal? Principal { get; init; }
    public int RetryAfterSeconds { get; init; }
    public string? Detail { get; init; }
}

/// <summary>
/// Limits admin login attempts. An attempt is counted (reserved) atomically BEFORE the password is
/// checked, so concurrent requests cannot slip past the limit; a successful login gives the
/// reservation back. Counters: per (username, IP), per username across all IPs, and per IP.
/// </summary>
public sealed class LoginAttemptTracker
{
    private const int MaxFailuresPerIp = 20;
    private const int UsernameAcrossIpsFactor = 4;
    private readonly Dictionary<string, Attempts> _attempts = new();
    private readonly object _lock = new();

    public bool TryBegin(string username, string ip, int maxFailures, TimeSpan lockout, out int retryAfterSeconds)
    {
        var now = DateTime.UtcNow;
        var perUser = Math.Max(1, maxFailures);
        var keys = Keys(username, ip, perUser);

        lock (_lock)
        {
            retryAfterSeconds = 0;
            foreach (var (key, _) in keys)
            {
                if (_attempts.TryGetValue(key, out var a) && a.LockedUntil > now)
                {
                    retryAfterSeconds = Math.Max(retryAfterSeconds, (int)Math.Ceiling((a.LockedUntil - now).TotalSeconds));
                }
            }
            if (retryAfterSeconds > 0) return false;

            foreach (var (key, limit) in keys)
            {
                if (!_attempts.TryGetValue(key, out var a))
                {
                    a = new Attempts { WindowStart = now };
                    _attempts[key] = a;
                }

                if (now - a.WindowStart > lockout)
                {
                    a.WindowStart = now;
                    a.Count = 0;
                }

                a.Count++;
                if (a.Count >= limit)
                {
                    a.LockedUntil = now.Add(lockout);
                    a.Count = 0;
                }
            }

            if (_attempts.Count > 10_000)
            {
                foreach (var stale in _attempts.Where(kv => kv.Value.LockedUntil < now && now - kv.Value.WindowStart > lockout)
                             .Select(kv => kv.Key).ToList())
                {
                    _attempts.Remove(stale);
                }
            }
            return true;
        }
    }

    /// <summary>Give back the reservation made by <see cref="TryBegin"/></summary>
    public void Succeeded(string username, string ip)
    {
        lock (_lock)
        {
            foreach (var (key, _) in Keys(username, ip, 1))
            {
                if (_attempts.TryGetValue(key, out var a) && a.Count > 0) a.Count--;
            }
            _attempts.Remove(PairKey(username, ip));
        }
    }

    private static (string Key, int Limit)[] Keys(string username, string ip, int perUser) => new[]
    {
        (PairKey(username, ip), perUser),
        ($"user|{username.ToLowerInvariant()}", perUser * UsernameAcrossIpsFactor),
        ($"ip|{ip}", MaxFailuresPerIp)
    };

    private static string PairKey(string username, string ip) => $"pair|{username.ToLowerInvariant()}|{ip}";

    private sealed class Attempts
    {
        public DateTime WindowStart;
        public int Count;
        public DateTime LockedUntil = DateTime.MinValue;
    }
}

/// <summary>
/// Signs administrators in with a local break-glass account or their AD credentials
/// </summary>
public sealed class AdminAuthService
{
    public const string ClaimDisplayName = "admin:display_name";
    public const string ClaimAuthMethod = "admin:auth_method";
    public const string ClaimRoleSource = "admin:role_source";
    public const string ClaimIdentities = "admin:identities";
    public const string ClaimGroups = "admin:groups";
    public const string ClaimIssuedAt = "admin:issued";
    public const string ClaimCheckedAt = "admin:checked";

    /// <summary>Hard cap on a session regardless of sliding renewal</summary>
    private static readonly TimeSpan AbsoluteLifetime = TimeSpan.FromHours(12);

    /// <summary>How often group-based sessions re-check AD membership</summary>
    private static readonly TimeSpan GroupRecheckInterval = TimeSpan.FromMinutes(10);

    /// <summary>Concurrent admin logins (each one runs PBKDF2 or an LDAP bind)</summary>
    private static readonly SemaphoreSlim LoginConcurrency = new(4, 4);

    private readonly ILdapService _ldap;
    private readonly IOptionsMonitor<AdminSettings> _settings;
    private readonly LoginAttemptTracker _tracker;
    private readonly ILogger<AdminAuthService> _logger;

    public AdminAuthService(ILdapService ldap, IOptionsMonitor<AdminSettings> settings, LoginAttemptTracker tracker, ILogger<AdminAuthService> logger)
    {
        _ldap = ldap;
        _settings = settings;
        _tracker = tracker;
        _logger = logger;
    }

    public async Task<AdminLoginResult> LoginAsync(string username, string password, string clientIp)
    {
        var settings = _settings.CurrentValue;
        username = username.Trim();
        var lockout = TimeSpan.FromMinutes(Math.Max(1, settings.LockoutMinutes));

        if (!_tracker.TryBegin(username, clientIp, settings.MaxFailedLogins, lockout, out var retryAfter))
        {
            return new AdminLoginResult { Status = AdminLoginStatus.LockedOut, RetryAfterSeconds = retryAfter };
        }

        if (!await LoginConcurrency.WaitAsync(TimeSpan.FromSeconds(10)))
        {
            return new AdminLoginResult { Status = AdminLoginStatus.Busy, RetryAfterSeconds = 5 };
        }

        try
        {
            var result = await LoginCoreAsync(username, password, settings);
            if (result.Status == AdminLoginStatus.Success)
            {
                _tracker.Succeeded(username, clientIp);
            }
            return result;
        }
        finally
        {
            LoginConcurrency.Release();
        }
    }

    private async Task<AdminLoginResult> LoginCoreAsync(string username, string password, AdminSettings settings)
    {
        // 1. Local break-glass accounts (work even when AD is down)
        var local = settings.LocalAdmins.FirstOrDefault(a =>
            !string.IsNullOrWhiteSpace(a.Username) && a.Username.Equals(username, StringComparison.OrdinalIgnoreCase));
        if (local != null)
        {
            if (!LocalPasswordHasher.Verify(password, local.PasswordHash))
            {
                return new AdminLoginResult { Status = AdminLoginStatus.InvalidCredentials, Detail = "Local account: wrong password" };
            }

            var localRole = LocalRole(local);
            return Success(local.Username, local.DisplayName ?? local.Username, localRole, "local", "local",
                new[] { local.Username }, Array.Empty<string>(), settings);
        }

        // 2. Active Directory
        var auth = await _ldap.AuthenticateWithResultAsync(username, password, allowServiceAccount: true);
        if (!auth.Success || auth.User == null)
        {
            if (auth.FailureReason is AuthFailureReason.ServerUnavailable or AuthFailureReason.Error)
            {
                return new AdminLoginResult { Status = AdminLoginStatus.DirectoryUnavailable, Detail = auth.Message };
            }
            return new AdminLoginResult { Status = AdminLoginStatus.InvalidCredentials, Detail = auth.FailureReason.ToString() };
        }

        var user = auth.User;
        // Only directory-assigned names count as identity. The typed input and the mail attribute do not:
        // mail can often be edited by the user or helpdesk, and would otherwise grant admin rights.
        var identities = DirectoryIdentities(user);
        var (role, source) = ResolveRole(settings, identities, user.Groups);
        if (role == null)
        {
            _logger.LogWarning("Admin login denied: {Username} authenticated against AD but is not an admin or viewer", username);
            return new AdminLoginResult { Status = AdminLoginStatus.NotAuthorized, Detail = "Not listed in AdminSettings" };
        }

        var name = string.IsNullOrWhiteSpace(user.SamAccountName) ? username : user.SamAccountName;
        var display = string.IsNullOrWhiteSpace(user.DisplayName) ? name : user.DisplayName;
        return Success(name, display, role, "ldap", source, identities, user.Groups, settings);
    }

    private static string[] DirectoryIdentities(UserInfo user) =>
        new[] { user.SamAccountName, user.UserPrincipalName }
            .Where(i => !string.IsNullOrWhiteSpace(i))
            .Select(i => i!)
            .ToArray();

    private static string LocalRole(LocalAdminAccount account) =>
        account.Role.Equals(AdminRoles.Viewer, StringComparison.OrdinalIgnoreCase) ? AdminRoles.Viewer : AdminRoles.Admin;

    /// <summary>
    /// Role from user lists (Admin wins over Viewer) or from direct AD group membership
    /// </summary>
    public static (string? Role, string Source) ResolveRole(AdminSettings settings, IEnumerable<string?> identities, IEnumerable<string> groups)
    {
        var ids = identities.Where(i => !string.IsNullOrWhiteSpace(i)).Select(i => i!.Trim()).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var groupSet = groups.ToHashSet(StringComparer.OrdinalIgnoreCase);

        bool Listed(IEnumerable<string> list) => list.Any(entry => ids.Contains(Normalize(entry)) || ids.Contains(entry.Trim()));
        bool InGroup(IEnumerable<string> list) => list.Any(g => groupSet.Contains(g.Trim()));

        if (Listed(settings.AdminUsers)) return (AdminRoles.Admin, "user-list");
        if (InGroup(settings.AdminGroups)) return (AdminRoles.Admin, "group");
        if (Listed(settings.ViewerUsers)) return (AdminRoles.Viewer, "user-list");
        if (InGroup(settings.ViewerGroups)) return (AdminRoles.Viewer, "group");
        return (null, string.Empty);
    }

    /// <summary>"DOMAIN\user" → "user". Identities always come from this directory, so the domain part is redundant.</summary>
    private static string Normalize(string value)
    {
        var v = value.Trim();
        var slash = v.IndexOf('\\');
        return slash >= 0 ? v[(slash + 1)..] : v;
    }

    private static AdminLoginResult Success(string username, string displayName, string role, string method,
        string roleSource, IEnumerable<string> identities, IEnumerable<string> groups, AdminSettings settings)
    {
        var now = DateTime.UtcNow.Ticks.ToString();
        var claims = new List<Claim>
        {
            new(ClaimTypes.Name, username),
            new(ClaimTypes.Role, role),
            new(ClaimDisplayName, displayName),
            new(ClaimAuthMethod, method),
            new(ClaimRoleSource, roleSource),
            new(ClaimIssuedAt, now),
            new(ClaimCheckedAt, now)
        };
        claims.AddRange(identities.Distinct(StringComparer.OrdinalIgnoreCase).Select(i => new Claim(ClaimIdentities, i)));

        // Only the groups that matter for portal roles go into the cookie.
        var relevant = settings.AdminGroups.Concat(settings.ViewerGroups).Select(g => g.Trim()).ToHashSet(StringComparer.OrdinalIgnoreCase);
        claims.AddRange(groups.Where(relevant.Contains).Distinct(StringComparer.OrdinalIgnoreCase).Select(g => new Claim(ClaimGroups, g)));

        var principal = new ClaimsPrincipal(new ClaimsIdentity(claims, AdminRoles.Scheme));
        return new AdminLoginResult
        {
            Status = AdminLoginStatus.Success,
            Principal = principal,
            Session = new AdminSession
            {
                Username = username,
                DisplayName = displayName,
                Role = role,
                AuthMethod = method,
                ExpiresAt = DateTime.UtcNow.AddMinutes(Math.Max(5, settings.SessionTimeoutMinutes))
            }
        };
    }

    public static AdminSession SessionFrom(ClaimsPrincipal user, DateTimeOffset? expires) => new()
    {
        Username = user.Identity?.Name ?? string.Empty,
        DisplayName = user.FindFirstValue(ClaimDisplayName) ?? user.Identity?.Name ?? string.Empty,
        Role = user.FindFirstValue(ClaimTypes.Role) ?? AdminRoles.Viewer,
        AuthMethod = user.FindFirstValue(ClaimAuthMethod) ?? "ldap",
        ExpiresAt = expires?.UtcDateTime
    };

    /// <summary>
    /// Runs on every request with an admin cookie. Ends the session when it is older than the absolute
    /// lifetime or when the admin's access was removed: immediately for settings changes, and within
    /// <see cref="GroupRecheckInterval"/> for AD group membership changes (fails closed if AD can't confirm).
    /// </summary>
    public static async Task ValidatePrincipalAsync(CookieValidatePrincipalContext context)
    {
        var services = context.HttpContext.RequestServices;
        var settings = services.GetRequiredService<IOptionsMonitor<AdminSettings>>().CurrentValue;
        var principal = context.Principal;
        var name = principal?.Identity?.Name;
        var role = principal?.FindFirstValue(ClaimTypes.Role);
        var source = principal?.FindFirstValue(ClaimRoleSource);

        if (principal == null || !settings.Enabled || name == null || role == null || IsOlderThan(principal, ClaimIssuedAt, AbsoluteLifetime))
        {
            context.RejectPrincipal();
            return;
        }

        var identities = principal.FindAll(ClaimIdentities).Select(c => c.Value).ToList();
        var groups = principal.FindAll(ClaimGroups).Select(c => c.Value).ToList();

        var stillValid = source switch
        {
            "local" => settings.LocalAdmins.Any(a => a.Username.Equals(name, StringComparison.OrdinalIgnoreCase) && LocalRole(a) == role),
            "user-list" or "group" => ResolveRole(settings, identities, groups).Role == role,
            _ => false
        };

        if (stillValid && source == "group" && IsOlderThan(principal, ClaimCheckedAt, GroupRecheckInterval))
        {
            var user = await services.GetRequiredService<ILdapService>().GetUserAsync(name);
            stillValid = user is { IsEnabled: true } &&
                         ResolveRole(settings, DirectoryIdentities(user), user.Groups).Role == role;

            if (stillValid)
            {
                var identity = new ClaimsIdentity(principal.Claims.Where(c => c.Type != ClaimCheckedAt), AdminRoles.Scheme);
                identity.AddClaim(new Claim(ClaimCheckedAt, DateTime.UtcNow.Ticks.ToString()));
                context.ReplacePrincipal(new ClaimsPrincipal(identity));
                context.ShouldRenew = true;
            }
        }

        if (!stillValid)
        {
            context.RejectPrincipal();
        }
    }

    private static bool IsOlderThan(ClaimsPrincipal principal, string claimType, TimeSpan age)
    {
        var value = principal.FindFirstValue(claimType);
        return value == null || !long.TryParse(value, out var ticks) || DateTime.UtcNow - new DateTime(ticks, DateTimeKind.Utc) > age;
    }
}
