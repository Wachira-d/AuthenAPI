using AuthenAPI.Models;
using AuthenAPI.Utilities;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.Options;
using System.Collections.Concurrent;
using System.Security.Claims;

namespace AuthenAPI.Services;

public enum AdminLoginStatus
{
    Success,
    InvalidCredentials,
    NotAuthorized,
    LockedOut,
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
/// Counts failed admin logins per (username, IP) and per IP, and locks out temporarily
/// </summary>
public sealed class LoginAttemptTracker
{
    private const int MaxFailuresPerIp = 20;
    private readonly ConcurrentDictionary<string, Attempts> _attempts = new();

    public bool IsLockedOut(string username, string ip, out int retryAfterSeconds)
    {
        retryAfterSeconds = 0;
        var now = DateTime.UtcNow;
        foreach (var key in Keys(username, ip))
        {
            if (_attempts.TryGetValue(key, out var a) && a.LockedUntil > now)
            {
                retryAfterSeconds = Math.Max(retryAfterSeconds, (int)Math.Ceiling((a.LockedUntil - now).TotalSeconds));
            }
        }
        return retryAfterSeconds > 0;
    }

    public void RecordFailure(string username, string ip, int maxFailures, TimeSpan lockout)
    {
        var now = DateTime.UtcNow;
        foreach (var key in Keys(username, ip))
        {
            var limit = key.StartsWith("ip|") ? MaxFailuresPerIp : Math.Max(1, maxFailures);
            var a = _attempts.GetOrAdd(key, _ => new Attempts());
            lock (a)
            {
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
        }

        // keep the dictionary from growing without bound
        if (_attempts.Count > 10_000)
        {
            foreach (var (key, a) in _attempts)
            {
                if (a.LockedUntil < now && now - a.WindowStart > lockout) _attempts.TryRemove(key, out _);
            }
        }
    }

    public void RecordSuccess(string username, string ip) => _attempts.TryRemove(UserKey(username, ip), out _);

    private static IEnumerable<string> Keys(string username, string ip) => new[] { UserKey(username, ip), $"ip|{ip}" };

    private static string UserKey(string username, string ip) => $"user|{username.ToLowerInvariant()}|{ip}";

    private sealed class Attempts
    {
        public DateTime WindowStart = DateTime.UtcNow;
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

        if (_tracker.IsLockedOut(username, clientIp, out var retryAfter))
        {
            return new AdminLoginResult { Status = AdminLoginStatus.LockedOut, RetryAfterSeconds = retryAfter };
        }

        var lockout = TimeSpan.FromMinutes(Math.Max(1, settings.LockoutMinutes));

        // 1. Local break-glass accounts (work even when AD is down)
        var local = settings.LocalAdmins.FirstOrDefault(a =>
            !string.IsNullOrWhiteSpace(a.Username) && a.Username.Equals(username, StringComparison.OrdinalIgnoreCase));
        if (local != null)
        {
            if (!LocalPasswordHasher.Verify(password, local.PasswordHash))
            {
                _tracker.RecordFailure(username, clientIp, settings.MaxFailedLogins, lockout);
                return new AdminLoginResult { Status = AdminLoginStatus.InvalidCredentials, Detail = "Local account: wrong password" };
            }

            var role = local.Role.Equals(AdminRoles.Viewer, StringComparison.OrdinalIgnoreCase) ? AdminRoles.Viewer : AdminRoles.Admin;
            _tracker.RecordSuccess(username, clientIp);
            return Success(local.Username, local.DisplayName ?? local.Username, role, "local", "local", new[] { local.Username }, settings);
        }

        // 2. Active Directory
        var auth = await _ldap.AuthenticateWithResultAsync(username, password);
        if (!auth.Success || auth.User == null)
        {
            if (auth.FailureReason is AuthFailureReason.ServerUnavailable or AuthFailureReason.Error)
            {
                return new AdminLoginResult { Status = AdminLoginStatus.DirectoryUnavailable, Detail = auth.Message };
            }

            _tracker.RecordFailure(username, clientIp, settings.MaxFailedLogins, lockout);
            return new AdminLoginResult { Status = AdminLoginStatus.InvalidCredentials, Detail = auth.FailureReason.ToString() };
        }

        var user = auth.User;
        var identities = new[] { username, user.SamAccountName, user.UserPrincipalName, user.Email };
        var (resolvedRole, source) = ResolveRole(settings, identities, user.Groups);
        if (resolvedRole == null)
        {
            _logger.LogWarning("Admin login denied: {Username} authenticated against AD but is not an admin or viewer", username);
            return new AdminLoginResult { Status = AdminLoginStatus.NotAuthorized, Detail = "Not listed in AdminSettings" };
        }

        _tracker.RecordSuccess(username, clientIp);
        var name = string.IsNullOrWhiteSpace(user.SamAccountName) ? username : user.SamAccountName;
        var display = string.IsNullOrWhiteSpace(user.DisplayName) ? name : user.DisplayName;
        return Success(name, display, resolvedRole, "ldap", source, identities, settings);
    }

    /// <summary>
    /// Role from user lists (Admin wins over Viewer) or from direct AD group membership
    /// </summary>
    public static (string? Role, string Source) ResolveRole(AdminSettings settings, IEnumerable<string?> identities, IEnumerable<string> groups)
    {
        var ids = identities.Where(i => !string.IsNullOrWhiteSpace(i)).Select(i => Normalize(i!)).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var groupSet = groups.ToHashSet(StringComparer.OrdinalIgnoreCase);

        bool Listed(IEnumerable<string> list) => list.Any(entry => ids.Contains(Normalize(entry)) || ids.Contains(entry.Trim()));
        bool InGroup(IEnumerable<string> list) => list.Any(g => groupSet.Contains(g.Trim()));

        if (Listed(settings.AdminUsers)) return (AdminRoles.Admin, "user-list");
        if (InGroup(settings.AdminGroups)) return (AdminRoles.Admin, "group");
        if (Listed(settings.ViewerUsers)) return (AdminRoles.Viewer, "user-list");
        if (InGroup(settings.ViewerGroups)) return (AdminRoles.Viewer, "group");
        return (null, string.Empty);
    }

    /// <summary>"DOMAIN\user" → "user"; "user@x" stays as is (compared as a whole)</summary>
    private static string Normalize(string value)
    {
        var v = value.Trim();
        var slash = v.IndexOf('\\');
        return slash >= 0 ? v[(slash + 1)..] : v;
    }

    private static AdminLoginResult Success(string username, string displayName, string role, string method,
        string roleSource, IEnumerable<string?> identities, AdminSettings settings)
    {
        var claims = new List<Claim>
        {
            new(ClaimTypes.Name, username),
            new(ClaimTypes.Role, role),
            new(ClaimDisplayName, displayName),
            new(ClaimAuthMethod, method),
            new(ClaimRoleSource, roleSource)
        };
        claims.AddRange(identities
            .Where(i => !string.IsNullOrWhiteSpace(i))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Select(i => new Claim(ClaimIdentities, i!)));

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
    /// Cookie validation on every request: a session ends as soon as the admin's access is
    /// removed from settings (for local and user-list based roles; group-based roles last until expiry).
    /// </summary>
    public static Task ValidatePrincipalAsync(CookieValidatePrincipalContext context)
    {
        var settings = context.HttpContext.RequestServices.GetRequiredService<IOptionsMonitor<AdminSettings>>().CurrentValue;
        var principal = context.Principal;
        var name = principal?.Identity?.Name;
        var role = principal?.FindFirstValue(ClaimTypes.Role);
        var source = principal?.FindFirstValue(ClaimRoleSource);

        var stillValid = settings.Enabled && name != null && role != null && source switch
        {
            "local" => settings.LocalAdmins.Any(a =>
                a.Username.Equals(name, StringComparison.OrdinalIgnoreCase) &&
                (a.Role.Equals(AdminRoles.Viewer, StringComparison.OrdinalIgnoreCase) ? AdminRoles.Viewer : AdminRoles.Admin) == role),
            "user-list" => ResolveRole(settings,
                principal!.FindAll(ClaimIdentities).Select(c => c.Value).Append(name), Array.Empty<string>()).Role == role,
            "group" => true,
            _ => false
        };

        if (!stillValid)
        {
            context.RejectPrincipal();
        }
        return Task.CompletedTask;
    }
}
