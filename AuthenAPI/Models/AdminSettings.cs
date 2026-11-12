namespace AuthenAPI.Models;

/// <summary>
/// Admin portal access settings
/// </summary>
public class AdminSettings
{
    /// <summary>
    /// Enable the admin portal (/admin and /api/admin)
    /// </summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// AD users (sAMAccountName or UPN; email is not accepted) granted the Admin role
    /// </summary>
    public List<string> AdminUsers { get; set; } = new();

    /// <summary>
    /// AD users granted the read-only Viewer role
    /// </summary>
    public List<string> ViewerUsers { get; set; } = new();

    /// <summary>
    /// AD group names (CN) whose direct members get the Admin role
    /// </summary>
    public List<string> AdminGroups { get; set; } = new();

    /// <summary>
    /// AD group names (CN) whose direct members get the Viewer role
    /// </summary>
    public List<string> ViewerGroups { get; set; } = new();

    /// <summary>
    /// Optional extra IP restriction for the admin portal (IP or CIDR). Empty = no extra restriction.
    /// Loopback is always allowed so the server itself can always reach the portal.
    /// </summary>
    public List<string> AllowedIpAddresses { get; set; } = new();

    /// <summary>
    /// Admin session lifetime in minutes (sliding). Takes effect after an app restart.
    /// </summary>
    public int SessionTimeoutMinutes { get; set; } = 60;

    /// <summary>
    /// Failed admin logins (per username + IP) before a temporary lockout
    /// </summary>
    public int MaxFailedLogins { get; set; } = 5;

    /// <summary>
    /// Lockout duration in minutes after too many failed admin logins
    /// </summary>
    public int LockoutMinutes { get; set; } = 15;

    /// <summary>
    /// Local "break-glass" accounts that work even when Active Directory is unreachable.
    /// Generate a hash with: AuthenAPI.exe hash-password "your-password"
    /// </summary>
    public List<LocalAdminAccount> LocalAdmins { get; set; } = new();
}

/// <summary>
/// Local admin account (not stored in Active Directory)
/// </summary>
public class LocalAdminAccount
{
    public string Username { get; set; } = string.Empty;
    public string PasswordHash { get; set; } = string.Empty;
    public string Role { get; set; } = AdminRoles.Admin;
    public string? DisplayName { get; set; }
}

/// <summary>
/// Admin portal role names and policy names
/// </summary>
public static class AdminRoles
{
    public const string Admin = "Admin";
    public const string Viewer = "Viewer";

    public const string ReadPolicy = "AdminRead";
    public const string WritePolicy = "AdminWrite";
    public const string Scheme = "AdminCookie";
}
