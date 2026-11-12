using AuthenAPI.Models;

namespace AuthenAPI.Services;

/// <summary>
/// Interface for LDAP/Active Directory operations
/// </summary>
public interface ILdapService
{
    /// <summary>
    /// Authenticate a user. Accepts sAMAccountName, DOMAIN\user, UPN or email.
    /// </summary>
    /// <returns>UserInfo if authentication succeeded, null otherwise</returns>
    Task<UserInfo?> AuthenticateAsync(string username, string password);

    /// <summary>
    /// Authenticate a user and report why it failed (bad password, locked, disabled, DC unreachable...)
    /// </summary>
    Task<LdapAuthResult> AuthenticateWithResultAsync(string username, string password, bool allowServiceAccount = false);

    /// <summary>
    /// Quick check: can the service account bind?
    /// </summary>
    Task<bool> TestConnectionAsync();

    /// <summary>
    /// Bind as the service account once using the preferred strategy.
    /// With <paramref name="reevaluate"/> the most secure strategies are tried first again.
    /// </summary>
    Task<LdapProbeResult> ProbeAsync(bool reevaluate = false, CancellationToken cancellationToken = default);

    /// <summary>
    /// Try every connection strategy and report which ones work (slow)
    /// </summary>
    Task<ConnectionTestResult> TestConnectionDetailedAsync();

    /// <summary>
    /// Test candidate settings (bind + Base DN) without saving them
    /// </summary>
    Task<LdapTestResult> TestSettingsAsync(LdapSettings candidate);

    /// <summary>
    /// Get user information by username
    /// </summary>
    Task<UserInfo?> GetUserAsync(string username);

    /// <summary>
    /// Search users in Active Directory
    /// </summary>
    Task<List<UserInfo>> SearchUsersAsync(SearchRequest request);

    /// <summary>
    /// Get the direct group memberships of a user
    /// </summary>
    Task<List<string>> GetUserGroupsAsync(string username);

    /// <summary>
    /// Check if user is a direct member of a group
    /// </summary>
    Task<bool> IsUserInGroupAsync(string username, string groupName);

    /// <summary>
    /// Drop all cached users and groups
    /// </summary>
    void ClearCache();
}
