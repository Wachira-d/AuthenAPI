using AuthenAPI.Models;

namespace AuthenAPI.Services;

/// <summary>
/// Interface for LDAP/Active Directory operations
/// </summary>
public interface ILdapService
{
    /// <summary>
    /// Authenticate a user against Active Directory
    /// </summary>
    /// <param name="username">Username (sAMAccountName or UPN)</param>
    /// <param name="password">Password</param>
    /// <returns>UserInfo if authentication successful, null otherwise</returns>
    Task<UserInfo?> AuthenticateAsync(string username, string password);

    /// <summary>
    /// Test connection to Active Directory server
    /// </summary>
    /// <returns>True if connection successful</returns>
    Task<bool> TestConnectionAsync();

    /// <summary>
    /// Test connection with detailed diagnostics trying multiple strategies
    /// </summary>
    /// <returns>Detailed test result with all strategies tried</returns>
    Task<ConnectionTestResult> TestConnectionDetailedAsync();

    /// <summary>
    /// Get user information by username
    /// </summary>
    /// <param name="username">Username (sAMAccountName or UPN)</param>
    /// <returns>UserInfo if found, null otherwise</returns>
    Task<UserInfo?> GetUserAsync(string username);

    /// <summary>
    /// Search users in Active Directory
    /// </summary>
    /// <param name="request">Search request parameters</param>
    /// <returns>List of matching users</returns>
    Task<List<UserInfo>> SearchUsersAsync(SearchRequest request);

    /// <summary>
    /// Get all groups for a user
    /// </summary>
    /// <param name="username">Username</param>
    /// <returns>List of group names</returns>
    Task<List<string>> GetUserGroupsAsync(string username);

    /// <summary>
    /// Check if user is member of a specific group
    /// </summary>
    /// <param name="username">Username</param>
    /// <param name="groupName">Group name</param>
    /// <returns>True if user is member of the group</returns>
    Task<bool> IsUserInGroupAsync(string username, string groupName);
}
