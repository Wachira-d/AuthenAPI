namespace AuthenAPI.Models;

/// <summary>
/// Request model for searching users in Active Directory
/// </summary>
public class SearchRequest
{
    /// <summary>
    /// Search query (searches in displayName, sAMAccountName, mail, givenName, sn)
    /// </summary>
    public string? Query { get; set; }

    /// <summary>
    /// Custom LDAP filter (overrides Query if provided)
    /// </summary>
    public string? LdapFilter { get; set; }

    /// <summary>
    /// Maximum number of results to return (default: 100)
    /// </summary>
    public int MaxResults { get; set; } = 100;

    /// <summary>
    /// Custom base DN for the search (optional, uses default if not specified)
    /// </summary>
    public string? BaseDN { get; set; }
}
