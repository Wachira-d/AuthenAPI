using System.ComponentModel.DataAnnotations;

namespace AuthenAPI.Models;

/// <summary>
/// Request model for searching users in Active Directory
/// </summary>
public class SearchRequest
{
    /// <summary>
    /// Search query (searches in displayName, sAMAccountName, mail, givenName, sn)
    /// </summary>
    [StringLength(256, ErrorMessage = "Query must not exceed 256 characters")]
    [RegularExpression(@"^[a-zA-Z0-9._@\s\-]*$", ErrorMessage = "Query contains invalid characters")]
    public string? Query { get; set; }

    /// <summary>
    /// Custom LDAP filter (overrides Query if provided)
    /// Note: Custom LDAP filters are disabled for security reasons
    /// </summary>
    [StringLength(0, ErrorMessage = "Custom LDAP filters are not allowed for security reasons")]
    public string? LdapFilter { get; set; }

    /// <summary>
    /// Maximum number of results to return (default: 100, max: 500)
    /// </summary>
    [Range(1, 500, ErrorMessage = "MaxResults must be between 1 and 500")]
    public int MaxResults { get; set; } = 100;

    /// <summary>
    /// Custom base DN for the search (optional, uses default if not specified)
    /// Note: Custom BaseDN is disabled for security reasons
    /// </summary>
    [StringLength(0, ErrorMessage = "Custom BaseDN is not allowed for security reasons")]
    public string? BaseDN { get; set; }
}
