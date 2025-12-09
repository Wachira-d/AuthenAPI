namespace AuthenAPI.Models;

/// <summary>
/// User information from Active Directory
/// </summary>
public class UserInfo
{
    /// <summary>
    /// Distinguished Name (DN)
    /// </summary>
    public string DistinguishedName { get; set; } = string.Empty;

    /// <summary>
    /// SAM Account Name (login name)
    /// </summary>
    public string SamAccountName { get; set; } = string.Empty;

    /// <summary>
    /// User Principal Name (email-like format)
    /// </summary>
    public string UserPrincipalName { get; set; } = string.Empty;

    /// <summary>
    /// Display name
    /// </summary>
    public string DisplayName { get; set; } = string.Empty;

    /// <summary>
    /// First name (given name)
    /// </summary>
    public string FirstName { get; set; } = string.Empty;

    /// <summary>
    /// Last name (surname)
    /// </summary>
    public string LastName { get; set; } = string.Empty;

    /// <summary>
    /// Email address
    /// </summary>
    public string Email { get; set; } = string.Empty;

    /// <summary>
    /// Department
    /// </summary>
    public string Department { get; set; } = string.Empty;

    /// <summary>
    /// Job title
    /// </summary>
    public string Title { get; set; } = string.Empty;

    /// <summary>
    /// Office location
    /// </summary>
    public string Office { get; set; } = string.Empty;

    /// <summary>
    /// Phone number
    /// </summary>
    public string Phone { get; set; } = string.Empty;

    /// <summary>
    /// Mobile phone number
    /// </summary>
    public string Mobile { get; set; } = string.Empty;

    /// <summary>
    /// Manager's distinguished name
    /// </summary>
    public string Manager { get; set; } = string.Empty;

    /// <summary>
    /// Employee ID
    /// </summary>
    public string EmployeeId { get; set; } = string.Empty;

    /// <summary>
    /// Company name
    /// </summary>
    public string Company { get; set; } = string.Empty;

    /// <summary>
    /// Account is enabled
    /// </summary>
    public bool IsEnabled { get; set; }

    /// <summary>
    /// Account is locked
    /// </summary>
    public bool IsLocked { get; set; }

    /// <summary>
    /// List of group memberships
    /// </summary>
    public List<string> Groups { get; set; } = new();

    /// <summary>
    /// When the account was created
    /// </summary>
    public DateTime? WhenCreated { get; set; }

    /// <summary>
    /// When the account was last modified
    /// </summary>
    public DateTime? WhenChanged { get; set; }

    /// <summary>
    /// Last logon timestamp
    /// </summary>
    public DateTime? LastLogon { get; set; }
}
