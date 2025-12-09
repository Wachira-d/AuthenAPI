using System.ComponentModel.DataAnnotations;

namespace AuthenAPI.Models;

/// <summary>
/// Request model for user authentication
/// </summary>
public class AuthenticateRequest
{
    /// <summary>
    /// Username (sAMAccountName, userPrincipalName, or email address)
    /// Examples: "john.doe", "john.doe@domain.com", "john.doe@company.com"
    /// </summary>
    [Required(ErrorMessage = "Username is required")]
    [StringLength(256, MinimumLength = 1, ErrorMessage = "Username must be between 1 and 256 characters")]
    [RegularExpression(@"^[a-zA-Z0-9._@\\-]+$", ErrorMessage = "Username contains invalid characters")]
    public string Username { get; set; } = string.Empty;

    /// <summary>
    /// User password
    /// </summary>
    [Required(ErrorMessage = "Password is required")]
    [StringLength(256, MinimumLength = 1, ErrorMessage = "Password must be between 1 and 256 characters")]
    public string Password { get; set; } = string.Empty;
}
