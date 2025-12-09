using System.ComponentModel.DataAnnotations;

namespace AuthenAPI.Models;

/// <summary>
/// Request model for user authentication
/// </summary>
public class AuthenticateRequest
{
    /// <summary>
    /// Username (sAMAccountName or userPrincipalName)
    /// </summary>
    [Required(ErrorMessage = "Username is required")]
    public string Username { get; set; } = string.Empty;

    /// <summary>
    /// User password
    /// </summary>
    [Required(ErrorMessage = "Password is required")]
    public string Password { get; set; } = string.Empty;
}
