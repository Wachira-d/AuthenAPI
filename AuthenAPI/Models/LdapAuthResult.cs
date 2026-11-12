using System.Text.Json.Serialization;

namespace AuthenAPI.Models;

/// <summary>
/// Why an authentication attempt failed. Derived from the Active Directory "data" sub-code of LDAP error 49.
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum AuthFailureReason
{
    None,
    InvalidCredentials,
    UserNotFound,
    AccountLocked,
    AccountDisabled,
    AccountExpired,
    PasswordExpired,
    PasswordMustChange,
    LogonNotPermitted,
    ServerUnavailable,
    Error
}

/// <summary>
/// Detailed result of authenticating a user against Active Directory
/// </summary>
public class LdapAuthResult
{
    public bool Success { get; set; }
    public UserInfo? User { get; set; }
    public AuthFailureReason FailureReason { get; set; }

    /// <summary>How the user was verified, e.g. "SearchThenBind", "DirectBind", "PrincipalContext"</summary>
    public string? Method { get; set; }

    public string? Strategy { get; set; }
    public string? Message { get; set; }
    public long DurationMs { get; set; }

    public static LdapAuthResult Fail(AuthFailureReason reason, string? message = null) =>
        new() { Success = false, FailureReason = reason, Message = message };
}

/// <summary>
/// One connection attempt made while testing LDAP settings
/// </summary>
public class LdapAttempt
{
    public string Strategy { get; set; } = string.Empty;
    public bool Success { get; set; }
    public string? Error { get; set; }
    public long LatencyMs { get; set; }
}

/// <summary>
/// Result of testing candidate LDAP settings without saving them
/// </summary>
public class LdapTestResult
{
    public bool Success { get; set; }
    public string? Strategy { get; set; }
    public long LatencyMs { get; set; }
    public string? Error { get; set; }
    public List<LdapAttempt> Attempts { get; set; } = new();
}
