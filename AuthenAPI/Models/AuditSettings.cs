namespace AuthenAPI.Models;

/// <summary>
/// Configuration settings for audit logging
/// </summary>
public class AuditSettings
{
    /// <summary>
    /// Enable or disable audit logging
    /// </summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// Enable file-based logging in addition to in-memory
    /// </summary>
    public bool EnableFileLogging { get; set; } = true;

    /// <summary>
    /// Directory path for audit log files
    /// </summary>
    public string? LogDirectory { get; set; }

    /// <summary>
    /// Number of days to retain audit logs
    /// </summary>
    public int RetentionDays { get; set; } = 90;

    /// <summary>
    /// Maximum failed login attempts before logging a warning
    /// </summary>
    public int FailedLoginThreshold { get; set; } = 5;

    /// <summary>
    /// Time window in minutes for failed login tracking
    /// </summary>
    public int FailedLoginWindowMinutes { get; set; } = 15;
}
