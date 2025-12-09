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

    /// <summary>
    /// Enable automatic purging of old logs
    /// </summary>
    public bool AutoPurgeEnabled { get; set; } = true;

    /// <summary>
    /// Interval in hours between auto-purge runs (default: 24 hours)
    /// </summary>
    public int AutoPurgeIntervalHours { get; set; } = 24;

    /// <summary>
    /// Time of day to run auto-purge (24-hour format, e.g., "02:00" for 2 AM)
    /// If not set, purge runs at the interval from service start
    /// </summary>
    public string? AutoPurgeTime { get; set; }
}
