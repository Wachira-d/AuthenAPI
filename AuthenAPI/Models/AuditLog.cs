namespace AuthenAPI.Models;

/// <summary>
/// Audit log entry for tracking all API operations
/// </summary>
public class AuditLog
{
    /// <summary>
    /// Unique identifier for the log entry
    /// </summary>
    public Guid Id { get; set; } = Guid.NewGuid();

    /// <summary>
    /// Timestamp when the event occurred
    /// </summary>
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Type of action performed
    /// </summary>
    public AuditAction Action { get; set; }

    /// <summary>
    /// Username involved in the action
    /// </summary>
    public string? Username { get; set; }

    /// <summary>
    /// Whether the action was successful
    /// </summary>
    public bool Success { get; set; }

    /// <summary>
    /// IP address of the client
    /// </summary>
    public string? IpAddress { get; set; }

    /// <summary>
    /// User agent string from the client
    /// </summary>
    public string? UserAgent { get; set; }

    /// <summary>
    /// Additional details or error message
    /// </summary>
    public string? Details { get; set; }

    /// <summary>
    /// Duration of the operation in milliseconds
    /// </summary>
    public long? DurationMs { get; set; }

    /// <summary>
    /// Request path
    /// </summary>
    public string? RequestPath { get; set; }

    /// <summary>
    /// HTTP method (GET, POST, etc.)
    /// </summary>
    public string? HttpMethod { get; set; }

    /// <summary>
    /// HTTP status code returned
    /// </summary>
    public int? StatusCode { get; set; }
}

/// <summary>
/// Types of auditable actions
/// </summary>
public enum AuditAction
{
    /// <summary>
    /// User authentication attempt
    /// </summary>
    Authenticate,

    /// <summary>
    /// Get user information
    /// </summary>
    GetUser,

    /// <summary>
    /// Search users
    /// </summary>
    SearchUsers,

    /// <summary>
    /// Get user groups
    /// </summary>
    GetUserGroups,

    /// <summary>
    /// Check group membership
    /// </summary>
    CheckGroupMembership,

    /// <summary>
    /// Test AD connection
    /// </summary>
    TestConnection,

    /// <summary>
    /// View audit logs
    /// </summary>
    ViewAuditLogs,

    /// <summary>
    /// API Key authentication attempt
    /// </summary>
    ApiKeyAuth
}

/// <summary>
/// Request model for querying audit logs
/// </summary>
public class AuditLogQuery
{
    /// <summary>
    /// Filter by username
    /// </summary>
    public string? Username { get; set; }

    /// <summary>
    /// Filter by action type
    /// </summary>
    public AuditAction? Action { get; set; }

    /// <summary>
    /// Filter by success status
    /// </summary>
    public bool? Success { get; set; }

    /// <summary>
    /// Filter from date (UTC)
    /// </summary>
    public DateTime? FromDate { get; set; }

    /// <summary>
    /// Filter to date (UTC)
    /// </summary>
    public DateTime? ToDate { get; set; }

    /// <summary>
    /// Filter by IP address
    /// </summary>
    public string? IpAddress { get; set; }

    /// <summary>
    /// Maximum number of results (default: 100)
    /// </summary>
    public int MaxResults { get; set; } = 100;

    /// <summary>
    /// Skip number of results for pagination
    /// </summary>
    public int Skip { get; set; } = 0;
}

/// <summary>
/// Summary statistics for audit logs
/// </summary>
public class AuditLogSummary
{
    /// <summary>
    /// Total number of log entries
    /// </summary>
    public int TotalEntries { get; set; }

    /// <summary>
    /// Number of successful operations
    /// </summary>
    public int SuccessCount { get; set; }

    /// <summary>
    /// Number of failed operations
    /// </summary>
    public int FailureCount { get; set; }

    /// <summary>
    /// Breakdown by action type
    /// </summary>
    public Dictionary<string, int> ActionCounts { get; set; } = new();

    /// <summary>
    /// Unique users count
    /// </summary>
    public int UniqueUsers { get; set; }

    /// <summary>
    /// Recent failed authentication attempts
    /// </summary>
    public List<AuditLog> RecentFailedLogins { get; set; } = new();

    /// <summary>
    /// Period start date
    /// </summary>
    public DateTime? PeriodStart { get; set; }

    /// <summary>
    /// Period end date
    /// </summary>
    public DateTime? PeriodEnd { get; set; }
}
