using AuthenAPI.Models;

namespace AuthenAPI.Services;

/// <summary>
/// Interface for audit logging operations
/// </summary>
public interface IAuditService
{
    /// <summary>
    /// Log an audit event
    /// </summary>
    /// <param name="log">Audit log entry</param>
    Task LogAsync(AuditLog log);

    /// <summary>
    /// Log an audit event with basic parameters
    /// </summary>
    Task LogAsync(AuditAction action, string? username, bool success, string? details = null);

    /// <summary>
    /// Query audit logs
    /// </summary>
    /// <param name="query">Query parameters</param>
    /// <returns>List of matching audit logs</returns>
    Task<List<AuditLog>> QueryAsync(AuditLogQuery query);

    /// <summary>
    /// Get audit log summary/statistics
    /// </summary>
    /// <param name="fromDate">Optional start date</param>
    /// <param name="toDate">Optional end date</param>
    /// <returns>Summary statistics</returns>
    Task<AuditLogSummary> GetSummaryAsync(DateTime? fromDate = null, DateTime? toDate = null);

    /// <summary>
    /// Get recent failed login attempts for a specific user
    /// </summary>
    /// <param name="username">Username to check</param>
    /// <param name="minutes">Time window in minutes</param>
    /// <returns>Number of failed attempts</returns>
    Task<int> GetRecentFailedLoginCountAsync(string username, int minutes = 15);

    /// <summary>
    /// Clear old audit logs
    /// </summary>
    /// <param name="olderThanDays">Remove logs older than this many days</param>
    /// <returns>Number of logs removed</returns>
    Task<int> PurgeOldLogsAsync(int olderThanDays = 90);
}
