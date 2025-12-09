using AuthenAPI.Models;
using AuthenAPI.Services;
using Microsoft.AspNetCore.Mvc;

namespace AuthenAPI.Controllers;

/// <summary>
/// API Controller for viewing and managing audit logs
/// </summary>
[ApiController]
[Route("api/[controller]")]
[Produces("application/json")]
public class AuditController : ControllerBase
{
    private readonly IAuditService _auditService;
    private readonly ILogger<AuditController> _logger;

    public AuditController(IAuditService auditService, ILogger<AuditController> logger)
    {
        _auditService = auditService;
        _logger = logger;
    }

    /// <summary>
    /// Query audit logs with optional filters
    /// </summary>
    /// <param name="query">Query parameters</param>
    /// <returns>List of audit log entries</returns>
    [HttpPost("logs")]
    [ProducesResponseType(typeof(ApiResponse<List<AuditLog>>), StatusCodes.Status200OK)]
    public async Task<IActionResult> QueryLogs([FromBody] AuditLogQuery query)
    {
        _logger.LogInformation("Querying audit logs");

        // Log this access
        await _auditService.LogAsync(new AuditLog
        {
            Action = AuditAction.ViewAuditLogs,
            Success = true,
            IpAddress = GetClientIpAddress(),
            UserAgent = GetUserAgent(),
            RequestPath = Request.Path,
            HttpMethod = Request.Method,
            Details = $"Query: Username={query.Username}, Action={query.Action}, MaxResults={query.MaxResults}"
        });

        var logs = await _auditService.QueryAsync(query);

        return Ok(ApiResponse<List<AuditLog>>.Ok(logs, $"Found {logs.Count} log entries"));
    }

    /// <summary>
    /// Get audit logs using query string parameters
    /// </summary>
    /// <param name="username">Filter by username</param>
    /// <param name="action">Filter by action type</param>
    /// <param name="success">Filter by success status</param>
    /// <param name="fromDate">Filter from date (ISO 8601)</param>
    /// <param name="toDate">Filter to date (ISO 8601)</param>
    /// <param name="maxResults">Maximum results (default: 100)</param>
    /// <param name="skip">Skip entries for pagination</param>
    /// <returns>List of audit log entries</returns>
    [HttpGet("logs")]
    [ProducesResponseType(typeof(ApiResponse<List<AuditLog>>), StatusCodes.Status200OK)]
    public async Task<IActionResult> GetLogs(
        [FromQuery] string? username = null,
        [FromQuery] AuditAction? action = null,
        [FromQuery] bool? success = null,
        [FromQuery] DateTime? fromDate = null,
        [FromQuery] DateTime? toDate = null,
        [FromQuery] int maxResults = 100,
        [FromQuery] int skip = 0)
    {
        var query = new AuditLogQuery
        {
            Username = username,
            Action = action,
            Success = success,
            FromDate = fromDate,
            ToDate = toDate,
            MaxResults = maxResults,
            Skip = skip
        };

        _logger.LogInformation("Querying audit logs via GET");

        var logs = await _auditService.QueryAsync(query);

        return Ok(ApiResponse<List<AuditLog>>.Ok(logs, $"Found {logs.Count} log entries"));
    }

    /// <summary>
    /// Get audit log summary and statistics
    /// </summary>
    /// <param name="fromDate">Start date for summary period (ISO 8601)</param>
    /// <param name="toDate">End date for summary period (ISO 8601)</param>
    /// <returns>Summary statistics</returns>
    [HttpGet("summary")]
    [ProducesResponseType(typeof(ApiResponse<AuditLogSummary>), StatusCodes.Status200OK)]
    public async Task<IActionResult> GetSummary(
        [FromQuery] DateTime? fromDate = null,
        [FromQuery] DateTime? toDate = null)
    {
        _logger.LogInformation("Getting audit log summary");

        var summary = await _auditService.GetSummaryAsync(fromDate, toDate);

        return Ok(ApiResponse<AuditLogSummary>.Ok(summary, "Audit log summary"));
    }

    /// <summary>
    /// Get failed login attempts for a specific user
    /// </summary>
    /// <param name="username">Username to check</param>
    /// <param name="minutes">Time window in minutes (default: 15)</param>
    /// <returns>Count of failed login attempts</returns>
    [HttpGet("failed-logins/{username}")]
    [ProducesResponseType(typeof(ApiResponse<int>), StatusCodes.Status200OK)]
    public async Task<IActionResult> GetFailedLogins(string username, [FromQuery] int minutes = 15)
    {
        if (string.IsNullOrWhiteSpace(username))
        {
            return BadRequest(ApiResponse.Fail("Username is required"));
        }

        _logger.LogInformation("Checking failed logins for user: {Username}", username);

        var count = await _auditService.GetRecentFailedLoginCountAsync(username, minutes);

        return Ok(ApiResponse<int>.Ok(count, $"Failed login attempts in last {minutes} minutes: {count}"));
    }

    /// <summary>
    /// Get authentication logs for a specific user
    /// </summary>
    /// <param name="username">Username</param>
    /// <param name="maxResults">Maximum results (default: 50)</param>
    /// <returns>List of authentication log entries for the user</returns>
    [HttpGet("users/{username}/auth-history")]
    [ProducesResponseType(typeof(ApiResponse<List<AuditLog>>), StatusCodes.Status200OK)]
    public async Task<IActionResult> GetUserAuthHistory(string username, [FromQuery] int maxResults = 50)
    {
        if (string.IsNullOrWhiteSpace(username))
        {
            return BadRequest(ApiResponse.Fail("Username is required"));
        }

        _logger.LogInformation("Getting auth history for user: {Username}", username);

        var query = new AuditLogQuery
        {
            Username = username,
            Action = AuditAction.Authenticate,
            MaxResults = maxResults
        };

        var logs = await _auditService.QueryAsync(query);

        return Ok(ApiResponse<List<AuditLog>>.Ok(logs, $"Found {logs.Count} authentication entries for user '{username}'"));
    }

    /// <summary>
    /// Purge old audit logs
    /// </summary>
    /// <param name="olderThanDays">Remove logs older than this many days (default: 90)</param>
    /// <returns>Number of logs removed</returns>
    [HttpDelete("logs/purge")]
    [ProducesResponseType(typeof(ApiResponse<int>), StatusCodes.Status200OK)]
    public async Task<IActionResult> PurgeLogs([FromQuery] int olderThanDays = 90)
    {
        _logger.LogInformation("Purging audit logs older than {Days} days", olderThanDays);

        // Log this action before purging
        await _auditService.LogAsync(new AuditLog
        {
            Action = AuditAction.ViewAuditLogs,
            Success = true,
            IpAddress = GetClientIpAddress(),
            UserAgent = GetUserAgent(),
            RequestPath = Request.Path,
            HttpMethod = Request.Method,
            Details = $"Purging logs older than {olderThanDays} days"
        });

        var purgedCount = await _auditService.PurgeOldLogsAsync(olderThanDays);

        return Ok(ApiResponse<int>.Ok(purgedCount, $"Purged {purgedCount} old log entries"));
    }

    #region Private Helper Methods

    private string? GetClientIpAddress()
    {
        var forwardedFor = Request.Headers["X-Forwarded-For"].FirstOrDefault();
        if (!string.IsNullOrEmpty(forwardedFor))
        {
            return forwardedFor.Split(',').FirstOrDefault()?.Trim();
        }

        return HttpContext.Connection.RemoteIpAddress?.ToString();
    }

    private string? GetUserAgent()
    {
        return Request.Headers["User-Agent"].FirstOrDefault();
    }

    #endregion
}
