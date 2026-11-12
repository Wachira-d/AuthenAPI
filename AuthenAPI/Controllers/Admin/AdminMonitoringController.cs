using AuthenAPI.Models;
using AuthenAPI.Services;
using AuthenAPI.Utilities;
using Microsoft.AspNetCore.Mvc;
using System.Text;

namespace AuthenAPI.Controllers.Admin;

/// <summary>
/// Health, metrics, request logs and audit logs
/// </summary>
public class AdminMonitoringController : AdminControllerBase
{
    private readonly HealthMonitorService _health;
    private readonly RequestLogService _requests;
    private readonly IAuditService _audit;

    public AdminMonitoringController(HealthMonitorService health, RequestLogService requests, IAuditService audit)
    {
        _health = health;
        _requests = requests;
        _audit = audit;
    }

    [HttpGet("health")]
    public IActionResult Health() => Ok(ApiResponse<HealthReport>.Ok(_health.BuildReport()));

    [HttpGet("health/history")]
    public IActionResult HealthHistory([FromQuery] int hours = 24) =>
        Ok(ApiResponse<List<HealthSample>>.Ok(_health.GetHistory(hours)));

    [HttpPost("health/check-now")]
    public async Task<IActionResult> CheckNow(CancellationToken cancellationToken)
    {
        await _health.ProbeNowAsync(cancellationToken);
        return Ok(ApiResponse<HealthReport>.Ok(_health.BuildReport(), "Health check completed"));
    }

    [HttpGet("metrics")]
    public IActionResult Metrics([FromQuery] string? range = "24h", [FromQuery] string? apiKeyId = null) =>
        Ok(ApiResponse<MetricsReport>.Ok(_requests.GetMetrics(range, apiKeyId)));

    [HttpGet("requests")]
    public IActionResult Requests([FromQuery] RequestLogQuery query) =>
        Ok(ApiResponse<PagedResult<RequestLogEntry>>.Ok(_requests.Query(query)));

    [HttpGet("requests/export")]
    public IActionResult ExportRequests([FromQuery] RequestLogQuery query) =>
        File(Encoding.UTF8.GetPreamble().Concat(Encoding.UTF8.GetBytes(_requests.ExportCsv(query))).ToArray(),
            "text/csv", $"requests_{DateTime.UtcNow:yyyyMMdd_HHmmss}.csv");

    [HttpGet("requests/{id}")]
    public IActionResult GetRequest(string id)
    {
        var entry = _requests.Get(id);
        return entry == null ? NotFound(ApiResponse.Fail("Request not found")) : Ok(ApiResponse<RequestLogEntry>.Ok(entry));
    }

    [HttpGet("audit")]
    public async Task<IActionResult> Audit(
        [FromQuery] string? username, [FromQuery] AuditAction? action, [FromQuery] bool? success,
        [FromQuery] DateTime? from, [FromQuery] DateTime? to, [FromQuery] string? ip,
        [FromQuery] int skip = 0, [FromQuery] int take = 50)
    {
        var page = await _audit.QueryPagedAsync(new AuditLogQuery
        {
            Username = username, Action = action, Success = success,
            FromDate = from, ToDate = to, IpAddress = ip, Skip = skip, MaxResults = take
        });
        return Ok(ApiResponse<PagedResult<AuditLog>>.Ok(page));
    }

    [HttpGet("audit/export")]
    public async Task<IActionResult> ExportAudit(
        [FromQuery] string? username, [FromQuery] AuditAction? action, [FromQuery] bool? success,
        [FromQuery] DateTime? from, [FromQuery] DateTime? to, [FromQuery] string? ip)
    {
        var page = await _audit.QueryPagedAsync(new AuditLogQuery
        {
            Username = username, Action = action, Success = success,
            FromDate = from, ToDate = to, IpAddress = ip, Skip = 0, MaxResults = 500
        });
        // QueryPaged caps a page at 500; fetch the rest for export.
        var items = page.Items;
        for (var skip = 500; skip < page.Total; skip += 500)
        {
            var next = await _audit.QueryPagedAsync(new AuditLogQuery
            {
                Username = username, Action = action, Success = success,
                FromDate = from, ToDate = to, IpAddress = ip, Skip = skip, MaxResults = 500
            });
            items.AddRange(next.Items);
        }

        var csv = CsvWriter.Build(
            new[] { "timestamp", "action", "username", "success", "ipAddress", "statusCode", "durationMs", "httpMethod", "requestPath", "details", "userAgent" },
            items.Select(l => new object?[]
            {
                l.Timestamp, l.Action.ToString(), l.Username, l.Success, l.IpAddress, l.StatusCode, l.DurationMs,
                l.HttpMethod, l.RequestPath, l.Details, l.UserAgent
            }));

        return File(Encoding.UTF8.GetPreamble().Concat(Encoding.UTF8.GetBytes(csv)).ToArray(),
            "text/csv", $"audit_{DateTime.UtcNow:yyyyMMdd_HHmmss}.csv");
    }

    [HttpGet("audit/actions")]
    public IActionResult AuditActions() =>
        Ok(ApiResponse<string[]>.Ok(Enum.GetNames<AuditAction>()));
}
