namespace AuthenAPI.Models;

/// <summary>
/// One API call as recorded by the request log
/// </summary>
public class RequestLogEntry
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    public string Method { get; set; } = string.Empty;
    public string Path { get; set; } = string.Empty;
    public string? QueryString { get; set; }
    public int StatusCode { get; set; }
    public long DurationMs { get; set; }
    public string? ClientIp { get; set; }
    public string? UserAgent { get; set; }
    public string? ApiKeyId { get; set; }
    public string? ApiKeyName { get; set; }
    public string? Username { get; set; }
    public string? Outcome { get; set; }
    public string? ErrorMessage { get; set; }
    public string? TraceId { get; set; }
    public string? LdapStrategy { get; set; }
}

/// <summary>
/// Filters for request log queries
/// </summary>
public class RequestLogQuery
{
    public DateTime? From { get; set; }
    public DateTime? To { get; set; }
    public string? Method { get; set; }
    public string? Path { get; set; }

    /// <summary>"2xx", "4xx", "5xx" or an exact code such as "401"</summary>
    public string? Status { get; set; }

    public string? ApiKeyId { get; set; }
    public string? Ip { get; set; }
    public string? Username { get; set; }
    public string? Search { get; set; }
    public long? MinDurationMs { get; set; }
    public int Skip { get; set; }
    public int Take { get; set; } = 50;
}

/// <summary>
/// A page of results with the total number of matches
/// </summary>
public class PagedResult<T>
{
    public int Total { get; set; }
    public List<T> Items { get; set; } = new();
}

/// <summary>
/// Aggregated traffic metrics for the dashboard
/// </summary>
public class MetricsReport
{
    public string Range { get; set; } = "24h";
    public DateTime From { get; set; }
    public DateTime To { get; set; }
    public int BucketMinutes { get; set; }
    public int TotalRequests { get; set; }
    public int SuccessRequests { get; set; }
    public int ClientErrors { get; set; }
    public int ServerErrors { get; set; }
    public double ErrorRate { get; set; }
    public double AvgLatencyMs { get; set; }
    public long P50LatencyMs { get; set; }
    public long P95LatencyMs { get; set; }
    public long P99LatencyMs { get; set; }
    public int AuthAttempts { get; set; }
    public int AuthSuccesses { get; set; }
    public int AuthFailures { get; set; }
    public int UniqueClients { get; set; }
    public List<TimelineBucket> Timeline { get; set; } = new();
    public List<EndpointStat> ByEndpoint { get; set; } = new();
    public List<ApiKeyStat> ByApiKey { get; set; } = new();
    public List<ClientIpStat> ByClientIp { get; set; } = new();
    public List<StatusCodeStat> ByStatusCode { get; set; } = new();
    public List<UserCountStat> TopFailedUsers { get; set; } = new();
}

public class TimelineBucket
{
    public DateTime BucketStart { get; set; }
    public int Total { get; set; }
    public int Errors { get; set; }
    public double AvgLatencyMs { get; set; }
    public int AuthSuccess { get; set; }
    public int AuthFailure { get; set; }
}

public class EndpointStat
{
    public string Endpoint { get; set; } = string.Empty;
    public int Count { get; set; }
    public int Errors { get; set; }
    public double AvgLatencyMs { get; set; }
}

public class ApiKeyStat
{
    public string? ApiKeyId { get; set; }
    public string? ApiKeyName { get; set; }
    public int Count { get; set; }
    public int Errors { get; set; }
    public DateTime? LastSeen { get; set; }
}

public class ClientIpStat
{
    public string Ip { get; set; } = string.Empty;
    public int Count { get; set; }
    public int Errors { get; set; }
}

public class StatusCodeStat
{
    public int StatusCode { get; set; }
    public int Count { get; set; }
}

public class UserCountStat
{
    public string Username { get; set; } = string.Empty;
    public int Count { get; set; }
}

/// <summary>
/// Keys used in HttpContext.Items to pass request-log details between middleware and controllers
/// </summary>
public static class RequestLogItems
{
    public const string ApiKeyId = "ReqLog.ApiKeyId";
    public const string ApiKeyName = "ReqLog.ApiKeyName";
    public const string Username = "ReqLog.Username";
    public const string Outcome = "ReqLog.Outcome";
    public const string Error = "ReqLog.Error";
    public const string LdapStrategy = "ReqLog.LdapStrategy";
}
