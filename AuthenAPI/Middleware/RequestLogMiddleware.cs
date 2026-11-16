using AuthenAPI.Models;
using AuthenAPI.Services;
using AuthenAPI.Utilities;
using System.Diagnostics;

namespace AuthenAPI.Middleware;

/// <summary>
/// Records every call to the public API (/api/*, except /api/admin) in the request log.
/// Placed early in the pipeline so requests blocked by the IP whitelist, rate limiter or
/// API-key check are recorded too.
/// </summary>
public class RequestLogMiddleware
{
    private const int MaxFieldLength = 512;
    private readonly RequestDelegate _next;

    public RequestLogMiddleware(RequestDelegate next) => _next = next;

    public async Task InvokeAsync(HttpContext context, RequestLogService requestLog)
    {
        var path = context.Request.Path;
        var isApi = path.StartsWithSegments("/api", StringComparison.OrdinalIgnoreCase) &&
                    !path.StartsWithSegments("/api/admin", StringComparison.OrdinalIgnoreCase);
        // SSO: log the protocol endpoints and login submissions, not static assets or page views.
        var isSso = path.StartsWithSegments("/connect", StringComparison.OrdinalIgnoreCase) ||
                    (path.Equals("/sso/login", StringComparison.OrdinalIgnoreCase) && HttpMethods.IsPost(context.Request.Method));
        if (!isApi && !isSso)
        {
            await _next(context);
            return;
        }

        var stopwatch = Stopwatch.StartNew();
        Exception? failure = null;
        try
        {
            await _next(context);
        }
        catch (Exception ex)
        {
            failure = ex;
            throw;
        }
        finally
        {
            stopwatch.Stop();
            var status = failure != null && !context.Response.HasStarted ? StatusCodes.Status500InternalServerError : context.Response.StatusCode;

            requestLog.Record(new RequestLogEntry
            {
                Timestamp = DateTime.UtcNow,
                Method = context.Request.Method,
                Path = Truncate(path.Value) ?? string.Empty,
                QueryString = Truncate(RedactQuery(context.Request.Query)),
                StatusCode = status,
                DurationMs = stopwatch.ElapsedMilliseconds,
                ClientIp = context.GetClientIpString(),
                UserAgent = Truncate(context.Request.Headers.UserAgent.ToString()),
                ApiKeyId = context.Items[RequestLogItems.ApiKeyId] as string,
                ApiKeyName = context.Items[RequestLogItems.ApiKeyName] as string,
                Username = Truncate(context.Items[RequestLogItems.Username] as string),
                Outcome = context.Items[RequestLogItems.Outcome] as string ?? (failure != null ? "Error" : DefaultOutcome(status)),
                ErrorMessage = Truncate(failure?.Message ?? context.Items[RequestLogItems.Error] as string),
                TraceId = Activity.Current?.Id ?? context.TraceIdentifier,
                LdapStrategy = context.Items[RequestLogItems.LdapStrategy] as string
            });
        }
    }

    private static readonly HashSet<string> SecretParameters = new(StringComparer.OrdinalIgnoreCase)
    {
        "access_token", "id_token", "id_token_hint", "refresh_token", "code", "code_verifier",
        "client_secret", "password", "sso_fresh", "state", "nonce"
    };

    /// <summary>Query string with token-like values replaced, so log readers never see credentials</summary>
    private static string? RedactQuery(IQueryCollection query)
    {
        if (query.Count == 0) return null;
        return "?" + string.Join("&", query.Select(q =>
            $"{Uri.EscapeDataString(q.Key)}={(SecretParameters.Contains(q.Key) ? "[redacted]" : Uri.EscapeDataString(q.Value.ToString()))}"));
    }

    private static string DefaultOutcome(int status) => status switch
    {
        < 400 => "Success",
        404 => "NotFound",
        < 500 => "ClientError",
        _ => "Error"
    };

    private static string? Truncate(string? value) =>
        value == null || value.Length <= MaxFieldLength ? value : value[..MaxFieldLength] + "…";
}

/// <summary>
/// Rejects state-changing admin API requests without the X-Admin-Request header.
/// Browsers cannot add custom headers to cross-site requests without a CORS preflight
/// (which this API never approves), so this blocks CSRF together with the SameSite=Strict cookie.
/// </summary>
public class AdminCsrfMiddleware
{
    public const string HeaderName = "X-Admin-Request";
    private readonly RequestDelegate _next;

    public AdminCsrfMiddleware(RequestDelegate next) => _next = next;

    public async Task InvokeAsync(HttpContext context)
    {
        if (context.Request.Path.StartsWithSegments("/api/admin", StringComparison.OrdinalIgnoreCase) &&
            !HttpMethods.IsGet(context.Request.Method) &&
            !HttpMethods.IsHead(context.Request.Method) &&
            !HttpMethods.IsOptions(context.Request.Method) &&
            context.Request.Headers[HeaderName] != "1")
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            await context.Response.WriteAsJsonAsync(ApiResponse.Fail("Missing anti-forgery header", $"Send header {HeaderName}: 1"));
            return;
        }

        await _next(context);
    }
}

public static class RequestLogMiddlewareExtensions
{
    public static IApplicationBuilder UseRequestLogging(this IApplicationBuilder builder) =>
        builder.UseMiddleware<RequestLogMiddleware>();

    public static IApplicationBuilder UseAdminCsrfProtection(this IApplicationBuilder builder) =>
        builder.UseMiddleware<AdminCsrfMiddleware>();
}
