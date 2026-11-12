using AuthenAPI.Models;
using AuthenAPI.Services;
using AuthenAPI.Utilities;
using Microsoft.Extensions.Options;

namespace AuthenAPI.Middleware;

/// <summary>
/// Requires a valid API key for the public API and enforces per-key scopes, IP restrictions,
/// expiry and rate limits. The admin portal (/admin, /api/admin) uses cookie authentication instead.
/// </summary>
public class ApiKeyAuthMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<ApiKeyAuthMiddleware> _logger;
    private readonly IOptionsMonitor<SecuritySettings> _settings;

    public ApiKeyAuthMiddleware(
        RequestDelegate next,
        ILogger<ApiKeyAuthMiddleware> logger,
        IOptionsMonitor<SecuritySettings> settings)
    {
        _next = next;
        _logger = logger;
        _settings = settings;
    }

    public async Task InvokeAsync(HttpContext context, ApiKeyService apiKeys, IAuditService auditService)
    {
        var settings = _settings.CurrentValue;
        var path = context.Request.Path.Value ?? string.Empty;

        if (!settings.EnableApiKeyAuth ||
            context.IsAdminPath() ||
            settings.ExcludedPaths.Any(p => path.StartsWith(p, StringComparison.OrdinalIgnoreCase)))
        {
            await _next(context);
            return;
        }

        context.Request.Headers.TryGetValue(settings.ApiKeyHeaderName, out var header);
        var scope = ApiKeyScopes.Resolve(context.Request.Method, path);
        var result = apiKeys.Validate(header.ToString(), context.GetClientIp(), scope);

        if (result.Success)
        {
            context.Items[RequestLogItems.ApiKeyId] = result.KeyId;
            context.Items[RequestLogItems.ApiKeyName] = result.KeyName;
            context.Items["ApiKeyDescription"] = result.KeyName; // kept for older code paths
            await _next(context);
            return;
        }

        var (status, message) = result.Failure switch
        {
            ApiKeyFailure.Missing => (StatusCodes.Status401Unauthorized, $"API key is required in the '{settings.ApiKeyHeaderName}' header"),
            ApiKeyFailure.Expired => (StatusCodes.Status401Unauthorized, "API key has expired"),
            ApiKeyFailure.Disabled or ApiKeyFailure.Revoked => (StatusCodes.Status401Unauthorized, "API key is not active"),
            ApiKeyFailure.IpDenied => (StatusCodes.Status403Forbidden, "API key is not allowed from this IP address"),
            ApiKeyFailure.ScopeDenied => (StatusCodes.Status403Forbidden, $"API key does not have the '{scope}' scope"),
            ApiKeyFailure.RateLimited => (StatusCodes.Status429TooManyRequests, "API key rate limit exceeded"),
            _ => (StatusCodes.Status401Unauthorized, "Invalid API key")
        };

        context.Items[RequestLogItems.ApiKeyId] = result.KeyId;
        context.Items[RequestLogItems.ApiKeyName] = result.KeyName;
        context.SetRequestOutcome($"ApiKey:{result.Failure}", message);

        _logger.LogWarning("API request rejected ({Failure}) for {Path} from {RemoteIp}, key: {Key}",
            result.Failure, path, context.GetClientIpString(), result.KeyName ?? "-");

        // Missing/invalid keys are recorded in the request log; only notable key misuse goes to the audit trail.
        if (result.Failure is not (ApiKeyFailure.Missing or ApiKeyFailure.Invalid or ApiKeyFailure.RateLimited))
        {
            await auditService.LogAsync(new AuditLog
            {
                Action = AuditAction.ApiKeyAuth,
                Username = result.KeyName ?? "Anonymous",
                Success = false,
                IpAddress = context.GetClientIpString(),
                UserAgent = context.Request.Headers.UserAgent.ToString(),
                RequestPath = path,
                HttpMethod = context.Request.Method,
                StatusCode = status,
                Details = $"{result.Failure}: {message}"
            });
        }

        if (result.RetryAfterSeconds.HasValue)
        {
            context.Response.Headers["Retry-After"] = result.RetryAfterSeconds.Value.ToString();
        }

        context.Response.StatusCode = status;
        await context.Response.WriteAsJsonAsync(new { error = message, reason = result.Failure.ToString() });
    }
}

/// <summary>
/// Extension method to register API key auth middleware
/// </summary>
public static class ApiKeyAuthMiddlewareExtensions
{
    public static IApplicationBuilder UseApiKeyAuth(this IApplicationBuilder builder)
    {
        return builder.UseMiddleware<ApiKeyAuthMiddleware>();
    }
}
