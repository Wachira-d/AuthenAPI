using AuthenAPI.Models;
using AuthenAPI.Services;
using Microsoft.Extensions.Options;

namespace AuthenAPI.Middleware;

/// <summary>
/// Middleware to authenticate requests using API keys
/// </summary>
public class ApiKeyAuthMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<ApiKeyAuthMiddleware> _logger;
    private readonly SecuritySettings _settings;

    public ApiKeyAuthMiddleware(
        RequestDelegate next,
        ILogger<ApiKeyAuthMiddleware> logger,
        IOptions<SecuritySettings> settings)
    {
        _next = next;
        _logger = logger;
        _settings = settings.Value;
    }

    public async Task InvokeAsync(HttpContext context, IAuditService auditService)
    {
        if (!_settings.EnableApiKeyAuth)
        {
            await _next(context);
            return;
        }

        // Check if path is excluded
        var path = context.Request.Path.Value?.ToLowerInvariant() ?? "";
        if (_settings.ExcludedPaths.Any(p => path.StartsWith(p.ToLowerInvariant())))
        {
            await _next(context);
            return;
        }

        // Get API key from header
        if (!context.Request.Headers.TryGetValue(_settings.ApiKeyHeaderName, out var apiKeyHeader))
        {
            _logger.LogWarning("API request rejected: Missing API key header from {RemoteIp}",
                context.Connection.RemoteIpAddress);

            await auditService.LogAsync(new AuditLog
            {
                Action = "ApiKeyAuth",
                Username = "Anonymous",
                Success = false,
                IpAddress = context.Connection.RemoteIpAddress?.ToString() ?? "Unknown",
                Details = "Missing API key header",
                RequestPath = context.Request.Path
            });

            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            await context.Response.WriteAsJsonAsync(new
            {
                error = "API key is required",
                message = $"Please provide API key in the '{_settings.ApiKeyHeaderName}' header"
            });
            return;
        }

        var apiKey = apiKeyHeader.ToString();

        // Validate API key
        var keyConfig = _settings.ApiKeys.FirstOrDefault(k =>
            k.Key == apiKey && k.IsActive);

        if (keyConfig == null)
        {
            _logger.LogWarning("API request rejected: Invalid API key from {RemoteIp}",
                context.Connection.RemoteIpAddress);

            await auditService.LogAsync(new AuditLog
            {
                Action = "ApiKeyAuth",
                Username = "Anonymous",
                Success = false,
                IpAddress = context.Connection.RemoteIpAddress?.ToString() ?? "Unknown",
                Details = "Invalid API key",
                RequestPath = context.Request.Path
            });

            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            await context.Response.WriteAsJsonAsync(new { error = "Invalid API key" });
            return;
        }

        // Check expiration
        if (keyConfig.ExpiresAt.HasValue && keyConfig.ExpiresAt.Value < DateTime.UtcNow)
        {
            _logger.LogWarning("API request rejected: Expired API key '{Description}' from {RemoteIp}",
                keyConfig.Description, context.Connection.RemoteIpAddress);

            await auditService.LogAsync(new AuditLog
            {
                Action = "ApiKeyAuth",
                Username = keyConfig.Description,
                Success = false,
                IpAddress = context.Connection.RemoteIpAddress?.ToString() ?? "Unknown",
                Details = "API key expired",
                RequestPath = context.Request.Path
            });

            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            await context.Response.WriteAsJsonAsync(new { error = "API key has expired" });
            return;
        }

        // Add key info to context for logging
        context.Items["ApiKeyDescription"] = keyConfig.Description;

        _logger.LogDebug("API request authenticated with key: {Description}", keyConfig.Description);

        await _next(context);
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
