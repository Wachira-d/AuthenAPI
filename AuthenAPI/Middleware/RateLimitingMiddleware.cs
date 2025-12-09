using AuthenAPI.Models;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using System.Collections.Concurrent;

namespace AuthenAPI.Middleware;

/// <summary>
/// Middleware to limit request rates per client
/// </summary>
public class RateLimitingMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<RateLimitingMiddleware> _logger;
    private readonly SecuritySettings _settings;
    private readonly ConcurrentDictionary<string, RateLimitEntry> _clients = new();

    public RateLimitingMiddleware(
        RequestDelegate next,
        ILogger<RateLimitingMiddleware> logger,
        IOptions<SecuritySettings> settings)
    {
        _next = next;
        _logger = logger;
        _settings = settings.Value;

        // Start cleanup task
        _ = CleanupExpiredEntriesAsync();
    }

    public async Task InvokeAsync(HttpContext context)
    {
        if (!_settings.EnableRateLimiting)
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

        var clientId = GetClientIdentifier(context);
        var now = DateTime.UtcNow;
        var windowStart = now.AddSeconds(-_settings.RateLimitWindowSeconds);

        var entry = _clients.GetOrAdd(clientId, _ => new RateLimitEntry());

        lock (entry)
        {
            // Remove old requests outside the window
            entry.Requests.RemoveAll(r => r < windowStart);

            if (entry.Requests.Count >= _settings.RateLimitMaxRequests)
            {
                _logger.LogWarning("Rate limit exceeded for client: {ClientId}", clientId);

                context.Response.StatusCode = StatusCodes.Status429TooManyRequests;
                context.Response.Headers.Append("Retry-After", _settings.RateLimitWindowSeconds.ToString());
                context.Response.Headers.Append("X-RateLimit-Limit", _settings.RateLimitMaxRequests.ToString());
                context.Response.Headers.Append("X-RateLimit-Remaining", "0");
                context.Response.Headers.Append("X-RateLimit-Reset", ((DateTimeOffset)windowStart.AddSeconds(_settings.RateLimitWindowSeconds)).ToUnixTimeSeconds().ToString());

                context.Response.WriteAsJsonAsync(new
                {
                    error = "Too many requests",
                    message = $"Rate limit of {_settings.RateLimitMaxRequests} requests per {_settings.RateLimitWindowSeconds} seconds exceeded",
                    retryAfter = _settings.RateLimitWindowSeconds
                }).Wait();

                return;
            }

            entry.Requests.Add(now);

            // Add rate limit headers
            context.Response.OnStarting(() =>
            {
                context.Response.Headers.Append("X-RateLimit-Limit", _settings.RateLimitMaxRequests.ToString());
                context.Response.Headers.Append("X-RateLimit-Remaining", (_settings.RateLimitMaxRequests - entry.Requests.Count).ToString());
                return Task.CompletedTask;
            });
        }

        await _next(context);
    }

    private string GetClientIdentifier(HttpContext context)
    {
        // Use API key if available, otherwise use IP
        if (context.Items.TryGetValue("ApiKeyDescription", out var apiKey) && apiKey != null)
        {
            return $"key:{apiKey}";
        }

        var ip = context.Connection.RemoteIpAddress;
        if (ip != null && ip.IsIPv4MappedToIPv6)
        {
            ip = ip.MapToIPv4();
        }

        return $"ip:{ip}";
    }

    private async Task CleanupExpiredEntriesAsync()
    {
        while (true)
        {
            await Task.Delay(TimeSpan.FromMinutes(5));

            var cutoff = DateTime.UtcNow.AddSeconds(-_settings.RateLimitWindowSeconds * 2);
            var keysToRemove = new List<string>();

            foreach (var kvp in _clients)
            {
                lock (kvp.Value)
                {
                    if (kvp.Value.Requests.All(r => r < cutoff))
                    {
                        keysToRemove.Add(kvp.Key);
                    }
                }
            }

            foreach (var key in keysToRemove)
            {
                _clients.TryRemove(key, out _);
            }
        }
    }

    private class RateLimitEntry
    {
        public List<DateTime> Requests { get; } = new();
    }
}

/// <summary>
/// Extension method to register rate limiting middleware
/// </summary>
public static class RateLimitingMiddlewareExtensions
{
    public static IApplicationBuilder UseRateLimiting(this IApplicationBuilder builder)
    {
        return builder.UseMiddleware<RateLimitingMiddleware>();
    }
}
