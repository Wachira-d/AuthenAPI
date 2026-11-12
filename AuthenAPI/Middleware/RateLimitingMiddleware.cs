using AuthenAPI.Models;
using AuthenAPI.Utilities;
using Microsoft.Extensions.Options;
using System.Collections.Concurrent;

namespace AuthenAPI.Middleware;

/// <summary>
/// Sliding-window rate limit per client IP for the public API.
/// The admin portal is excluded (admin logins have their own lockout); per-API-key limits are
/// enforced by the API key middleware.
/// </summary>
public class RateLimitingMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<RateLimitingMiddleware> _logger;
    private readonly IOptionsMonitor<SecuritySettings> _settings;
    private readonly ConcurrentDictionary<string, RateLimitEntry> _clients = new();
    private long _lastCleanupTicks = DateTime.UtcNow.Ticks;

    public RateLimitingMiddleware(
        RequestDelegate next,
        ILogger<RateLimitingMiddleware> logger,
        IOptionsMonitor<SecuritySettings> settings)
    {
        _next = next;
        _logger = logger;
        _settings = settings;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var settings = _settings.CurrentValue;
        var path = context.Request.Path.Value ?? string.Empty;

        if (!settings.EnableRateLimiting ||
            context.IsAdminPath() ||
            settings.ExcludedPaths.Any(p => path.StartsWith(p, StringComparison.OrdinalIgnoreCase)))
        {
            await _next(context);
            return;
        }

        var clientId = context.GetClientIpString();
        var window = TimeSpan.FromSeconds(Math.Max(1, settings.RateLimitWindowSeconds));
        var limit = Math.Max(1, settings.RateLimitMaxRequests);
        var now = DateTime.UtcNow;

        var entry = _clients.GetOrAdd(clientId, _ => new RateLimitEntry());
        bool allowed;
        int remaining;
        lock (entry)
        {
            entry.Requests.RemoveAll(r => r < now - window);
            allowed = entry.Requests.Count < limit;
            if (allowed) entry.Requests.Add(now);
            remaining = Math.Max(0, limit - entry.Requests.Count);
        }

        CleanupIfDue(now, window);

        if (!allowed)
        {
            _logger.LogWarning("Rate limit exceeded for client: {ClientId}", clientId);
            context.SetRequestOutcome("RateLimited", $"More than {limit} requests in {window.TotalSeconds:0}s");
            context.Response.StatusCode = StatusCodes.Status429TooManyRequests;
            context.Response.Headers["Retry-After"] = ((int)window.TotalSeconds).ToString();
            context.Response.Headers["X-RateLimit-Limit"] = limit.ToString();
            context.Response.Headers["X-RateLimit-Remaining"] = "0";
            await context.Response.WriteAsJsonAsync(new
            {
                error = "Too many requests",
                message = $"Rate limit of {limit} requests per {window.TotalSeconds:0} seconds exceeded",
                retryAfter = (int)window.TotalSeconds
            });
            return;
        }

        context.Response.OnStarting(() =>
        {
            context.Response.Headers["X-RateLimit-Limit"] = limit.ToString();
            context.Response.Headers["X-RateLimit-Remaining"] = remaining.ToString();
            return Task.CompletedTask;
        });

        await _next(context);
    }

    private void CleanupIfDue(DateTime now, TimeSpan window)
    {
        var last = Interlocked.Read(ref _lastCleanupTicks);
        if (now.Ticks - last < TimeSpan.TicksPerMinute * 5) return;
        if (Interlocked.CompareExchange(ref _lastCleanupTicks, now.Ticks, last) != last) return;

        foreach (var (key, entry) in _clients)
        {
            lock (entry)
            {
                if (entry.Requests.All(r => r < now - window)) _clients.TryRemove(key, out _);
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
