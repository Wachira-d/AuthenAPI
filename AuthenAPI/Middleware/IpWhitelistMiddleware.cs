using AuthenAPI.Models;
using AuthenAPI.Utilities;
using Microsoft.Extensions.Options;
using System.Net;

namespace AuthenAPI.Middleware;

/// <summary>
/// Rejects requests from IPs outside SecuritySettings:AllowedIpAddresses, plus the optional
/// AdminSettings:AllowedIpAddresses for the admin portal. Loopback is always allowed.
/// Settings changes from the admin portal apply immediately.
/// </summary>
public class IpWhitelistMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<IpWhitelistMiddleware> _logger;
    private readonly IOptionsMonitor<SecuritySettings> _security;
    private readonly IOptionsMonitor<AdminSettings> _admin;
    private volatile IpNetworkMatcher _apiMatcher;
    private volatile IpNetworkMatcher _adminMatcher;

    public IpWhitelistMiddleware(
        RequestDelegate next,
        ILogger<IpWhitelistMiddleware> logger,
        IOptionsMonitor<SecuritySettings> security,
        IOptionsMonitor<AdminSettings> admin)
    {
        _next = next;
        _logger = logger;
        _security = security;
        _admin = admin;
        _apiMatcher = IpNetworkMatcher.Parse(security.CurrentValue.AllowedIpAddresses);
        _adminMatcher = IpNetworkMatcher.Parse(admin.CurrentValue.AllowedIpAddresses);
        security.OnChange(s => _apiMatcher = IpNetworkMatcher.Parse(s.AllowedIpAddresses));
        admin.OnChange(a => _adminMatcher = IpNetworkMatcher.Parse(a.AllowedIpAddresses));
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var settings = _security.CurrentValue;
        var path = context.Request.Path.Value ?? string.Empty;
        var remoteIp = context.GetClientIp();
        var isLoopback = remoteIp != null && IPAddress.IsLoopback(remoteIp);

        if (context.IsAdminPath() && !isLoopback && _adminMatcher.Count > 0 && !_adminMatcher.Contains(remoteIp))
        {
            await Reject(context, remoteIp, "Admin portal is not available from this IP address");
            return;
        }

        var excluded = settings.ExcludedPaths.Any(p => path.StartsWith(p, StringComparison.OrdinalIgnoreCase));
        if (!settings.EnableIpWhitelist || excluded || isLoopback)
        {
            await _next(context);
            return;
        }

        if (remoteIp == null || !_apiMatcher.Contains(remoteIp))
        {
            await Reject(context, remoteIp, "Access denied: IP address not allowed");
            return;
        }

        await _next(context);
    }

    private async Task Reject(HttpContext context, IPAddress? remoteIp, string message)
    {
        _logger.LogWarning("Request to {Path} rejected from unauthorized IP: {RemoteIp}", context.Request.Path, remoteIp);
        context.SetRequestOutcome("IpBlocked", message);
        context.Response.StatusCode = StatusCodes.Status403Forbidden;
        await context.Response.WriteAsJsonAsync(ApiResponse.Fail(message));
    }
}

/// <summary>
/// Extension method to register IP whitelist middleware
/// </summary>
public static class IpWhitelistMiddlewareExtensions
{
    public static IApplicationBuilder UseIpWhitelist(this IApplicationBuilder builder)
    {
        return builder.UseMiddleware<IpWhitelistMiddleware>();
    }
}
