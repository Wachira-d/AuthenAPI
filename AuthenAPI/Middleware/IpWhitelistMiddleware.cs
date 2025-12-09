using AuthenAPI.Models;
using Microsoft.Extensions.Options;
using System.Net;

namespace AuthenAPI.Middleware;

/// <summary>
/// Middleware to filter requests based on IP whitelist
/// </summary>
public class IpWhitelistMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<IpWhitelistMiddleware> _logger;
    private readonly SecuritySettings _settings;
    private readonly List<(IPAddress Network, int PrefixLength)> _allowedNetworks;

    public IpWhitelistMiddleware(
        RequestDelegate next,
        ILogger<IpWhitelistMiddleware> logger,
        IOptions<SecuritySettings> settings)
    {
        _next = next;
        _logger = logger;
        _settings = settings.Value;
        _allowedNetworks = ParseAllowedNetworks(_settings.AllowedIpAddresses);
    }

    public async Task InvokeAsync(HttpContext context)
    {
        if (!_settings.EnableIpWhitelist)
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

        var remoteIp = context.Connection.RemoteIpAddress;

        if (remoteIp == null)
        {
            _logger.LogWarning("Request rejected: Unable to determine remote IP address");
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            await context.Response.WriteAsJsonAsync(new { error = "Unable to determine client IP" });
            return;
        }

        // Handle IPv6-mapped IPv4 addresses
        if (remoteIp.IsIPv4MappedToIPv6)
        {
            remoteIp = remoteIp.MapToIPv4();
        }

        if (!IsIpAllowed(remoteIp))
        {
            _logger.LogWarning("Request rejected from unauthorized IP: {RemoteIp}", remoteIp);
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            await context.Response.WriteAsJsonAsync(new { error = "Access denied: IP address not allowed" });
            return;
        }

        await _next(context);
    }

    private bool IsIpAllowed(IPAddress remoteIp)
    {
        // Always allow localhost
        if (IPAddress.IsLoopback(remoteIp))
        {
            return true;
        }

        foreach (var (network, prefixLength) in _allowedNetworks)
        {
            if (IsInNetwork(remoteIp, network, prefixLength))
            {
                return true;
            }
        }

        return false;
    }

    private static bool IsInNetwork(IPAddress address, IPAddress network, int prefixLength)
    {
        if (address.AddressFamily != network.AddressFamily)
        {
            return false;
        }

        var addressBytes = address.GetAddressBytes();
        var networkBytes = network.GetAddressBytes();

        var fullBytes = prefixLength / 8;
        var remainingBits = prefixLength % 8;

        for (int i = 0; i < fullBytes; i++)
        {
            if (addressBytes[i] != networkBytes[i])
            {
                return false;
            }
        }

        if (remainingBits > 0 && fullBytes < addressBytes.Length)
        {
            var mask = (byte)(0xFF << (8 - remainingBits));
            if ((addressBytes[fullBytes] & mask) != (networkBytes[fullBytes] & mask))
            {
                return false;
            }
        }

        return true;
    }

    private static List<(IPAddress Network, int PrefixLength)> ParseAllowedNetworks(List<string> addresses)
    {
        var result = new List<(IPAddress, int)>();

        foreach (var addr in addresses)
        {
            try
            {
                if (addr.Contains('/'))
                {
                    var parts = addr.Split('/');
                    var ip = IPAddress.Parse(parts[0]);
                    var prefix = int.Parse(parts[1]);
                    result.Add((ip, prefix));
                }
                else
                {
                    var ip = IPAddress.Parse(addr);
                    var prefix = ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? 32 : 128;
                    result.Add((ip, prefix));
                }
            }
            catch (Exception)
            {
                // Skip invalid entries
            }
        }

        return result;
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
