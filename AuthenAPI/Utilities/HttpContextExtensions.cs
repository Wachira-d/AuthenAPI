using System.Net;

namespace AuthenAPI.Utilities;

public static class HttpContextExtensions
{
    /// <summary>
    /// Client IP as seen by ASP.NET Core. Behind IIS (ANCM) the forwarded-headers
    /// integration has already replaced the proxy address with the real client address,
    /// so raw X-Forwarded-For headers (which a client can forge) are not consulted.
    /// </summary>
    public static IPAddress? GetClientIp(this HttpContext context)
    {
        var ip = context.Connection.RemoteIpAddress;
        if (ip != null && ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        return ip;
    }

    public static string GetClientIpString(this HttpContext context) =>
        context.GetClientIp()?.ToString() ?? "unknown";

    public static bool IsAdminPath(this HttpContext context) => IsAdminPath(context.Request.Path);

    /// <summary>
    /// True for the admin UI (/admin...) and the admin API (/api/admin...)
    /// </summary>
    public static bool IsAdminPath(PathString path) =>
        path.StartsWithSegments("/admin", StringComparison.OrdinalIgnoreCase) ||
        path.StartsWithSegments("/api/admin", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Browser-facing single sign-on paths. They are protected by the OIDC protocol (client secret,
    /// registered redirect URIs) and the login lockout, not by API keys or the API IP whitelist.
    /// </summary>
    public static bool IsSsoPath(this HttpContext context) => IsSsoPath(context.Request.Path);

    public static bool IsSsoPath(PathString path) =>
        path.StartsWithSegments("/connect", StringComparison.OrdinalIgnoreCase) ||
        path.StartsWithSegments("/sso", StringComparison.OrdinalIgnoreCase) ||
        path.StartsWithSegments("/.well-known", StringComparison.OrdinalIgnoreCase);

    public static void SetRequestOutcome(this HttpContext context, string outcome, string? error = null)
    {
        context.Items[Models.RequestLogItems.Outcome] = outcome;
        if (error != null) context.Items[Models.RequestLogItems.Error] = error;
    }
}
