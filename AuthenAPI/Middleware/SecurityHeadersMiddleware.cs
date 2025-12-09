namespace AuthenAPI.Middleware;

/// <summary>
/// Middleware to add security headers to all responses
/// </summary>
public class SecurityHeadersMiddleware
{
    private readonly RequestDelegate _next;

    public SecurityHeadersMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        // Add security headers before processing
        context.Response.OnStarting(() =>
        {
            var headers = context.Response.Headers;

            // Prevent clickjacking
            if (!headers.ContainsKey("X-Frame-Options"))
            {
                headers.Append("X-Frame-Options", "DENY");
            }

            // Prevent MIME type sniffing
            if (!headers.ContainsKey("X-Content-Type-Options"))
            {
                headers.Append("X-Content-Type-Options", "nosniff");
            }

            // Enable XSS filter
            if (!headers.ContainsKey("X-XSS-Protection"))
            {
                headers.Append("X-XSS-Protection", "1; mode=block");
            }

            // Referrer policy
            if (!headers.ContainsKey("Referrer-Policy"))
            {
                headers.Append("Referrer-Policy", "strict-origin-when-cross-origin");
            }

            // Content Security Policy for API
            if (!headers.ContainsKey("Content-Security-Policy"))
            {
                headers.Append("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'");
            }

            // Permissions Policy (formerly Feature-Policy)
            if (!headers.ContainsKey("Permissions-Policy"))
            {
                headers.Append("Permissions-Policy", "geolocation=(), microphone=(), camera=()");
            }

            // Cache control for API responses (prevent caching sensitive data)
            if (!headers.ContainsKey("Cache-Control"))
            {
                headers.Append("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
                headers.Append("Pragma", "no-cache");
                headers.Append("Expires", "0");
            }

            // Remove server header
            headers.Remove("Server");
            headers.Remove("X-Powered-By");

            return Task.CompletedTask;
        });

        await _next(context);
    }
}

/// <summary>
/// Extension method to register security headers middleware
/// </summary>
public static class SecurityHeadersMiddlewareExtensions
{
    public static IApplicationBuilder UseSecurityHeaders(this IApplicationBuilder builder)
    {
        return builder.UseMiddleware<SecurityHeadersMiddleware>();
    }
}
