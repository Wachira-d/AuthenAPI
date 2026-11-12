using AuthenAPI.Models;
using AuthenAPI.Services;
using AuthenAPI.Utilities;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AuthenAPI.Controllers.Admin;

/// <summary>
/// Base for admin portal controllers: cookie-authenticated, hidden from Swagger, read access for Admin + Viewer.
/// Write endpoints add [Authorize(Policy = AdminRoles.WritePolicy)].
/// </summary>
[ApiController]
[Route("api/admin")]
[Produces("application/json")]
[ApiExplorerSettings(IgnoreApi = true)]
[Authorize(Policy = AdminRoles.ReadPolicy)]
public abstract class AdminControllerBase : ControllerBase
{
    protected string CurrentUser => User.Identity?.Name ?? "unknown";

    protected string ClientIp => HttpContext.GetClientIpString();

    protected Task AuditAsync(AuditAction action, bool success, string details, string? username = null)
    {
        var audit = HttpContext.RequestServices.GetRequiredService<IAuditService>();
        return audit.LogAsync(new AuditLog
        {
            Action = action,
            Username = username ?? CurrentUser,
            Success = success,
            IpAddress = ClientIp,
            UserAgent = Request.Headers.UserAgent.ToString(),
            RequestPath = Request.Path,
            HttpMethod = Request.Method,
            Details = details
        });
    }

    protected IActionResult Invalid(IEnumerable<string> errors) =>
        BadRequest(ApiResponse.Fail("Validation failed", string.Join("; ", errors)));
}
