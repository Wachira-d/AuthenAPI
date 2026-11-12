using AuthenAPI.Models;
using AuthenAPI.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace AuthenAPI.Controllers.Admin;

[Route("api/admin/auth")]
public class AdminAuthController : AdminControllerBase
{
    private readonly AdminAuthService _auth;
    private readonly IOptionsMonitor<AdminSettings> _settings;

    public AdminAuthController(AdminAuthService auth, IOptionsMonitor<AdminSettings> settings)
    {
        _auth = auth;
        _settings = settings;
    }

    [HttpPost("login")]
    [AllowAnonymous]
    public async Task<IActionResult> Login([FromBody] AdminLoginRequest request)
    {
        if (!_settings.CurrentValue.Enabled)
        {
            return NotFound(ApiResponse.Fail("Admin portal is disabled"));
        }

        if (string.IsNullOrWhiteSpace(request.Username) || string.IsNullOrEmpty(request.Password) ||
            request.Username.Length > 256 || request.Password.Length > 256)
        {
            return BadRequest(ApiResponse.Fail("Username and password are required"));
        }

        var result = await _auth.LoginAsync(request.Username, request.Password, ClientIp);

        switch (result.Status)
        {
            case AdminLoginStatus.Success:
                await HttpContext.SignInAsync(AdminRoles.Scheme, result.Principal!, new AuthenticationProperties
                {
                    IsPersistent = false,
                    ExpiresUtc = result.Session!.ExpiresAt,
                    AllowRefresh = true
                });
                await AuditAsync(AuditAction.AdminLogin, true,
                    $"Signed in as {result.Session.Role} via {result.Session.AuthMethod}", result.Session.Username);
                return Ok(ApiResponse<AdminSession>.Ok(result.Session, "Signed in"));

            case AdminLoginStatus.LockedOut:
                await AuditAsync(AuditAction.AdminLogin, false, $"Locked out ({result.RetryAfterSeconds}s left)", request.Username);
                Response.Headers["Retry-After"] = result.RetryAfterSeconds.ToString();
                return StatusCode(StatusCodes.Status423Locked, new ApiResponse<object>
                {
                    Success = false,
                    Message = "Too many failed attempts. Try again later.",
                    Data = new { retryAfterSeconds = result.RetryAfterSeconds }
                });

            case AdminLoginStatus.NotAuthorized:
                await AuditAsync(AuditAction.AdminLogin, false, "Valid AD credentials but no admin/viewer access", request.Username);
                return StatusCode(StatusCodes.Status403Forbidden,
                    ApiResponse.Fail("Your account is not allowed to use the admin portal. Ask an administrator to add you."));

            case AdminLoginStatus.DirectoryUnavailable:
                await AuditAsync(AuditAction.AdminLogin, false, $"Directory unavailable: {result.Detail}", request.Username);
                return StatusCode(StatusCodes.Status503ServiceUnavailable,
                    ApiResponse.Fail("Active Directory is unreachable. Use a local break-glass account."));

            default:
                await AuditAsync(AuditAction.AdminLogin, false, $"Invalid credentials ({result.Detail})", request.Username);
                return Unauthorized(ApiResponse.Fail("Invalid username or password"));
        }
    }

    [HttpPost("logout")]
    [AllowAnonymous]
    public async Task<IActionResult> Logout()
    {
        if (User.Identity?.IsAuthenticated == true)
        {
            await AuditAsync(AuditAction.AdminLogout, true, "Signed out");
        }
        await HttpContext.SignOutAsync(AdminRoles.Scheme);
        return Ok(ApiResponse.Ok("Signed out"));
    }

    [HttpGet("me")]
    public async Task<IActionResult> Me()
    {
        var auth = await HttpContext.AuthenticateAsync(AdminRoles.Scheme);
        return Ok(ApiResponse<AdminSession>.Ok(AdminAuthService.SessionFrom(User, auth.Properties?.ExpiresUtc)));
    }
}
