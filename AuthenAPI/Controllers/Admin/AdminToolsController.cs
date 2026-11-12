using AuthenAPI.Models;
using AuthenAPI.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AuthenAPI.Controllers.Admin;

/// <summary>
/// LDAP diagnostics and maintenance tools
/// </summary>
public class AdminToolsController : AdminControllerBase
{
    private readonly ILdapService _ldap;
    private readonly LdapStrategyCache _strategyCache;

    public AdminToolsController(ILdapService ldap, LdapStrategyCache strategyCache)
    {
        _ldap = ldap;
        _strategyCache = strategyCache;
    }

    [HttpPost("tools/ldap-diagnostics")]
    [Authorize(Policy = AdminRoles.WritePolicy)]
    public async Task<IActionResult> Diagnostics()
    {
        var result = await _ldap.TestConnectionDetailedAsync();
        await AuditAsync(AuditAction.AdminTool, result.Success, $"LDAP diagnostics: {result.Summary}");
        return Ok(ApiResponse<ConnectionTestResult>.Ok(result, result.Summary));
    }

    [HttpPost("tools/test-auth")]
    [Authorize(Policy = AdminRoles.WritePolicy)]
    public async Task<IActionResult> TestAuth([FromBody] AdminLoginRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Username) || string.IsNullOrEmpty(request.Password))
        {
            return BadRequest(ApiResponse.Fail("Username and password are required"));
        }

        var result = await _ldap.AuthenticateWithResultAsync(request.Username, request.Password);
        await AuditAsync(AuditAction.AdminTool, result.Success,
            $"Test login for '{request.Username}': {(result.Success ? "OK" : result.FailureReason.ToString())} via {result.Method}/{result.Strategy}");

        return Ok(ApiResponse<TestAuthResponse>.Ok(new TestAuthResponse
        {
            Success = result.Success,
            FailureReason = result.FailureReason,
            Method = result.Method,
            Strategy = result.Strategy,
            DurationMs = result.DurationMs,
            Message = result.Message,
            User = result.User
        }));
    }

    [HttpGet("tools/lookup-user")]
    public async Task<IActionResult> LookupUser([FromQuery] string username)
    {
        if (string.IsNullOrWhiteSpace(username)) return BadRequest(ApiResponse.Fail("username is required"));

        var user = await _ldap.GetUserAsync(username.Trim());
        return user == null
            ? NotFound(ApiResponse.Fail($"User '{username}' not found"))
            : Ok(ApiResponse<UserInfo>.Ok(user));
    }

    [HttpPost("tools/clear-cache")]
    [Authorize(Policy = AdminRoles.WritePolicy)]
    public async Task<IActionResult> ClearCache()
    {
        _ldap.ClearCache();
        await AuditAsync(AuditAction.AdminTool, true, "Cleared user/group cache");
        return Ok(ApiResponse<object>.Ok(new { cleared = true }, "Cache cleared"));
    }

    [HttpPost("tools/reset-ldap-strategy")]
    [Authorize(Policy = AdminRoles.WritePolicy)]
    public async Task<IActionResult> ResetStrategy()
    {
        var previous = _strategyCache.PreferredStrategy;
        _strategyCache.Reset();
        await AuditAsync(AuditAction.AdminTool, true, $"Reset preferred LDAP strategy (was {previous ?? "none"})");
        return Ok(ApiResponse.Ok("Preferred LDAP strategy reset. The most secure working strategy will be chosen on the next call."));
    }

    [HttpGet("ldap/strategies")]
    public IActionResult Strategies() => Ok(ApiResponse<List<LdapStrategyStats>>.Ok(_strategyCache.GetStats()));
}
