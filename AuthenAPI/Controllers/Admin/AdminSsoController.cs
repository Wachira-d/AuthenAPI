using AuthenAPI.Models;
using AuthenAPI.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace AuthenAPI.Controllers.Admin;

[Route("api/admin/sso")]
public class AdminSsoController : AdminControllerBase
{
    private readonly SsoClientService _clients;
    private readonly SsoSessionTracker _sessions;
    private readonly IOptionsMonitor<SsoSettings> _settings;

    public AdminSsoController(SsoClientService clients, SsoSessionTracker sessions, IOptionsMonitor<SsoSettings> settings)
    {
        _clients = clients;
        _sessions = sessions;
        _settings = settings;
    }

    [HttpGet("info")]
    public IActionResult Info()
    {
        var s = _settings.CurrentValue;
        var issuer = !string.IsNullOrWhiteSpace(s.Issuer)
            ? s.Issuer.TrimEnd('/') + "/"
            : $"{Request.Scheme}://{Request.Host}{Request.PathBase}/";

        return Ok(ApiResponse<SsoInfo>.Ok(new SsoInfo
        {
            Enabled = s.Enabled,
            Issuer = issuer,
            DiscoveryUrl = issuer + ".well-known/openid-configuration",
            AuthorizeUrl = issuer + "connect/authorize",
            TokenUrl = issuer + "connect/token",
            UserinfoUrl = issuer + "connect/userinfo",
            LogoutUrl = issuer + "connect/logout",
            LoginPageUrl = issuer + "sso/login",
            SessionHours = s.SessionHours,
            Scopes = SsoSetup.SupportedScopes.ToList(),
            Claims = SsoSetup.SupportedClaims.ToList(),
            ActiveSessions = _sessions.ActiveCount
        }));
    }

    [HttpGet("clients")]
    public IActionResult List() => Ok(ApiResponse<List<SsoClientView>>.Ok(_clients.List()));

    [HttpPost("clients")]
    [Authorize(Policy = AdminRoles.WritePolicy)]
    public async Task<IActionResult> Create([FromBody] SsoClientInput input)
    {
        var errors = _clients.Validate(input, creating: true);
        if (errors.Count > 0) return Invalid(errors);

        var created = _clients.Create(input, CurrentUser);
        await AuditAsync(AuditAction.SsoClientCreated, true,
            $"Created SSO application '{created.Client.ClientId}' ({created.Client.Type}) redirects=[{string.Join(", ", created.Client.RedirectUris)}] groups=[{string.Join(", ", created.Client.AllowedGroups)}]");
        return Ok(ApiResponse<SsoClientSecretResponse>.Ok(created,
            created.ClientSecret != null ? "Application created. Copy the client secret now: it will not be shown again." : "Application created."));
    }

    [HttpPut("clients/{clientId}")]
    [Authorize(Policy = AdminRoles.WritePolicy)]
    public async Task<IActionResult> Update(string clientId, [FromBody] SsoClientInput input)
    {
        var errors = _clients.Validate(input, creating: false);
        if (errors.Count > 0) return Invalid(errors);

        var updated = _clients.Update(clientId, input, CurrentUser);
        if (updated == null) return NotFound(ApiResponse.Fail("Application not found"));

        await AuditAsync(AuditAction.SsoClientUpdated, true,
            $"Updated SSO application '{clientId}': active={updated.IsActive} redirects=[{string.Join(", ", updated.RedirectUris)}] groups=[{string.Join(", ", updated.AllowedGroups)}] pkce={updated.RequirePkce}");
        return Ok(ApiResponse<SsoClientView>.Ok(updated, "Application updated"));
    }

    [HttpPost("clients/{clientId}/rotate-secret")]
    [Authorize(Policy = AdminRoles.WritePolicy)]
    public async Task<IActionResult> RotateSecret(string clientId)
    {
        var rotated = _clients.RotateSecret(clientId, CurrentUser);
        if (rotated == null) return NotFound(ApiResponse.Fail("Application not found, or it is a public application without a secret"));

        await AuditAsync(AuditAction.SsoClientSecretRotated, true, $"Rotated the client secret of '{clientId}'");
        return Ok(ApiResponse<SsoClientSecretResponse>.Ok(rotated, "Secret rotated. The old secret no longer works."));
    }

    [HttpDelete("clients/{clientId}")]
    [Authorize(Policy = AdminRoles.WritePolicy)]
    public async Task<IActionResult> Delete(string clientId)
    {
        if (!_clients.Delete(clientId)) return NotFound(ApiResponse.Fail("Application not found"));

        await AuditAsync(AuditAction.SsoClientDeleted, true, $"Deleted SSO application '{clientId}'");
        return Ok(ApiResponse.Ok("Application deleted"));
    }
}
