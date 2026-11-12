using AuthenAPI.Models;
using AuthenAPI.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AuthenAPI.Controllers.Admin;

[Route("api/admin/keys")]
public class AdminKeysController : AdminControllerBase
{
    private readonly ApiKeyService _keys;

    public AdminKeysController(ApiKeyService keys) => _keys = keys;

    [HttpGet]
    public IActionResult List() => Ok(ApiResponse<List<ApiKeyView>>.Ok(_keys.List()));

    [HttpGet("scopes")]
    public IActionResult Scopes() =>
        Ok(ApiResponse<object>.Ok(ApiKeyScopes.All.Select(s => new { scope = s.Key, description = s.Value }).ToList()));

    [HttpPost]
    [Authorize(Policy = AdminRoles.WritePolicy)]
    public async Task<IActionResult> Create([FromBody] ApiKeyInput input)
    {
        var errors = _keys.ValidateInput(input);
        if (errors.Count > 0) return Invalid(errors);

        var created = _keys.Create(input, CurrentUser);
        await AuditAsync(AuditAction.ApiKeyCreated, true,
            $"Created key '{created.Key.Name}' ({created.Key.Prefix}) scopes=[{string.Join(",", created.Key.Scopes)}] ips=[{string.Join(",", created.Key.AllowedIps)}]");
        return Ok(ApiResponse<ApiKeySecretResponse>.Ok(created, "API key created. Copy it now: it will not be shown again."));
    }

    [HttpPut("{id}")]
    [Authorize(Policy = AdminRoles.WritePolicy)]
    public async Task<IActionResult> Update(string id, [FromBody] ApiKeyInput input)
    {
        if (_keys.IsLegacy(id)) return BadRequest(ApiResponse.Fail("Keys from appsettings.json are read-only"));

        var errors = _keys.ValidateInput(input);
        if (errors.Count > 0) return Invalid(errors);

        var updated = _keys.Update(id, input, CurrentUser);
        if (updated == null) return NotFound(ApiResponse.Fail("API key not found"));

        await AuditAsync(AuditAction.ApiKeyUpdated, true,
            $"Updated key '{updated.Name}' ({updated.Prefix}) active={updated.IsActive} scopes=[{string.Join(",", updated.Scopes)}] ips=[{string.Join(",", updated.AllowedIps)}] rate={updated.RateLimitPerMinute?.ToString() ?? "-"} expires={updated.ExpiresAt?.ToString("u") ?? "-"}");
        return Ok(ApiResponse<ApiKeyView>.Ok(updated, "API key updated"));
    }

    [HttpPost("{id}/rotate")]
    [Authorize(Policy = AdminRoles.WritePolicy)]
    public async Task<IActionResult> Rotate(string id)
    {
        if (_keys.IsLegacy(id)) return BadRequest(ApiResponse.Fail("Keys from appsettings.json are read-only"));

        var rotated = _keys.Rotate(id, CurrentUser);
        if (rotated == null) return NotFound(ApiResponse.Fail("API key not found or revoked"));

        await AuditAsync(AuditAction.ApiKeyRotated, true, $"Rotated key '{rotated.Key.Name}' (new prefix {rotated.Key.Prefix})");
        return Ok(ApiResponse<ApiKeySecretResponse>.Ok(rotated, "API key rotated. The old value no longer works."));
    }

    [HttpPost("{id}/revoke")]
    [Authorize(Policy = AdminRoles.WritePolicy)]
    public async Task<IActionResult> Revoke(string id)
    {
        if (_keys.IsLegacy(id)) return BadRequest(ApiResponse.Fail("Keys from appsettings.json are read-only"));

        var revoked = _keys.Revoke(id, CurrentUser);
        if (revoked == null) return NotFound(ApiResponse.Fail("API key not found"));

        await AuditAsync(AuditAction.ApiKeyRevoked, true, $"Revoked key '{revoked.Name}' ({revoked.Prefix})");
        return Ok(ApiResponse<ApiKeyView>.Ok(revoked, "API key revoked"));
    }

    [HttpDelete("{id}")]
    [Authorize(Policy = AdminRoles.WritePolicy)]
    public async Task<IActionResult> Delete(string id)
    {
        if (_keys.IsLegacy(id)) return BadRequest(ApiResponse.Fail("Keys from appsettings.json are read-only"));

        var existing = _keys.Get(id);
        if (existing == null || !_keys.Delete(id)) return NotFound(ApiResponse.Fail("API key not found"));

        await AuditAsync(AuditAction.ApiKeyDeleted, true, $"Deleted key '{existing.Name}' ({existing.Prefix})");
        return Ok(ApiResponse.Ok("API key deleted"));
    }
}
