using AuthenAPI.Models;
using AuthenAPI.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace AuthenAPI.Controllers.Admin;

/// <summary>
/// View and change settings at runtime. Changes are stored in App_Data/settings.runtime.json
/// (previous versions in App_Data/backups) and apply without a restart.
/// </summary>
[Route("api/admin/settings")]
public class AdminSettingsController : AdminControllerBase
{
    private readonly RuntimeSettingsStore _store;
    private readonly DataPaths _paths;
    private readonly IOptionsMonitor<LdapSettings> _ldap;
    private readonly IOptionsMonitor<SecuritySettings> _security;
    private readonly IOptionsMonitor<AuditSettings> _audit;
    private readonly IOptionsMonitor<AdminSettings> _admin;
    private readonly LdapStrategyCache _strategyCache;

    public AdminSettingsController(
        RuntimeSettingsStore store,
        DataPaths paths,
        IOptionsMonitor<LdapSettings> ldap,
        IOptionsMonitor<SecuritySettings> security,
        IOptionsMonitor<AuditSettings> audit,
        IOptionsMonitor<AdminSettings> admin,
        LdapStrategyCache strategyCache)
    {
        _store = store;
        _paths = paths;
        _ldap = ldap;
        _security = security;
        _audit = audit;
        _admin = admin;
        _strategyCache = strategyCache;
    }

    [HttpGet]
    public IActionResult Get() => Ok(ApiResponse<SettingsOverview>.Ok(BuildOverview()));

    [HttpPut("ldap")]
    [Authorize(Policy = AdminRoles.WritePolicy)]
    public async Task<IActionResult> PutLdap([FromBody] LdapSettingsDto dto)
    {
        var errors = SettingsMapper.Validate(dto);
        if (errors.Count > 0) return Invalid(errors);

        var before = SettingsMapper.ToDto(_ldap.CurrentValue);
        var passwordChanged = !string.IsNullOrEmpty(dto.ServiceAccountPassword);
        dto.ServiceAccountPasswordSet = false;
        var password = dto.ServiceAccountPassword;
        dto.ServiceAccountPassword = null;

        _store.Update(o => o.Ldap = dto, CurrentUser, newLdapPassword: password);

        // New connection settings: forget the old preferred strategy and any service-account backoff.
        _strategyCache.Reset();

        await AuditAsync(AuditAction.SettingsChanged, true,
            $"LDAP settings changed: {Diff(before, SettingsMapper.ToDto(_ldap.CurrentValue))}{(passwordChanged ? "; service account password changed" : "")}");
        return Ok(ApiResponse<LdapSettingsDto>.Ok(SettingsMapper.ToDto(_ldap.CurrentValue), "LDAP settings saved"));
    }

    [HttpPut("security")]
    [Authorize(Policy = AdminRoles.WritePolicy)]
    public async Task<IActionResult> PutSecurity([FromBody] SecuritySettingsDto dto)
    {
        var errors = SettingsMapper.Validate(dto);
        if (errors.Count > 0) return Invalid(errors);

        var before = SettingsMapper.ToDto(_security.CurrentValue);
        _store.Update(o => o.Security = dto, CurrentUser);

        await AuditAsync(AuditAction.SettingsChanged, true,
            $"Security settings changed: {Diff(before, SettingsMapper.ToDto(_security.CurrentValue))}");
        return Ok(ApiResponse<SecuritySettingsDto>.Ok(SettingsMapper.ToDto(_security.CurrentValue), "Security settings saved"));
    }

    [HttpPut("audit")]
    [Authorize(Policy = AdminRoles.WritePolicy)]
    public async Task<IActionResult> PutAudit([FromBody] AuditSettingsDto dto)
    {
        var errors = SettingsMapper.Validate(dto);
        if (errors.Count > 0) return Invalid(errors);

        var before = SettingsMapper.ToDto(_audit.CurrentValue);
        _store.Update(o => o.Audit = dto, CurrentUser);

        await AuditAsync(AuditAction.SettingsChanged, true,
            $"Audit settings changed: {Diff(before, SettingsMapper.ToDto(_audit.CurrentValue))}");
        return Ok(ApiResponse<AuditSettingsDto>.Ok(SettingsMapper.ToDto(_audit.CurrentValue), "Audit settings saved"));
    }

    [HttpPut("admin")]
    [Authorize(Policy = AdminRoles.WritePolicy)]
    public async Task<IActionResult> PutAdmin([FromBody] AdminSettingsDto dto)
    {
        var errors = SettingsMapper.Validate(dto);

        // Refuse a change that would leave nobody able to administer the portal.
        var current = _admin.CurrentValue;
        var hasLocalAdmin = current.LocalAdmins.Any(a => !a.Role.Equals(AdminRoles.Viewer, StringComparison.OrdinalIgnoreCase));
        if (!hasLocalAdmin && dto.AdminUsers.All(string.IsNullOrWhiteSpace) && dto.AdminGroups.All(string.IsNullOrWhiteSpace))
        {
            errors.Add("At least one admin user or admin group is required (no local break-glass admin is configured)");
        }
        if (errors.Count > 0) return Invalid(errors);

        var before = SettingsMapper.ToDto(current);
        _store.Update(o => o.Admin = dto, CurrentUser);

        await AuditAsync(AuditAction.SettingsChanged, true,
            $"Admin access changed: {Diff(before, SettingsMapper.ToDto(_admin.CurrentValue))}");
        return Ok(ApiResponse<AdminSettingsDto>.Ok(SettingsMapper.ToDto(_admin.CurrentValue), "Admin access saved"));
    }

    [HttpDelete("{section}")]
    [Authorize(Policy = AdminRoles.WritePolicy)]
    public async Task<IActionResult> Revert(string section)
    {
        Action<RuntimeOverrides>? revert = section.ToLowerInvariant() switch
        {
            "ldap" => o => { o.Ldap = null; o.LdapPasswordProtected = null; },
            "security" => o => o.Security = null,
            "audit" => o => o.Audit = null,
            "admin" => o => o.Admin = null,
            _ => null
        };
        if (revert == null) return NotFound(ApiResponse.Fail($"Unknown section '{section}'"));

        _store.Update(revert, CurrentUser);
        if (section.Equals("ldap", StringComparison.OrdinalIgnoreCase)) _strategyCache.Reset();

        await AuditAsync(AuditAction.SettingsChanged, true, $"Reverted '{section}' settings to appsettings.json");
        return Ok(ApiResponse<SettingsOverview>.Ok(BuildOverview(), $"'{section}' reverted to appsettings.json"));
    }

    [HttpPost("ldap/test")]
    [Authorize(Policy = AdminRoles.WritePolicy)]
    public async Task<IActionResult> TestLdap([FromBody] LdapSettingsDto dto, [FromServices] ILdapService ldap)
    {
        var errors = SettingsMapper.Validate(dto);
        if (errors.Count > 0) return Invalid(errors);

        var candidate = new LdapSettings
        {
            ServiceAccountPassword = string.IsNullOrEmpty(dto.ServiceAccountPassword)
                ? _ldap.CurrentValue.ServiceAccountPassword
                : dto.ServiceAccountPassword
        };
        SettingsMapper.Apply(dto, candidate);

        var result = await ldap.TestSettingsAsync(candidate);
        await AuditAsync(AuditAction.AdminTool, result.Success,
            $"Tested LDAP settings for {candidate.Server}:{candidate.Port}: {(result.Success ? "OK via " + result.Strategy : result.Error)}");
        return Ok(ApiResponse<LdapTestResult>.Ok(result, result.Success ? "Connection test passed" : "Connection test failed"));
    }

    private SettingsOverview BuildOverview()
    {
        var o = _store.Current;
        return new SettingsOverview
        {
            Ldap = SettingsMapper.ToDto(_ldap.CurrentValue),
            Security = SettingsMapper.ToDto(_security.CurrentValue),
            Audit = SettingsMapper.ToDto(_audit.CurrentValue),
            Admin = SettingsMapper.ToDto(_admin.CurrentValue),
            Overridden = new Dictionary<string, bool>
            {
                ["ldap"] = o.Ldap != null || o.LdapPasswordProtected != null,
                ["security"] = o.Security != null,
                ["audit"] = o.Audit != null,
                ["admin"] = o.Admin != null
            },
            DataDirectory = _paths.DataDirectory
        };
    }

    /// <summary>"field: old → new" for changed properties (passwords are never included)</summary>
    private static string Diff<T>(T before, T after)
    {
        var changes = new List<string>();
        foreach (var prop in typeof(T).GetProperties())
        {
            if (prop.Name.Contains("Password", StringComparison.OrdinalIgnoreCase)) continue;

            var a = Format(prop.GetValue(before));
            var b = Format(prop.GetValue(after));
            if (a != b) changes.Add($"{prop.Name}: {a} → {b}");
        }
        return changes.Count == 0 ? "no changes" : string.Join("; ", changes);

        static string Format(object? v) => v switch
        {
            null => "null",
            IEnumerable<string> list => "[" + string.Join(", ", list) + "]",
            _ => v.ToString() ?? "null"
        };
    }
}
