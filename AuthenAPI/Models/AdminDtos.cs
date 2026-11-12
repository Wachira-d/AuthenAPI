namespace AuthenAPI.Models;

public class AdminLoginRequest
{
    public string Username { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
}

public class AdminSession
{
    public string Username { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public string Role { get; set; } = AdminRoles.Viewer;
    public string AuthMethod { get; set; } = "ldap";
    public DateTime? ExpiresAt { get; set; }
}

public class LdapSettingsDto
{
    public string Server { get; set; } = string.Empty;
    public List<string> FallbackServers { get; set; } = new();
    public int Port { get; set; } = 636;
    public bool UseSSL { get; set; } = true;
    public string BaseDN { get; set; } = string.Empty;
    public string Domain { get; set; } = string.Empty;
    public string? NetBiosDomain { get; set; }
    public string ServiceAccountUsername { get; set; } = string.Empty;

    /// <summary>Write-only. Empty/null on update keeps the current password.</summary>
    public string? ServiceAccountPassword { get; set; }

    /// <summary>Read-only: whether a service account password is configured</summary>
    public bool ServiceAccountPasswordSet { get; set; }

    public int ConnectionTimeout { get; set; } = 10;
    public bool SkipCertificateValidation { get; set; }
    public bool ChaseReferrals { get; set; }
    public bool EnableCache { get; set; } = true;
    public int CacheDurationMinutes { get; set; } = 5;
}

public class SecuritySettingsDto
{
    public bool EnableIpWhitelist { get; set; }
    public List<string> AllowedIpAddresses { get; set; } = new();
    public bool EnableApiKeyAuth { get; set; } = true;
    public string ApiKeyHeaderName { get; set; } = "X-API-Key";
    public bool EnableRateLimiting { get; set; } = true;
    public int RateLimitMaxRequests { get; set; } = 100;
    public int RateLimitWindowSeconds { get; set; } = 60;
}

public class AuditSettingsDto
{
    public bool Enabled { get; set; } = true;
    public bool EnableFileLogging { get; set; } = true;
    public int RetentionDays { get; set; } = 90;
    public int FailedLoginThreshold { get; set; } = 5;
    public int FailedLoginWindowMinutes { get; set; } = 15;
    public bool AutoPurgeEnabled { get; set; } = true;
    public int RequestLogRetentionDays { get; set; } = 30;
}

public class AdminSettingsDto
{
    public List<string> AdminUsers { get; set; } = new();
    public List<string> ViewerUsers { get; set; } = new();
    public List<string> AdminGroups { get; set; } = new();
    public List<string> ViewerGroups { get; set; } = new();
    public List<string> AllowedIpAddresses { get; set; } = new();
    public int SessionTimeoutMinutes { get; set; } = 60;
}

public class SettingsOverview
{
    public LdapSettingsDto Ldap { get; set; } = new();
    public SecuritySettingsDto Security { get; set; } = new();
    public AuditSettingsDto Audit { get; set; } = new();
    public AdminSettingsDto Admin { get; set; } = new();
    public Dictionary<string, bool> Overridden { get; set; } = new();
    public string DataDirectory { get; set; } = string.Empty;
}

public class TestAuthResponse
{
    public bool Success { get; set; }
    public AuthFailureReason FailureReason { get; set; }
    public string? Method { get; set; }
    public string? Strategy { get; set; }
    public long DurationMs { get; set; }
    public string? Message { get; set; }
    public UserInfo? User { get; set; }
}
