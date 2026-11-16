namespace AuthenAPI.Models;

/// <summary>
/// Single sign-on (OpenID Connect provider) settings
/// </summary>
public class SsoSettings
{
    public bool Enabled { get; set; } = true;

    /// <summary>Public base URL, e.g. https://authen.hondacx.me/. Empty = taken from the request.</summary>
    public string? Issuer { get; set; }

    /// <summary>How long a user stays signed in to the SSO (absolute, not sliding)</summary>
    public int SessionHours { get; set; } = 8;

    /// <summary>How often a live SSO session re-checks in AD that the account is still enabled</summary>
    public int AccountRecheckMinutes { get; set; } = 10;

    public int IdentityTokenMinutes { get; set; } = 10;
    public int AccessTokenMinutes { get; set; } = 30;

    /// <summary>Failed logins per username before a temporary lockout (AD has its own lockout too)</summary>
    public int MaxFailedLogins { get; set; } = 5;
    public int LockoutMinutes { get; set; } = 15;

    /// <summary>Failed logins per client IP. Higher than for the admin portal: an office NATs many users behind one IP.</summary>
    public int MaxFailedLoginsPerIp { get; set; } = 100;
}

/// <summary>
/// A registered application (OpenID Connect client)
/// </summary>
public class SsoClient
{
    public string ClientId { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;

    /// <summary>"confidential" (server-side, has a secret) or "public" (SPA/mobile, PKCE only)</summary>
    public string Type { get; set; } = SsoClientTypes.Confidential;

    /// <summary>SHA-256 (hex) of the client secret; null for public clients</summary>
    public string? SecretHash { get; set; }

    public List<string> RedirectUris { get; set; } = new();
    public List<string> PostLogoutRedirectUris { get; set; } = new();
    public string? FrontChannelLogoutUri { get; set; }
    public List<string> AllowedGroups { get; set; } = new();
    public bool RequirePkce { get; set; } = true;
    public bool IsActive { get; set; } = true;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public string? CreatedBy { get; set; }
    public DateTime? UpdatedAt { get; set; }
    public string? UpdatedBy { get; set; }
    public DateTime? SecretRotatedAt { get; set; }
    public DateTime? LastLoginAt { get; set; }
    public long LoginCount { get; set; }
}

public static class SsoClientTypes
{
    public const string Confidential = "confidential";
    public const string Public = "public";
}

public class SsoClientInput
{
    public string? ClientId { get; set; }
    public string DisplayName { get; set; } = string.Empty;
    public string? Type { get; set; }
    public List<string>? RedirectUris { get; set; }
    public List<string>? PostLogoutRedirectUris { get; set; }
    public string? FrontChannelLogoutUri { get; set; }
    public List<string>? AllowedGroups { get; set; }
    public bool RequirePkce { get; set; } = true;
    public bool IsActive { get; set; } = true;
}

public class SsoClientView
{
    public string ClientId { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public string Type { get; set; } = string.Empty;
    public List<string> RedirectUris { get; set; } = new();
    public List<string> PostLogoutRedirectUris { get; set; } = new();
    public string? FrontChannelLogoutUri { get; set; }
    public List<string> AllowedGroups { get; set; } = new();
    public bool RequirePkce { get; set; }
    public bool IsActive { get; set; }
    public DateTime CreatedAt { get; set; }
    public string? CreatedBy { get; set; }
    public DateTime? UpdatedAt { get; set; }
    public DateTime? SecretRotatedAt { get; set; }
    public DateTime? LastLoginAt { get; set; }
    public long LoginCount { get; set; }
}

public class SsoClientSecretResponse
{
    public SsoClientView Client { get; set; } = new();
    public string? ClientSecret { get; set; }
}

public class SsoInfo
{
    public bool Enabled { get; set; }
    public string Issuer { get; set; } = string.Empty;
    public string DiscoveryUrl { get; set; } = string.Empty;
    public string AuthorizeUrl { get; set; } = string.Empty;
    public string TokenUrl { get; set; } = string.Empty;
    public string UserinfoUrl { get; set; } = string.Empty;
    public string LogoutUrl { get; set; } = string.Empty;
    public string LoginPageUrl { get; set; } = string.Empty;
    public int SessionHours { get; set; }
    public List<string> Scopes { get; set; } = new();
    public List<string> Claims { get; set; } = new();
    public int ActiveSessions { get; set; }
}

/// <summary>Persisted OIDC signing/encryption keys (protected with Data Protection before storage)</summary>
public class SsoKeyMaterial
{
    public string SigningKeyId { get; set; } = string.Empty;
    public string SigningRsaPrivateKey { get; set; } = string.Empty; // base64 PKCS#8
    public string EncryptionKeyId { get; set; } = string.Empty;
    public string EncryptionKey { get; set; } = string.Empty;        // base64, 256-bit
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}
