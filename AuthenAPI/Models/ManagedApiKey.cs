using System.Text.Json.Serialization;

namespace AuthenAPI.Models;

/// <summary>
/// API key managed through the admin portal. Only a SHA-256 hash of the key is stored.
/// </summary>
public class ManagedApiKey
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }

    /// <summary>First characters of the key, safe to display</summary>
    public string Prefix { get; set; } = string.Empty;

    /// <summary>SHA-256 (hex) of the full key</summary>
    public string KeyHash { get; set; } = string.Empty;

    /// <summary>Allowed scopes. Empty = all scopes.</summary>
    public List<string> Scopes { get; set; } = new();

    /// <summary>Allowed client IPs (IP or CIDR). Empty = any.</summary>
    public List<string> AllowedIps { get; set; } = new();

    /// <summary>Per-key request limit per minute. Null = no per-key limit.</summary>
    public int? RateLimitPerMinute { get; set; }

    public bool IsActive { get; set; } = true;
    public DateTime? ExpiresAt { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public string? CreatedBy { get; set; }
    public DateTime? UpdatedAt { get; set; }
    public string? UpdatedBy { get; set; }
    public DateTime? LastUsedAt { get; set; }
    public string? LastUsedIp { get; set; }
    public long UsageCount { get; set; }
    public DateTime? RevokedAt { get; set; }
    public string? RevokedBy { get; set; }
}

/// <summary>
/// API key as shown in the admin portal (never contains the key itself)
/// </summary>
public class ApiKeyView
{
    public string Id { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }
    public string Prefix { get; set; } = string.Empty;
    public string Source { get; set; } = "managed";
    public List<string> Scopes { get; set; } = new();
    public List<string> AllowedIps { get; set; } = new();
    public int? RateLimitPerMinute { get; set; }
    public bool IsActive { get; set; }
    public string Status { get; set; } = "Active";
    public DateTime? ExpiresAt { get; set; }
    public DateTime? CreatedAt { get; set; }
    public string? CreatedBy { get; set; }
    public DateTime? LastUsedAt { get; set; }
    public string? LastUsedIp { get; set; }
    public long UsageCount { get; set; }
    public DateTime? RevokedAt { get; set; }
    public string? RevokedBy { get; set; }
}

/// <summary>
/// Create / update payload for an API key
/// </summary>
public class ApiKeyInput
{
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }
    public List<string>? Scopes { get; set; }
    public List<string>? AllowedIps { get; set; }
    public int? RateLimitPerMinute { get; set; }
    public DateTime? ExpiresAt { get; set; }

    /// <summary>Only used on update</summary>
    public bool? IsActive { get; set; }
}

/// <summary>
/// Response for create / rotate: the plaintext key is returned exactly once
/// </summary>
public class ApiKeySecretResponse
{
    public ApiKeyView Key { get; set; } = new();
    public string PlainTextKey { get; set; } = string.Empty;
}

/// <summary>
/// Known API key scopes and the endpoints they unlock
/// </summary>
public static class ApiKeyScopes
{
    public const string Authenticate = "authenticate";
    public const string UsersRead = "users.read";
    public const string Search = "search";
    public const string Groups = "groups";
    public const string Test = "test";
    public const string Audit = "audit";

    public static readonly IReadOnlyDictionary<string, string> All = new Dictionary<string, string>
    {
        [Authenticate] = "POST /api/ldap/authenticate",
        [UsersRead] = "GET /api/ldap/users/{username}",
        [Search] = "GET/POST /api/ldap/users/search",
        [Groups] = "/api/ldap/users/{username}/groups*",
        [Test] = "/api/ldap/test-connection*",
        [Audit] = "/api/audit/*"
    };

    /// <summary>
    /// Scope required for a request, or null when the path needs no specific scope
    /// </summary>
    public static string? Resolve(string method, string path)
    {
        var p = path.TrimEnd('/').ToLowerInvariant();

        if (p.StartsWith("/api/audit")) return Audit;
        if (!p.StartsWith("/api/ldap")) return null;
        if (p.StartsWith("/api/ldap/test-connection")) return Test;
        if (p == "/api/ldap/authenticate") return Authenticate;
        if (p == "/api/ldap/users/search") return Search;
        if (p.StartsWith("/api/ldap/users/") && p.Contains("/groups")) return Groups;
        if (p.StartsWith("/api/ldap/users/")) return UsersRead;
        return null;
    }
}

/// <summary>
/// Why an API key was rejected
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum ApiKeyFailure
{
    None,
    Missing,
    Invalid,
    Disabled,
    Expired,
    Revoked,
    IpDenied,
    ScopeDenied,
    RateLimited
}

/// <summary>
/// Result of validating a presented API key
/// </summary>
public class ApiKeyValidationResult
{
    public bool Success => Failure == ApiKeyFailure.None;
    public ApiKeyFailure Failure { get; init; }
    public string? KeyId { get; init; }
    public string? KeyName { get; init; }
    public int? RetryAfterSeconds { get; init; }
}
