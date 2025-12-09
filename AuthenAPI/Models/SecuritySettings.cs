namespace AuthenAPI.Models;

/// <summary>
/// Security configuration settings
/// </summary>
public class SecuritySettings
{
    /// <summary>
    /// Enable IP whitelist filtering
    /// </summary>
    public bool EnableIpWhitelist { get; set; } = false;

    /// <summary>
    /// List of allowed IP addresses (supports CIDR notation)
    /// Example: ["192.168.1.0/24", "10.0.0.1", "172.16.0.0/16"]
    /// </summary>
    public List<string> AllowedIpAddresses { get; set; } = new();

    /// <summary>
    /// Enable API Key authentication
    /// </summary>
    public bool EnableApiKeyAuth { get; set; } = true;

    /// <summary>
    /// List of valid API keys with their descriptions
    /// </summary>
    public List<ApiKeyConfig> ApiKeys { get; set; } = new();

    /// <summary>
    /// API Key header name
    /// </summary>
    public string ApiKeyHeaderName { get; set; } = "X-API-Key";

    /// <summary>
    /// Enable rate limiting
    /// </summary>
    public bool EnableRateLimiting { get; set; } = true;

    /// <summary>
    /// Maximum requests per window
    /// </summary>
    public int RateLimitMaxRequests { get; set; } = 100;

    /// <summary>
    /// Rate limit window in seconds
    /// </summary>
    public int RateLimitWindowSeconds { get; set; } = 60;

    /// <summary>
    /// Paths to exclude from authentication (e.g., health check)
    /// </summary>
    public List<string> ExcludedPaths { get; set; } = new() { "/health", "/swagger" };
}

/// <summary>
/// API Key configuration
/// </summary>
public class ApiKeyConfig
{
    /// <summary>
    /// The API key value
    /// </summary>
    public string Key { get; set; } = string.Empty;

    /// <summary>
    /// Description of who/what this key is for
    /// </summary>
    public string Description { get; set; } = string.Empty;

    /// <summary>
    /// Whether this key is active
    /// </summary>
    public bool IsActive { get; set; } = true;

    /// <summary>
    /// Optional expiration date
    /// </summary>
    public DateTime? ExpiresAt { get; set; }
}
