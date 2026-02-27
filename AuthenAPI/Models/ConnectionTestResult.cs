namespace AuthenAPI.Models;

/// <summary>
/// Result of a single connection attempt with a specific strategy
/// </summary>
public class ConnectionAttemptResult
{
    /// <summary>
    /// Name of the connection strategy (e.g., "LDAPS-636-UPN")
    /// </summary>
    public string StrategyName { get; set; } = "";

    /// <summary>
    /// Server hostname used
    /// </summary>
    public string Server { get; set; } = "";

    /// <summary>
    /// Port used for connection
    /// </summary>
    public int Port { get; set; }

    /// <summary>
    /// Whether SSL was used
    /// </summary>
    public bool UseSSL { get; set; }

    /// <summary>
    /// Authentication type used
    /// </summary>
    public string AuthType { get; set; } = "";

    /// <summary>
    /// Username format used for authentication
    /// </summary>
    public string UsernameFormat { get; set; } = "";

    /// <summary>
    /// Whether the connection was successful
    /// </summary>
    public bool Success { get; set; }

    /// <summary>
    /// Response time in milliseconds (if successful)
    /// </summary>
    public long? ResponseTimeMs { get; set; }

    /// <summary>
    /// LDAP error code (if failed)
    /// </summary>
    public int? ErrorCode { get; set; }

    /// <summary>
    /// Error message (if failed)
    /// </summary>
    public string? ErrorMessage { get; set; }
}

/// <summary>
/// Complete result of connection diagnostics testing multiple strategies
/// </summary>
public class ConnectionTestResult
{
    /// <summary>
    /// Target server being tested
    /// </summary>
    public string Server { get; set; } = "";

    /// <summary>
    /// Configured port in settings
    /// </summary>
    public int ConfiguredPort { get; set; }

    /// <summary>
    /// When the test started
    /// </summary>
    public DateTime TestStartTime { get; set; }

    /// <summary>
    /// Total time for all tests in milliseconds
    /// </summary>
    public long TotalTestTimeMs { get; set; }

    /// <summary>
    /// Overall success - at least one strategy worked
    /// </summary>
    public bool Success { get; set; }

    /// <summary>
    /// The recommended strategy based on testing (first successful one)
    /// </summary>
    public ConnectionAttemptResult? RecommendedStrategy { get; set; }

    /// <summary>
    /// List of all successful connection strategies
    /// </summary>
    public List<ConnectionAttemptResult> SuccessfulStrategies { get; set; } = new();

    /// <summary>
    /// List of all failed connection strategies
    /// </summary>
    public List<ConnectionAttemptResult> FailedStrategies { get; set; } = new();

    /// <summary>
    /// Summary message for display
    /// </summary>
    public string Summary => Success
        ? $"Connection successful! Recommended: {RecommendedStrategy?.StrategyName}. {SuccessfulStrategies.Count} working strategies found."
        : $"Connection failed. All {FailedStrategies.Count} strategies failed.";
}
