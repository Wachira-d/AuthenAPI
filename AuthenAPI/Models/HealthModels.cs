using System.Text.Json.Serialization;

namespace AuthenAPI.Models;

[JsonConverter(typeof(JsonStringEnumConverter))]
public enum HealthState
{
    Healthy,
    Degraded,
    Unhealthy
}

/// <summary>
/// Complete health report for the admin dashboard
/// </summary>
public class HealthReport
{
    public HealthState Status { get; set; }
    public DateTime CheckedAt { get; set; }
    public DateTime StartedAt { get; set; }
    public long UptimeSeconds { get; set; }
    public string Version { get; set; } = string.Empty;
    public string Environment { get; set; } = string.Empty;
    public string MachineName { get; set; } = string.Empty;
    public string FrameworkVersion { get; set; } = string.Empty;
    public LdapHealth Ldap { get; set; } = new();
    public ProcessHealth Process { get; set; } = new();
    public StorageHealth Storage { get; set; } = new();
    public CacheHealth Cache { get; set; } = new();
    public List<HealthCheckItem> Checks { get; set; } = new();
}

public class LdapHealth
{
    public HealthState Status { get; set; }
    public string Server { get; set; } = string.Empty;
    public List<string> FallbackServers { get; set; } = new();
    public string? ActiveStrategy { get; set; }
    public bool Secure { get; set; }
    public DateTime? LastSuccessAt { get; set; }
    public DateTime? LastFailureAt { get; set; }
    public string? LastError { get; set; }
    public long? LatencyMs { get; set; }
    public double Availability24h { get; set; }
    public List<PortProbe> Ports { get; set; } = new();
}

public class PortProbe
{
    public string Server { get; set; } = string.Empty;
    public int Port { get; set; }
    public bool Ssl { get; set; }
    public bool Reachable { get; set; }
    public long? LatencyMs { get; set; }
    public string? Error { get; set; }
}

public class ProcessHealth
{
    public double WorkingSetMb { get; set; }
    public double GcHeapMb { get; set; }
    public int ThreadCount { get; set; }
    public double CpuPercent { get; set; }
}

public class StorageHealth
{
    public string LogDirectory { get; set; } = string.Empty;
    public bool LogDirectoryWritable { get; set; }
    public string DataDirectory { get; set; } = string.Empty;
    public bool DataDirectoryWritable { get; set; }
    public double? DiskFreeGb { get; set; }
}

public class CacheHealth
{
    public long Entries { get; set; }
    public long Hits { get; set; }
    public long Misses { get; set; }
}

public class HealthCheckItem
{
    public string Name { get; set; } = string.Empty;
    public HealthState Status { get; set; }
    public string Message { get; set; } = string.Empty;
}

/// <summary>
/// One periodic LDAP probe result
/// </summary>
public class HealthSample
{
    public DateTime Timestamp { get; set; }
    public bool Ok { get; set; }
    public long? LatencyMs { get; set; }
    public string? Strategy { get; set; }
    public string? Error { get; set; }
}

/// <summary>
/// Result of a quick service-account bind used by the health monitor
/// </summary>
public class LdapProbeResult
{
    public bool Ok { get; set; }
    public string? Strategy { get; set; }
    public bool Secure { get; set; }
    public long LatencyMs { get; set; }
    public string? Error { get; set; }
    public AuthFailureReason FailureReason { get; set; }
}

/// <summary>
/// Statistics for one LDAP connection strategy
/// </summary>
public class LdapStrategyStats
{
    public string Name { get; set; } = string.Empty;
    public string Server { get; set; } = string.Empty;
    public int Port { get; set; }
    public bool Ssl { get; set; }
    public bool Secure { get; set; }
    public long SuccessCount { get; set; }
    public long FailureCount { get; set; }
    public DateTime? LastSuccessAt { get; set; }
    public DateTime? LastFailureAt { get; set; }
    public string? LastError { get; set; }
    public double AvgLatencyMs { get; set; }
    public bool IsPreferred { get; set; }
}
