using AuthenAPI.Models;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net.Sockets;
using System.Reflection;
using System.Runtime.InteropServices;

namespace AuthenAPI.Services;

/// <summary>
/// Probes LDAP every minute (service-account bind + TCP reachability of each port),
/// keeps a 7-day history and builds the health report for the admin dashboard.
/// </summary>
public sealed class HealthMonitorService : BackgroundService
{
    private static readonly TimeSpan Interval = TimeSpan.FromSeconds(60);
    private const int ReevaluateEvery = 15;   // probes; ~15 minutes
    private const int MaxSamples = 7 * 24 * 60;

    private static readonly (int Port, bool Ssl)[] ProbedPorts = { (636, true), (389, false), (3269, true), (3268, false) };

    private readonly IServiceScopeFactory _scopeFactory;
    private readonly IOptionsMonitor<LdapSettings> _ldapSettings;
    private readonly LdapStrategyCache _strategyCache;
    private readonly RequestLogService _requestLog;
    private readonly DataPaths _paths;
    private readonly IMemoryCache _cache;
    private readonly IWebHostEnvironment _environment;
    private readonly ILogger<HealthMonitorService> _logger;

    private readonly ConcurrentQueue<HealthSample> _samples = new();
    private readonly SemaphoreSlim _probeLock = new(1, 1);
    private readonly DateTime _startedAt = DateTime.UtcNow;
    private volatile List<PortProbe> _lastPorts = new();
    private volatile LdapProbeResult? _lastProbe;
    private DateTime? _lastProbeAt;
    private DateTime? _lastSuccessAt;
    private DateTime? _lastFailureAt;
    private string? _lastError;
    private int _probeCount;

    private TimeSpan _lastCpu = Process.GetCurrentProcess().TotalProcessorTime;
    private DateTime _lastCpuAt = DateTime.UtcNow;
    private double _cpuPercent;

    public HealthMonitorService(
        IServiceScopeFactory scopeFactory,
        IOptionsMonitor<LdapSettings> ldapSettings,
        LdapStrategyCache strategyCache,
        RequestLogService requestLog,
        DataPaths paths,
        IMemoryCache cache,
        IWebHostEnvironment environment,
        ILogger<HealthMonitorService> logger)
    {
        _scopeFactory = scopeFactory;
        _ldapSettings = ldapSettings;
        _strategyCache = strategyCache;
        _requestLog = requestLog;
        _paths = paths;
        _cache = cache;
        _environment = environment;
        _logger = logger;
    }

    /// <summary>True when the last probe could bind to LDAP (used by /health/ready)</summary>
    public bool? LastProbeOk => _lastProbe?.Ok;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // Let the app finish starting before the first probe.
        try { await Task.Delay(TimeSpan.FromSeconds(5), stoppingToken); }
        catch (OperationCanceledException) { return; }

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await ProbeNowAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Health probe failed unexpectedly");
            }

            try { await Task.Delay(Interval, stoppingToken); }
            catch (OperationCanceledException) { break; }
        }
    }

    /// <summary>Run a probe now (also used by "Check now" in the portal)</summary>
    public async Task ProbeNowAsync(CancellationToken cancellationToken = default)
    {
        await _probeLock.WaitAsync(cancellationToken);
        try
        {
            var settings = _ldapSettings.CurrentValue;
            var portsTask = ProbePortsAsync(settings);

            var reevaluate = Interlocked.Increment(ref _probeCount) % ReevaluateEvery == 0;
            LdapProbeResult probe;
            using (var scope = _scopeFactory.CreateScope())
            {
                var ldap = scope.ServiceProvider.GetRequiredService<ILdapService>();
                probe = await ldap.ProbeAsync(reevaluate, cancellationToken);
            }

            _lastPorts = await portsTask;
            _lastProbe = probe;
            _lastProbeAt = DateTime.UtcNow;

            if (probe.Ok)
            {
                _lastSuccessAt = DateTime.UtcNow;
            }
            else
            {
                _lastFailureAt = DateTime.UtcNow;
                _lastError = probe.Error;
                _logger.LogWarning("Health probe: LDAP bind failed: {Error}", probe.Error);
            }

            _samples.Enqueue(new HealthSample
            {
                Timestamp = DateTime.UtcNow,
                Ok = probe.Ok,
                LatencyMs = probe.LatencyMs,
                Strategy = probe.Strategy,
                Error = probe.Ok ? null : probe.Error
            });
            while (_samples.Count > MaxSamples) _samples.TryDequeue(out _);
        }
        finally
        {
            _probeLock.Release();
        }
    }

    private static async Task<List<PortProbe>> ProbePortsAsync(LdapSettings settings)
    {
        var servers = new[] { settings.Server }.Concat(settings.FallbackServers)
            .Where(s => !string.IsNullOrWhiteSpace(s)).Distinct(StringComparer.OrdinalIgnoreCase);

        var ports = ProbedPorts.ToList();
        if (!ports.Any(p => p.Port == settings.Port)) ports.Insert(0, (settings.Port, settings.UseSSL));

        var tasks = servers.SelectMany(server => ports.Select(p => ProbePortAsync(server, p.Port, p.Ssl)));
        return (await Task.WhenAll(tasks)).ToList();
    }

    private static async Task<PortProbe> ProbePortAsync(string server, int port, bool ssl)
    {
        var probe = new PortProbe { Server = server, Port = port, Ssl = ssl };
        var sw = Stopwatch.StartNew();
        try
        {
            using var client = new TcpClient();
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(3));
            await client.ConnectAsync(server, port, cts.Token);
            probe.Reachable = true;
            probe.LatencyMs = sw.ElapsedMilliseconds;
        }
        catch (OperationCanceledException)
        {
            probe.Error = "Timed out after 3s";
        }
        catch (Exception ex)
        {
            probe.Error = ex.Message;
        }
        return probe;
    }

    public List<HealthSample> GetHistory(int hours)
    {
        var cutoff = DateTime.UtcNow.AddHours(-Math.Clamp(hours, 1, 24 * 7));
        return _samples.Where(s => s.Timestamp >= cutoff).OrderBy(s => s.Timestamp).ToList();
    }

    public HealthReport BuildReport()
    {
        var settings = _ldapSettings.CurrentValue;
        var probe = _lastProbe;
        var now = DateTime.UtcNow;

        var last24h = _samples.Where(s => s.Timestamp >= now.AddHours(-24)).ToList();
        var availability = last24h.Count == 0 ? 0 : Math.Round(100.0 * last24h.Count(s => s.Ok) / last24h.Count, 2);

        var report = new HealthReport
        {
            CheckedAt = _lastProbeAt ?? now,
            StartedAt = _startedAt,
            UptimeSeconds = (long)(now - _startedAt).TotalSeconds,
            Version = Assembly.GetEntryAssembly()?.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion?.Split('+')[0]
                      ?? Assembly.GetEntryAssembly()?.GetName().Version?.ToString() ?? "unknown",
            Environment = _environment.EnvironmentName,
            MachineName = System.Environment.MachineName,
            FrameworkVersion = RuntimeInformation.FrameworkDescription,
            Ldap = new LdapHealth
            {
                Server = settings.Server,
                FallbackServers = settings.FallbackServers.ToList(),
                ActiveStrategy = _strategyCache.PreferredStrategy ?? probe?.Strategy,
                Secure = probe?.Secure
                         ?? (_strategyCache.PreferredStrategy is { } preferred && _strategyCache.Get(preferred)?.Secure == true),
                LastSuccessAt = _lastSuccessAt,
                LastFailureAt = _lastFailureAt,
                LastError = _lastError,
                LatencyMs = probe?.LatencyMs,
                Availability24h = availability,
                Ports = _lastPorts,
                Status = probe == null ? HealthState.Degraded
                    : !probe.Ok ? HealthState.Unhealthy
                    : probe.Secure ? HealthState.Healthy
                    : HealthState.Degraded
            },
            Process = ProcessInfo(),
            Storage = StorageInfo(),
            Cache = CacheInfo()
        };

        report.Checks = BuildChecks(report, probe);
        report.Status = report.Checks.Any(c => c.Status == HealthState.Unhealthy) ? HealthState.Unhealthy
            : report.Checks.Any(c => c.Status == HealthState.Degraded) ? HealthState.Degraded
            : HealthState.Healthy;

        return report;
    }

    private List<HealthCheckItem> BuildChecks(HealthReport report, LdapProbeResult? probe)
    {
        var checks = new List<HealthCheckItem>();

        if (probe == null)
        {
            checks.Add(new HealthCheckItem { Name = "LDAP bind", Status = HealthState.Degraded, Message = "First probe has not run yet" });
        }
        else if (probe.Ok)
        {
            checks.Add(new HealthCheckItem
            {
                Name = "LDAP bind",
                Status = HealthState.Healthy,
                Message = $"Service account bound via {probe.Strategy} in {probe.LatencyMs} ms"
            });
            checks.Add(new HealthCheckItem
            {
                Name = "LDAP encryption",
                Status = probe.Secure ? HealthState.Healthy : HealthState.Degraded,
                Message = probe.Secure
                    ? "Connection to the DC is encrypted"
                    : "Active strategy is unencrypted: passwords are sent in clear text to the DC. Fix LDAPS (636) or allow the sealed 389 strategy."
            });
        }
        else
        {
            checks.Add(new HealthCheckItem
            {
                Name = "LDAP bind",
                Status = HealthState.Unhealthy,
                Message = probe.Error ?? "Service account could not bind"
            });
        }

        var ldaps = _strategyCache.Get("LDAPS-636");
        var port636 = report.Ldap.Ports.FirstOrDefault(p => p.Port == 636 && p.Ssl);
        if (port636 is { Reachable: true } && ldaps is { LastError: not null } &&
            (ldaps.LastSuccessAt == null || ldaps.LastFailureAt > ldaps.LastSuccessAt) &&
            ldaps.LastError.Contains("LDAP 81"))
        {
            checks.Add(new HealthCheckItem
            {
                Name = "LDAPS certificate",
                Status = HealthState.Degraded,
                Message = "Port 636 is reachable but the LDAPS handshake fails: the DC certificate is probably not trusted by this server " +
                          "or does not match the server name. Import the CA certificate or connect by the DC's FQDN."
            });
        }

        var anyPortOpen = report.Ldap.Ports.Any(p => p.Reachable);
        if (report.Ldap.Ports.Count > 0 && !anyPortOpen)
        {
            checks.Add(new HealthCheckItem { Name = "LDAP network", Status = HealthState.Unhealthy, Message = "No LDAP port is reachable on any configured DC" });
        }

        checks.Add(new HealthCheckItem
        {
            Name = "Log directory",
            Status = report.Storage.LogDirectoryWritable ? HealthState.Healthy : HealthState.Degraded,
            Message = report.Storage.LogDirectoryWritable ? report.Storage.LogDirectory : $"Not writable: {report.Storage.LogDirectory} (grant Modify to the app pool identity)"
        });
        checks.Add(new HealthCheckItem
        {
            Name = "Data directory",
            Status = report.Storage.DataDirectoryWritable ? HealthState.Healthy : HealthState.Unhealthy,
            Message = report.Storage.DataDirectoryWritable ? report.Storage.DataDirectory : $"Not writable: {report.Storage.DataDirectory} (API keys and settings cannot be saved)"
        });

        if (report.Storage.DiskFreeGb is < 1)
        {
            checks.Add(new HealthCheckItem { Name = "Disk space", Status = HealthState.Degraded, Message = $"Only {report.Storage.DiskFreeGb:0.00} GB free" });
        }

        var (total, serverErrors) = _requestLog.RecentErrorStats(15);
        var errorRate = total == 0 ? 0 : (double)serverErrors / total;
        checks.Add(new HealthCheckItem
        {
            Name = "Server errors (15 min)",
            Status = total >= 20 && errorRate > 0.05 ? HealthState.Degraded : HealthState.Healthy,
            Message = $"{serverErrors} of {total} requests returned 5xx"
        });

        return checks;
    }

    private ProcessHealth ProcessInfo()
    {
        var process = Process.GetCurrentProcess();
        var now = DateTime.UtcNow;
        var cpu = process.TotalProcessorTime;
        var elapsed = (now - _lastCpuAt).TotalMilliseconds;
        if (elapsed > 1000)
        {
            _cpuPercent = Math.Round((cpu - _lastCpu).TotalMilliseconds / (elapsed * System.Environment.ProcessorCount) * 100, 1);
            _lastCpu = cpu;
            _lastCpuAt = now;
        }

        return new ProcessHealth
        {
            WorkingSetMb = Math.Round(process.WorkingSet64 / 1024d / 1024d, 1),
            GcHeapMb = Math.Round(GC.GetTotalMemory(false) / 1024d / 1024d, 1),
            ThreadCount = process.Threads.Count,
            CpuPercent = _cpuPercent
        };
    }

    private StorageHealth StorageInfo()
    {
        var logDir = _requestLog.LogDirectory;
        var storage = new StorageHealth
        {
            LogDirectory = logDir,
            LogDirectoryWritable = IsWritable(logDir),
            DataDirectory = _paths.DataDirectory,
            DataDirectoryWritable = IsWritable(_paths.DataDirectory)
        };

        try
        {
            var root = Path.GetPathRoot(Path.GetFullPath(_paths.DataDirectory));
            if (!string.IsNullOrEmpty(root))
            {
                storage.DiskFreeGb = Math.Round(new DriveInfo(root).AvailableFreeSpace / 1024d / 1024d / 1024d, 2);
            }
        }
        catch
        {
            // drive info unavailable
        }

        return storage;
    }

    private CacheHealth CacheInfo()
    {
        var stats = (_cache as MemoryCache)?.GetCurrentStatistics();
        return new CacheHealth
        {
            Entries = stats?.CurrentEntryCount ?? 0,
            Hits = stats?.TotalHits ?? 0,
            Misses = stats?.TotalMisses ?? 0
        };
    }

    private static bool IsWritable(string directory)
    {
        try
        {
            Directory.CreateDirectory(directory);
            var probe = Path.Combine(directory, $".write-test-{Guid.NewGuid():N}");
            File.WriteAllText(probe, "ok");
            File.Delete(probe);
            return true;
        }
        catch
        {
            return false;
        }
    }
}
