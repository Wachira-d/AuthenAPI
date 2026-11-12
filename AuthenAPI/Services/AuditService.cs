using AuthenAPI.Models;
using Microsoft.Extensions.Options;
using System.Collections.Concurrent;
using System.Text.Json;

namespace AuthenAPI.Services;

/// <summary>
/// Audit service implementation with in-memory storage and optional file logging
/// </summary>
public class AuditService : IAuditService, IDisposable
{
    private readonly ILogger<AuditService> _logger;
    private readonly IOptionsMonitor<AuditSettings> _settingsMonitor;
    private readonly ConcurrentQueue<AuditLog> _auditLogs;
    private readonly SemaphoreSlim _fileLock;
    private readonly string _logDirectory;
    private bool _disposed;

    private AuditSettings _settings => _settingsMonitor.CurrentValue;

    // Maximum logs to keep in memory
    private const int MaxInMemoryLogs = 10000;

    public AuditService(ILogger<AuditService> logger, IOptionsMonitor<AuditSettings> settings, IWebHostEnvironment environment)
    {
        _logger = logger;
        _settingsMonitor = settings;
        _auditLogs = new ConcurrentQueue<AuditLog>();
        _fileLock = new SemaphoreSlim(1, 1);

        var configured = _settings.LogDirectory;
        if (string.IsNullOrWhiteSpace(configured)) configured = "logs";
        _logDirectory = Path.IsPathRooted(configured) ? configured : Path.Combine(environment.ContentRootPath, configured);

        try
        {
            Directory.CreateDirectory(_logDirectory);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Cannot create audit log directory {Path}", _logDirectory);
        }

        LoadRecentFiles();

        _logger.LogInformation("AuditService initialized. File logging: {Enabled}, Directory: {Path}, reloaded {Count} entries",
            _settings.EnableFileLogging, _logDirectory, _auditLogs.Count);
    }

    /// <summary>
    /// Reload today's and yesterday's audit files so the trail survives app-pool recycles
    /// </summary>
    private void LoadRecentFiles()
    {
        try
        {
            var today = DateTime.UtcNow.Date;
            var loaded = new List<AuditLog>();
            foreach (var day in new[] { today.AddDays(-1), today })
            {
                var file = Path.Combine(_logDirectory, $"audit_{day:yyyyMMdd}.json");
                if (!File.Exists(file)) continue;

                foreach (var line in File.ReadLines(file))
                {
                    if (string.IsNullOrWhiteSpace(line)) continue;
                    try
                    {
                        var entry = JsonSerializer.Deserialize<AuditLog>(line);
                        if (entry != null) loaded.Add(entry);
                    }
                    catch (JsonException)
                    {
                        // skip partially written line
                    }
                }
            }

            foreach (var entry in loaded.OrderBy(l => l.Timestamp).TakeLast(MaxInMemoryLogs))
            {
                _auditLogs.Enqueue(entry);
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not reload audit files from {Path}", _logDirectory);
        }
    }

    /// <inheritdoc />
    public async Task LogAsync(AuditLog log)
    {
        if (!_settings.Enabled) return;

        // Add to in-memory queue
        _auditLogs.Enqueue(log);

        // Trim if exceeds max
        while (_auditLogs.Count > MaxInMemoryLogs)
        {
            _auditLogs.TryDequeue(out _);
        }

        // Log to console/standard logging
        var logLevel = log.Success ? LogLevel.Information : LogLevel.Warning;
        _logger.Log(logLevel,
            "Audit: {Action} | User: {Username} | Success: {Success} | IP: {IP} | Details: {Details}",
            log.Action, log.Username ?? "N/A", log.Success, log.IpAddress ?? "N/A", log.Details ?? "N/A");

        // Write to file if enabled
        if (_settings.EnableFileLogging)
        {
            await WriteToFileAsync(log);
        }
    }

    /// <inheritdoc />
    public async Task LogAsync(AuditAction action, string? username, bool success, string? details = null)
    {
        var log = new AuditLog
        {
            Action = action,
            Username = username,
            Success = success,
            Details = details
        };

        await LogAsync(log);
    }

    /// <inheritdoc />
    public Task<List<AuditLog>> QueryAsync(AuditLogQuery query)
    {
        var logs = _auditLogs.ToList().AsQueryable();

        // Apply filters
        if (!string.IsNullOrEmpty(query.Username))
        {
            logs = logs.Where(l => l.Username != null &&
                l.Username.Contains(query.Username, StringComparison.OrdinalIgnoreCase));
        }

        if (query.Action.HasValue)
        {
            logs = logs.Where(l => l.Action == query.Action.Value);
        }

        if (query.Success.HasValue)
        {
            logs = logs.Where(l => l.Success == query.Success.Value);
        }

        if (query.FromDate.HasValue)
        {
            logs = logs.Where(l => l.Timestamp >= query.FromDate.Value);
        }

        if (query.ToDate.HasValue)
        {
            logs = logs.Where(l => l.Timestamp <= query.ToDate.Value);
        }

        if (!string.IsNullOrEmpty(query.IpAddress))
        {
            logs = logs.Where(l => l.IpAddress == query.IpAddress);
        }

        // Order by timestamp descending (most recent first)
        var result = logs
            .OrderByDescending(l => l.Timestamp)
            .Skip(query.Skip)
            .Take(query.MaxResults)
            .ToList();

        return Task.FromResult(result);
    }

    /// <inheritdoc />
    public Task<PagedResult<AuditLog>> QueryPagedAsync(AuditLogQuery query)
    {
        IEnumerable<AuditLog> logs = _auditLogs.ToList();

        if (!string.IsNullOrEmpty(query.Username))
        {
            logs = logs.Where(l => l.Username != null &&
                l.Username.Contains(query.Username, StringComparison.OrdinalIgnoreCase));
        }
        if (query.Action.HasValue) logs = logs.Where(l => l.Action == query.Action.Value);
        if (query.Success.HasValue) logs = logs.Where(l => l.Success == query.Success.Value);
        if (query.FromDate.HasValue) logs = logs.Where(l => l.Timestamp >= query.FromDate.Value.ToUniversalTime());
        if (query.ToDate.HasValue) logs = logs.Where(l => l.Timestamp <= query.ToDate.Value.ToUniversalTime());
        if (!string.IsNullOrEmpty(query.IpAddress))
        {
            logs = logs.Where(l => l.IpAddress != null && l.IpAddress.Contains(query.IpAddress, StringComparison.OrdinalIgnoreCase));
        }

        var matches = logs.OrderByDescending(l => l.Timestamp).ToList();
        return Task.FromResult(new PagedResult<AuditLog>
        {
            Total = matches.Count,
            Items = matches.Skip(Math.Max(0, query.Skip)).Take(Math.Clamp(query.MaxResults, 1, 500)).ToList()
        });
    }

    /// <inheritdoc />
    public Task<AuditLogSummary> GetSummaryAsync(DateTime? fromDate = null, DateTime? toDate = null)
    {
        var logs = _auditLogs.ToList().AsQueryable();

        if (fromDate.HasValue)
        {
            logs = logs.Where(l => l.Timestamp >= fromDate.Value);
        }

        if (toDate.HasValue)
        {
            logs = logs.Where(l => l.Timestamp <= toDate.Value);
        }

        var logList = logs.ToList();

        var summary = new AuditLogSummary
        {
            TotalEntries = logList.Count,
            SuccessCount = logList.Count(l => l.Success),
            FailureCount = logList.Count(l => !l.Success),
            UniqueUsers = logList
                .Where(l => !string.IsNullOrEmpty(l.Username))
                .Select(l => l.Username!.ToLowerInvariant())
                .Distinct()
                .Count(),
            ActionCounts = logList
                .GroupBy(l => l.Action.ToString())
                .ToDictionary(g => g.Key, g => g.Count()),
            RecentFailedLogins = logList
                .Where(l => l.Action == AuditAction.Authenticate && !l.Success)
                .OrderByDescending(l => l.Timestamp)
                .Take(10)
                .ToList(),
            PeriodStart = fromDate ?? logList.MinBy(l => l.Timestamp)?.Timestamp,
            PeriodEnd = toDate ?? logList.MaxBy(l => l.Timestamp)?.Timestamp
        };

        return Task.FromResult(summary);
    }

    /// <inheritdoc />
    public Task<int> GetRecentFailedLoginCountAsync(string username, int minutes = 15)
    {
        var cutoff = DateTime.UtcNow.AddMinutes(-minutes);
        var count = _auditLogs
            .Where(l => l.Action == AuditAction.Authenticate &&
                       !l.Success &&
                       l.Username != null &&
                       l.Username.Equals(username, StringComparison.OrdinalIgnoreCase) &&
                       l.Timestamp >= cutoff)
            .Count();

        return Task.FromResult(count);
    }

    /// <inheritdoc />
    public Task<int> PurgeOldLogsAsync(int olderThanDays = 90)
    {
        var cutoff = DateTime.UtcNow.AddDays(-olderThanDays);
        var initialCount = _auditLogs.Count;

        // Create new queue without old logs
        var recentLogs = _auditLogs.Where(l => l.Timestamp >= cutoff).ToList();

        // Clear and re-add
        while (_auditLogs.TryDequeue(out _)) { }

        foreach (var log in recentLogs)
        {
            _auditLogs.Enqueue(log);
        }

        var purgedCount = initialCount - _auditLogs.Count;
        _logger.LogInformation("Purged {Count} old audit logs (older than {Days} days)", purgedCount, olderThanDays);

        return Task.FromResult(purgedCount);
    }

    private async Task WriteToFileAsync(AuditLog log)
    {
        try
        {
            await _fileLock.WaitAsync();

            var currentLogFile = Path.Combine(_logDirectory, $"audit_{DateTime.UtcNow:yyyyMMdd}.json");

            var json = JsonSerializer.Serialize(log, new JsonSerializerOptions
            {
                WriteIndented = false
            });

            await File.AppendAllTextAsync(currentLogFile, json + Environment.NewLine);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to write audit log to file");
        }
        finally
        {
            _fileLock.Release();
        }
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            _fileLock.Dispose();
            _disposed = true;
        }
    }
}
