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
    private readonly AuditSettings _settings;
    private readonly ConcurrentQueue<AuditLog> _auditLogs;
    private readonly SemaphoreSlim _fileLock;
    private readonly string _logFilePath;
    private bool _disposed;

    // Maximum logs to keep in memory
    private const int MaxInMemoryLogs = 10000;

    public AuditService(ILogger<AuditService> logger, IOptions<AuditSettings> settings)
    {
        _logger = logger;
        _settings = settings.Value;
        _auditLogs = new ConcurrentQueue<AuditLog>();
        _fileLock = new SemaphoreSlim(1, 1);

        // Set up log file path
        var logDirectory = _settings.LogDirectory ?? Path.Combine(AppContext.BaseDirectory, "logs");
        if (!Directory.Exists(logDirectory))
        {
            Directory.CreateDirectory(logDirectory);
        }
        _logFilePath = Path.Combine(logDirectory, $"audit_{DateTime.UtcNow:yyyyMMdd}.json");

        _logger.LogInformation("AuditService initialized. File logging: {Enabled}, Path: {Path}",
            _settings.EnableFileLogging, _logFilePath);
    }

    /// <inheritdoc />
    public async Task LogAsync(AuditLog log)
    {
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

            // Update file path if date changed
            var currentLogFile = Path.Combine(
                Path.GetDirectoryName(_logFilePath) ?? "logs",
                $"audit_{DateTime.UtcNow:yyyyMMdd}.json");

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
