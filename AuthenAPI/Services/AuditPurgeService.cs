using AuthenAPI.Models;
using Microsoft.Extensions.Options;

namespace AuthenAPI.Services;

/// <summary>
/// Background service for automatic audit log purging
/// </summary>
public class AuditPurgeService : BackgroundService
{
    private readonly IServiceProvider _serviceProvider;
    private readonly ILogger<AuditPurgeService> _logger;
    private readonly AuditSettings _settings;

    public AuditPurgeService(
        IServiceProvider serviceProvider,
        ILogger<AuditPurgeService> logger,
        IOptions<AuditSettings> settings)
    {
        _serviceProvider = serviceProvider;
        _logger = logger;
        _settings = settings.Value;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!_settings.AutoPurgeEnabled)
        {
            _logger.LogInformation("Auto-purge is disabled. Background service will not run.");
            return;
        }

        _logger.LogInformation(
            "Audit Auto-Purge Service started. Retention: {Days} days, Interval: {Hours} hours",
            _settings.RetentionDays,
            _settings.AutoPurgeIntervalHours);

        // Wait a bit before first run to let the application start up
        await Task.Delay(TimeSpan.FromMinutes(1), stoppingToken);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await PurgeOldLogsAsync();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error occurred during auto-purge");
            }

            // Wait for the next purge interval
            var interval = TimeSpan.FromHours(_settings.AutoPurgeIntervalHours);
            _logger.LogDebug("Next auto-purge scheduled in {Hours} hours", _settings.AutoPurgeIntervalHours);

            await Task.Delay(interval, stoppingToken);
        }

        _logger.LogInformation("Audit Auto-Purge Service stopped");
    }

    private async Task PurgeOldLogsAsync()
    {
        _logger.LogInformation("Starting auto-purge of audit logs older than {Days} days", _settings.RetentionDays);

        using var scope = _serviceProvider.CreateScope();
        var auditService = scope.ServiceProvider.GetRequiredService<IAuditService>();

        var purgedCount = await auditService.PurgeOldLogsAsync(_settings.RetentionDays);

        if (purgedCount > 0)
        {
            _logger.LogInformation("Auto-purge completed. Removed {Count} old audit log entries", purgedCount);

            // Log the purge action itself
            await auditService.LogAsync(new AuditLog
            {
                Action = AuditAction.ViewAuditLogs,
                Success = true,
                Details = $"Auto-purge: Removed {purgedCount} logs older than {_settings.RetentionDays} days"
            });
        }
        else
        {
            _logger.LogDebug("Auto-purge completed. No old logs to remove");
        }

        // Also clean up old log files if file logging is enabled
        if (_settings.EnableFileLogging)
        {
            await CleanupOldLogFilesAsync();
        }
    }

    private Task CleanupOldLogFilesAsync()
    {
        try
        {
            var logDirectory = _settings.LogDirectory ?? Path.Combine(AppContext.BaseDirectory, "logs");

            if (!Directory.Exists(logDirectory))
            {
                return Task.CompletedTask;
            }

            var cutoffDate = DateTime.UtcNow.AddDays(-_settings.RetentionDays);
            var logFiles = Directory.GetFiles(logDirectory, "audit_*.json");
            var deletedCount = 0;

            foreach (var file in logFiles)
            {
                var fileInfo = new FileInfo(file);

                // Check if file is older than retention period
                if (fileInfo.LastWriteTimeUtc < cutoffDate)
                {
                    try
                    {
                        File.Delete(file);
                        deletedCount++;
                        _logger.LogDebug("Deleted old log file: {FileName}", fileInfo.Name);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "Failed to delete old log file: {FileName}", fileInfo.Name);
                    }
                }
            }

            if (deletedCount > 0)
            {
                _logger.LogInformation("Cleaned up {Count} old log files", deletedCount);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during log file cleanup");
        }

        return Task.CompletedTask;
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("Audit Auto-Purge Service is stopping");
        await base.StopAsync(cancellationToken);
    }
}
