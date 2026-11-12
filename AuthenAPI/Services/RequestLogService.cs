using AuthenAPI.Data;
using AuthenAPI.Models;
using Microsoft.EntityFrameworkCore;
using AuthenAPI.Utilities;
using Microsoft.Extensions.Options;
using System.Text.Json;
using System.Threading.Channels;

namespace AuthenAPI.Services;

/// <summary>
/// Records every API call. Keeps the most recent entries in memory for the admin portal and
/// appends all entries to logs/requests_yyyyMMdd.jsonl (written by a background loop, so requests never wait on disk).
/// </summary>
public sealed class RequestLogService : BackgroundService
{
    private const int Capacity = 50_000;
    private static readonly JsonSerializerOptions FileJson = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

    private const int MaxMetricRows = 500_000;
    private readonly Database _database;
    private readonly DatabaseLogWriter _dbWriter;
    private readonly IOptionsMonitor<AuditSettings> _auditSettings;
    private readonly IWebHostEnvironment _environment;
    private readonly ILogger<RequestLogService> _logger;
    private readonly Channel<RequestLogEntry> _writeQueue =
        Channel.CreateBounded<RequestLogEntry>(new BoundedChannelOptions(10_000) { FullMode = BoundedChannelFullMode.DropOldest });

    private readonly RequestLogEntry?[] _buffer = new RequestLogEntry?[Capacity];
    private readonly object _bufferLock = new();
    private int _next;
    private int _count;
    private DateTime _lastPurge = DateTime.MinValue;

    public RequestLogService(Database database, DatabaseLogWriter dbWriter, IOptionsMonitor<AuditSettings> auditSettings,
        IWebHostEnvironment environment, ILogger<RequestLogService> logger)
    {
        _database = database;
        _dbWriter = dbWriter;
        _auditSettings = auditSettings;
        _environment = environment;
        _logger = logger;
        LoadRecentFiles();
    }

    public string LogDirectory
    {
        get
        {
            var dir = _auditSettings.CurrentValue.LogDirectory;
            if (string.IsNullOrWhiteSpace(dir)) dir = "logs";
            return Path.IsPathRooted(dir) ? dir : Path.Combine(_environment.ContentRootPath, dir);
        }
    }

    public void Record(RequestLogEntry entry)
    {
        lock (_bufferLock)
        {
            _buffer[_next] = entry;
            _next = (_next + 1) % Capacity;
            if (_count < Capacity) _count++;
        }

        _writeQueue.Writer.TryWrite(entry);
        _dbWriter.Enqueue(entry);
    }

    /// <summary>Run a database read; on failure fall back to the in-memory copy</summary>
    private T FromDatabaseOr<T>(Func<AuthenDbContext, T> read, Func<T> fallback)
    {
        if (!_database.Enabled) return fallback();
        try
        {
            using var db = _database.CreateContext();
            db.Database.SetCommandTimeout(30);
            var result = read(db);
            _database.ReportOk();
            return result;
        }
        catch (Exception ex)
        {
            _database.ReportError(ex);
            _logger.LogWarning("Request log query failed on the database, showing recent in-memory entries: {Error}",
                ex.GetBaseException().Message);
            return fallback();
        }
    }

    /// <summary>Entries in chronological order (oldest first)</summary>
    private List<RequestLogEntry> Snapshot()
    {
        lock (_bufferLock)
        {
            var list = new List<RequestLogEntry>(_count);
            var start = (_next - _count + Capacity) % Capacity;
            for (var i = 0; i < _count; i++)
            {
                var e = _buffer[(start + i) % Capacity];
                if (e != null) list.Add(e);
            }
            return list;
        }
    }

    #region Queries

    public PagedResult<RequestLogEntry> Query(RequestLogQuery q) => FromDatabaseOr(
        db =>
        {
            var query = FilterDb(db.RequestLogs.AsNoTracking(), q);
            return new PagedResult<RequestLogEntry>
            {
                Total = query.Count(),
                Items = query.OrderByDescending(e => e.Timestamp).Skip(Math.Max(0, q.Skip)).Take(Math.Clamp(q.Take, 1, 500)).ToList()
            };
        },
        () =>
        {
            var matches = Filter(Snapshot(), q).OrderByDescending(e => e.Timestamp).ToList();
            return new PagedResult<RequestLogEntry>
            {
                Total = matches.Count,
                Items = matches.Skip(Math.Max(0, q.Skip)).Take(Math.Clamp(q.Take, 1, 500)).ToList()
            };
        });

    public RequestLogEntry? Get(string id) => FromDatabaseOr(
        db => db.RequestLogs.AsNoTracking().FirstOrDefault(e => e.Id == id) ?? Snapshot().FirstOrDefault(e => e.Id == id),
        () => Snapshot().FirstOrDefault(e => e.Id == id));

    public string ExportCsv(RequestLogQuery q)
    {
        var rows = FromDatabaseOr(
            db => FilterDb(db.RequestLogs.AsNoTracking(), q).OrderByDescending(e => e.Timestamp).Take(100_000).ToList(),
            () => Filter(Snapshot(), q).OrderByDescending(e => e.Timestamp).Take(100_000).ToList());
        return CsvWriter.Build(
            new[] { "timestamp", "method", "path", "query", "status", "durationMs", "clientIp", "apiKey", "username", "outcome", "error", "ldapStrategy", "userAgent", "traceId" },
            rows.Select(e => new object?[]
            {
                e.Timestamp, e.Method, e.Path, e.QueryString, e.StatusCode, e.DurationMs, e.ClientIp,
                e.ApiKeyName, e.Username, e.Outcome, e.ErrorMessage, e.LdapStrategy, e.UserAgent, e.TraceId
            }));
    }

    /// <summary>Same filters as <see cref="Filter"/>, translated to SQL (LIKE is case-insensitive with the default collation)</summary>
    private static IQueryable<RequestLogEntry> FilterDb(IQueryable<RequestLogEntry> e, RequestLogQuery q)
    {
        if (q.From.HasValue) { var from = q.From.Value.ToUniversalTime(); e = e.Where(x => x.Timestamp >= from); }
        if (q.To.HasValue) { var to = q.To.Value.ToUniversalTime(); e = e.Where(x => x.Timestamp <= to); }
        if (!string.IsNullOrWhiteSpace(q.Method)) { var m = q.Method.Trim().ToUpperInvariant(); e = e.Where(x => x.Method == m); }
        if (!string.IsNullOrWhiteSpace(q.Path)) e = e.Where(x => x.Path.Contains(q.Path));
        if (!string.IsNullOrWhiteSpace(q.ApiKeyId)) e = e.Where(x => x.ApiKeyId == q.ApiKeyId);
        if (!string.IsNullOrWhiteSpace(q.Ip)) e = e.Where(x => x.ClientIp != null && x.ClientIp.Contains(q.Ip));
        if (!string.IsNullOrWhiteSpace(q.Username)) e = e.Where(x => x.Username != null && x.Username.Contains(q.Username));
        if (q.MinDurationMs.HasValue) e = e.Where(x => x.DurationMs >= q.MinDurationMs.Value);

        if (!string.IsNullOrWhiteSpace(q.Status))
        {
            var status = q.Status.Trim().ToLowerInvariant();
            if (status.Length == 3 && status.EndsWith("xx") && char.IsDigit(status[0]))
            {
                var low = (status[0] - '0') * 100;
                var high = low + 100;
                e = e.Where(x => x.StatusCode >= low && x.StatusCode < high);
            }
            else if (int.TryParse(status, out var code))
            {
                e = e.Where(x => x.StatusCode == code);
            }
        }

        if (!string.IsNullOrWhiteSpace(q.Search))
        {
            var s = q.Search.Trim();
            e = e.Where(x =>
                x.Path.Contains(s) || (x.Username != null && x.Username.Contains(s)) || (x.ClientIp != null && x.ClientIp.Contains(s)) ||
                (x.ApiKeyName != null && x.ApiKeyName.Contains(s)) || (x.Outcome != null && x.Outcome.Contains(s)) ||
                (x.ErrorMessage != null && x.ErrorMessage.Contains(s)) || (x.UserAgent != null && x.UserAgent.Contains(s)) ||
                (x.TraceId != null && x.TraceId.Contains(s)));
        }

        return e;
    }

    private static IEnumerable<RequestLogEntry> Filter(IEnumerable<RequestLogEntry> source, RequestLogQuery q)
    {
        var e = source;
        if (q.From.HasValue) { var from = q.From.Value.ToUniversalTime(); e = e.Where(x => x.Timestamp >= from); }
        if (q.To.HasValue) { var to = q.To.Value.ToUniversalTime(); e = e.Where(x => x.Timestamp <= to); }
        if (!string.IsNullOrWhiteSpace(q.Method)) e = e.Where(x => x.Method.Equals(q.Method, StringComparison.OrdinalIgnoreCase));
        if (!string.IsNullOrWhiteSpace(q.Path)) e = e.Where(x => x.Path.Contains(q.Path, StringComparison.OrdinalIgnoreCase));
        if (!string.IsNullOrWhiteSpace(q.ApiKeyId)) e = e.Where(x => x.ApiKeyId == q.ApiKeyId);
        if (!string.IsNullOrWhiteSpace(q.Ip)) e = e.Where(x => x.ClientIp != null && x.ClientIp.Contains(q.Ip, StringComparison.OrdinalIgnoreCase));
        if (!string.IsNullOrWhiteSpace(q.Username)) e = e.Where(x => x.Username != null && x.Username.Contains(q.Username, StringComparison.OrdinalIgnoreCase));
        if (q.MinDurationMs.HasValue) e = e.Where(x => x.DurationMs >= q.MinDurationMs.Value);

        if (!string.IsNullOrWhiteSpace(q.Status))
        {
            var status = q.Status.Trim().ToLowerInvariant();
            if (status.Length == 3 && status.EndsWith("xx") && char.IsDigit(status[0]))
            {
                var cls = status[0] - '0';
                e = e.Where(x => x.StatusCode / 100 == cls);
            }
            else if (int.TryParse(status, out var code))
            {
                e = e.Where(x => x.StatusCode == code);
            }
        }

        if (!string.IsNullOrWhiteSpace(q.Search))
        {
            var s = q.Search.Trim();
            e = e.Where(x =>
                Contains(x.Path, s) || Contains(x.Username, s) || Contains(x.ClientIp, s) || Contains(x.ApiKeyName, s) ||
                Contains(x.Outcome, s) || Contains(x.ErrorMessage, s) || Contains(x.UserAgent, s) || Contains(x.TraceId, s));
        }

        return e;

        static bool Contains(string? value, string term) => value != null && value.Contains(term, StringComparison.OrdinalIgnoreCase);
    }

    public MetricsReport GetMetrics(string? range, string? apiKeyId)
    {
        var (span, bucketMinutes, label) = (range ?? "24h").ToLowerInvariant() switch
        {
            "1h" => (TimeSpan.FromHours(1), 1, "1h"),
            "7d" => (TimeSpan.FromDays(7), 360, "7d"),
            _ => (TimeSpan.FromHours(24), 60, "24h")
        };

        var bucket = TimeSpan.FromMinutes(bucketMinutes);
        var to = DateTime.UtcNow;
        var firstBucket = new DateTime(((to - span).Ticks / bucket.Ticks + 1) * bucket.Ticks, DateTimeKind.Utc);
        var from = firstBucket;

        var list = FromDatabaseOr(
            db =>
            {
                var q = db.RequestLogs.AsNoTracking().Where(e => e.Timestamp >= from && e.Timestamp <= to);
                if (!string.IsNullOrWhiteSpace(apiKeyId)) q = q.Where(e => e.ApiKeyId == apiKeyId);
                // Only the columns metrics need.
                return q.OrderByDescending(e => e.Timestamp).Take(MaxMetricRows).Select(e => new RequestLogEntry
                {
                    Timestamp = e.Timestamp, Method = e.Method, Path = e.Path, StatusCode = e.StatusCode, DurationMs = e.DurationMs,
                    ApiKeyId = e.ApiKeyId, ApiKeyName = e.ApiKeyName, ClientIp = e.ClientIp, Username = e.Username
                }).ToList();
            },
            () =>
            {
                var entries = Snapshot().Where(e => e.Timestamp >= from && e.Timestamp <= to);
                if (!string.IsNullOrWhiteSpace(apiKeyId)) entries = entries.Where(e => e.ApiKeyId == apiKeyId);
                return entries.ToList();
            });

        var durations = list.Select(e => e.DurationMs).OrderBy(d => d).ToList();
        var auth = list.Where(IsAuthCall).ToList();

        var report = new MetricsReport
        {
            Range = label,
            From = from,
            To = to,
            BucketMinutes = bucketMinutes,
            TotalRequests = list.Count,
            SuccessRequests = list.Count(e => e.StatusCode is >= 200 and < 300),
            ClientErrors = list.Count(e => e.StatusCode is >= 400 and < 500),
            ServerErrors = list.Count(e => e.StatusCode >= 500),
            AvgLatencyMs = durations.Count == 0 ? 0 : Math.Round(durations.Average(), 1),
            P50LatencyMs = Percentile(durations, 0.50),
            P95LatencyMs = Percentile(durations, 0.95),
            P99LatencyMs = Percentile(durations, 0.99),
            AuthAttempts = auth.Count,
            AuthSuccesses = auth.Count(e => e.StatusCode == 200),
            AuthFailures = auth.Count(e => e.StatusCode != 200),
            UniqueClients = list.Select(e => e.ClientIp).Where(ip => ip != null).Distinct().Count()
        };
        report.ErrorRate = report.TotalRequests == 0
            ? 0
            : Math.Round((double)(report.ClientErrors + report.ServerErrors) / report.TotalRequests, 4);

        var byBucket = list.GroupBy(e => e.Timestamp.Ticks / bucket.Ticks).ToDictionary(g => g.Key, g => g.ToList());
        for (var t = firstBucket; t <= to; t = t.Add(bucket))
        {
            byBucket.TryGetValue(t.Ticks / bucket.Ticks, out var items);
            items ??= new List<RequestLogEntry>();
            report.Timeline.Add(new TimelineBucket
            {
                BucketStart = t,
                Total = items.Count,
                Errors = items.Count(e => e.StatusCode >= 400),
                AvgLatencyMs = items.Count == 0 ? 0 : Math.Round(items.Average(e => e.DurationMs), 1),
                AuthSuccess = items.Count(e => IsAuthCall(e) && e.StatusCode == 200),
                AuthFailure = items.Count(e => IsAuthCall(e) && e.StatusCode != 200)
            });
        }

        report.ByEndpoint = list
            .GroupBy(e => $"{e.Method} {NormalizePath(e.Path)}")
            .Select(g => new EndpointStat
            {
                Endpoint = g.Key,
                Count = g.Count(),
                Errors = g.Count(e => e.StatusCode >= 400),
                AvgLatencyMs = Math.Round(g.Average(e => e.DurationMs), 1)
            })
            .OrderByDescending(x => x.Count).Take(20).ToList();

        report.ByApiKey = list
            .GroupBy(e => e.ApiKeyId ?? string.Empty)
            .Select(g => new ApiKeyStat
            {
                ApiKeyId = g.Key.Length == 0 ? null : g.Key,
                ApiKeyName = g.Key.Length == 0 ? "(no key)" : g.Last().ApiKeyName,
                Count = g.Count(),
                Errors = g.Count(e => e.StatusCode >= 400),
                LastSeen = g.Max(e => e.Timestamp)
            })
            .OrderByDescending(x => x.Count).Take(20).ToList();

        report.ByClientIp = list
            .GroupBy(e => e.ClientIp ?? "unknown")
            .Select(g => new ClientIpStat { Ip = g.Key, Count = g.Count(), Errors = g.Count(e => e.StatusCode >= 400) })
            .OrderByDescending(x => x.Count).Take(20).ToList();

        report.ByStatusCode = list
            .GroupBy(e => e.StatusCode)
            .Select(g => new StatusCodeStat { StatusCode = g.Key, Count = g.Count() })
            .OrderBy(x => x.StatusCode).ToList();

        report.TopFailedUsers = auth
            .Where(e => e.StatusCode != 200 && !string.IsNullOrEmpty(e.Username))
            .GroupBy(e => e.Username!.ToLowerInvariant())
            .Select(g => new UserCountStat { Username = g.Key, Count = g.Count() })
            .OrderByDescending(x => x.Count).Take(10).ToList();

        return report;
    }

    /// <summary>Server errors (5xx) as a share of requests in the last <paramref name="minutes"/> minutes</summary>
    public (int Total, int ServerErrors) RecentErrorStats(int minutes)
    {
        var cutoff = DateTime.UtcNow.AddMinutes(-minutes);
        var recent = Snapshot().Where(e => e.Timestamp >= cutoff).ToList();
        return (recent.Count, recent.Count(e => e.StatusCode >= 500));
    }

    private static bool IsAuthCall(RequestLogEntry e) =>
        e.Method == "POST" && e.Path.Equals("/api/ldap/authenticate", StringComparison.OrdinalIgnoreCase);

    /// <summary>Collapse per-user paths so they group as one endpoint</summary>
    private static string NormalizePath(string path)
    {
        var p = path.ToLowerInvariant().TrimEnd('/');
        if (!p.StartsWith("/api/ldap/users/") || p == "/api/ldap/users/search") return p;

        var parts = p.Split('/');
        if (parts.Length > 4) parts[4] = "{username}";
        if (parts.Length > 6) parts[6] = "{group}";
        return string.Join('/', parts);
    }

    private static long Percentile(List<long> sorted, double p)
    {
        if (sorted.Count == 0) return 0;
        var index = (int)Math.Ceiling(p * sorted.Count) - 1;
        return sorted[Math.Clamp(index, 0, sorted.Count - 1)];
    }

    #endregion

    #region File persistence

    private string FileFor(DateTime day) => Path.Combine(LogDirectory, $"requests_{day:yyyyMMdd}.jsonl");

    private void LoadRecentFiles()
    {
        try
        {
            var today = DateTime.UtcNow.Date;
            var loaded = new List<RequestLogEntry>();
            foreach (var day in new[] { today.AddDays(-1), today })
            {
                var file = FileFor(day);
                if (!File.Exists(file)) continue;

                foreach (var line in File.ReadLines(file))
                {
                    if (string.IsNullOrWhiteSpace(line)) continue;
                    try
                    {
                        var entry = JsonSerializer.Deserialize<RequestLogEntry>(line, FileJson);
                        if (entry != null) loaded.Add(entry);
                    }
                    catch (JsonException)
                    {
                        // skip partially written line
                    }
                }
            }

            foreach (var entry in loaded.OrderBy(e => e.Timestamp).TakeLast(Capacity))
            {
                _buffer[_next] = entry;
                _next = (_next + 1) % Capacity;
                if (_count < Capacity) _count++;
            }

            if (loaded.Count > 0) _logger.LogInformation("Request log: reloaded {Count} entries from disk", Math.Min(loaded.Count, Capacity));
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not reload request log files");
        }
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var batch = new List<RequestLogEntry>();
        try
        {
            while (await _writeQueue.Reader.WaitToReadAsync(stoppingToken))
            {
                batch.Clear();
                while (batch.Count < 500 && _writeQueue.Reader.TryRead(out var entry)) batch.Add(entry);
                await WriteBatchAsync(batch);
                PurgeOldFiles();
            }
        }
        catch (OperationCanceledException)
        {
            // shutting down: flush what is left
            batch.Clear();
            while (_writeQueue.Reader.TryRead(out var entry)) batch.Add(entry);
            await WriteBatchAsync(batch);
        }
    }

    private async Task WriteBatchAsync(List<RequestLogEntry> batch)
    {
        if (batch.Count == 0) return;
        try
        {
            Directory.CreateDirectory(LogDirectory);
            foreach (var group in batch.GroupBy(e => e.Timestamp.Date))
            {
                var lines = group.Select(e => JsonSerializer.Serialize(e, FileJson));
                await File.AppendAllLinesAsync(FileFor(group.Key), lines);
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning("Failed to write request log to {Dir}: {Error}", LogDirectory, ex.Message);
        }
    }

    private void PurgeOldFiles()
    {
        if (DateTime.UtcNow - _lastPurge < TimeSpan.FromHours(6)) return;
        _lastPurge = DateTime.UtcNow;

        if (_database.Enabled)
        {
            try
            {
                var dbCutoff = DateTime.UtcNow.AddDays(-Math.Max(1, _auditSettings.CurrentValue.RequestLogRetentionDays));
                using var db = _database.CreateContext();
                db.Database.SetCommandTimeout(300);
                var deleted = db.RequestLogs.Where(e => e.Timestamp < dbCutoff).ExecuteDelete();
                if (deleted > 0) _logger.LogInformation("Purged {Count} request log rows older than {Cutoff:u}", deleted, dbCutoff);
            }
            catch (Exception ex)
            {
                _database.ReportError(ex);
                _logger.LogWarning("Failed to purge old request logs from the database: {Error}", ex.GetBaseException().Message);
            }
        }

        try
        {
            var cutoff = DateTime.UtcNow.Date.AddDays(-Math.Max(1, _auditSettings.CurrentValue.RequestLogRetentionDays));
            foreach (var file in Directory.GetFiles(LogDirectory, "requests_*.jsonl"))
            {
                var name = Path.GetFileNameWithoutExtension(file);
                if (DateTime.TryParseExact(name["requests_".Length..], "yyyyMMdd", null,
                        System.Globalization.DateTimeStyles.AssumeUniversal | System.Globalization.DateTimeStyles.AdjustToUniversal, out var day)
                    && day < cutoff)
                {
                    File.Delete(file);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning("Failed to purge old request logs: {Error}", ex.Message);
        }
    }

    #endregion
}
