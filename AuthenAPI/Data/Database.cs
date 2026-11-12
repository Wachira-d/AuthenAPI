using AuthenAPI.Models;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using System.Diagnostics;
using System.Threading.Channels;

namespace AuthenAPI.Data;

/// <summary>
/// Optional SQL Server storage. Enabled when ConnectionStrings:AuthenAPI is set; otherwise every
/// store keeps using the files in App_Data and logs.
/// </summary>
public sealed class Database
{
    private readonly IDbContextFactory<AuthenDbContext>? _factory;
    private readonly ILogger<Database> _logger;
    private volatile string? _lastError;
    private DateTime? _lastOkAt;

    public Database(IConfiguration configuration, ILogger<Database> logger, IDbContextFactory<AuthenDbContext>? factory = null)
    {
        _logger = logger;
        _factory = factory;
        ConnectionString = configuration.GetConnectionString("AuthenAPI");

        if (Enabled)
        {
            var csb = new SqlConnectionStringBuilder(ConnectionString);
            Server = csb.DataSource;
            DatabaseName = csb.InitialCatalog;
        }
    }

    public string? ConnectionString { get; }
    public bool Enabled => !string.IsNullOrWhiteSpace(ConnectionString) && _factory != null;
    public string? Server { get; }
    public string? DatabaseName { get; }
    public bool SchemaReady { get; private set; }
    public string? LastError => _lastError;
    public DateTime? LastOkAt => _lastOkAt;

    public AuthenDbContext CreateContext()
    {
        if (_factory == null) throw new InvalidOperationException("Database storage is not configured");
        return _factory.CreateDbContext();
    }

    public void ReportOk()
    {
        _lastOkAt = DateTime.UtcNow;
        _lastError = null;
    }

    public void ReportError(Exception ex) => _lastError = ex.GetBaseException().Message;

    /// <summary>
    /// Create missing tables (idempotent). Retries a few times so a DB that starts slower than IIS
    /// does not push the app into file mode. Returns false when the database could not be prepared.
    /// </summary>
    public bool Initialize()
    {
        if (!Enabled) return false;

        var script = ReadSchemaScript();
        for (var attempt = 1; attempt <= 3; attempt++)
        {
            try
            {
                using var db = CreateContext();
                db.Database.SetCommandTimeout(60);
                db.Database.ExecuteSqlRaw(script);
                SchemaReady = true;
                ReportOk();
                _logger.LogInformation("Database storage ready: {Server} / {Database}", Server, DatabaseName);
                return true;
            }
            catch (Exception ex)
            {
                ReportError(ex);
                _logger.LogError("Database initialization attempt {Attempt}/3 failed ({Server} / {Database}): {Error}",
                    attempt, Server, DatabaseName, ex.GetBaseException().Message);
                if (attempt < 3) Thread.Sleep(TimeSpan.FromSeconds(3 * attempt));
            }
        }

        _logger.LogError(
            "Database storage is NOT available. API keys and settings are served from the local cache in App_Data " +
            "(read-only for management changes); logs are kept in files until the database is reachable. " +
            "If the SQL login may not create tables, run Data/DatabaseSchema.sql once as a DBA.");
        return false;
    }

    /// <summary>Round-trip check used by the health monitor</summary>
    public async Task<(bool Ok, long LatencyMs, string? Error)> PingAsync(CancellationToken cancellationToken)
    {
        var sw = Stopwatch.StartNew();
        try
        {
            await using var db = CreateContext();
            await db.Database.ExecuteSqlRawAsync("SELECT 1", cancellationToken);
            if (!SchemaReady) SchemaReady = Initialize();
            ReportOk();
            return (true, sw.ElapsedMilliseconds, null);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            ReportError(ex);
            return (false, sw.ElapsedMilliseconds, ex.GetBaseException().Message);
        }
    }

    public static string ReadSchemaScript()
    {
        using var stream = typeof(Database).Assembly.GetManifestResourceStream("AuthenAPI.Data.DatabaseSchema.sql")
                           ?? throw new InvalidOperationException("Embedded schema script not found");
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }
}

/// <summary>
/// Writes request and audit log entries to the database in batches, off the request path.
/// If the database is down, entries are kept in memory (bounded) and retried; files remain the local copy.
/// </summary>
public sealed class DatabaseLogWriter : BackgroundService
{
    private const int MaxText = 4000;
    private readonly Database _database;
    private readonly ILogger<DatabaseLogWriter> _logger;
    private readonly Channel<object> _queue =
        Channel.CreateBounded<object>(new BoundedChannelOptions(50_000) { FullMode = BoundedChannelFullMode.DropOldest });

    public DatabaseLogWriter(Database database, ILogger<DatabaseLogWriter> logger)
    {
        _database = database;
        _logger = logger;
    }

    public void Enqueue(RequestLogEntry entry)
    {
        if (_database.Enabled) _queue.Writer.TryWrite(entry);
    }

    public void Enqueue(AuditLog entry)
    {
        if (_database.Enabled) _queue.Writer.TryWrite(entry);
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!_database.Enabled) return;

        var batch = new List<object>();
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                if (batch.Count == 0 && !await _queue.Reader.WaitToReadAsync(stoppingToken)) break;
                while (batch.Count < 1000 && _queue.Reader.TryRead(out var item)) batch.Add(item);

                await WriteAsync(batch, stoppingToken);
                batch.Clear();
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _database.ReportError(ex);
                _logger.LogWarning("Could not write {Count} log entries to the database, retrying in 15s: {Error}",
                    batch.Count, ex.GetBaseException().Message);
                if (batch.Count > 20_000) batch.RemoveRange(0, batch.Count - 20_000);
                try { await Task.Delay(TimeSpan.FromSeconds(15), stoppingToken); }
                catch (OperationCanceledException) { break; }
            }
        }

        // Final flush on shutdown (best effort).
        while (_queue.Reader.TryRead(out var item)) batch.Add(item);
        if (batch.Count > 0)
        {
            try { await WriteAsync(batch, CancellationToken.None); }
            catch (Exception ex) { _logger.LogWarning("Dropped {Count} log entries at shutdown: {Error}", batch.Count, ex.GetBaseException().Message); }
        }
    }

    private async Task WriteAsync(List<object> batch, CancellationToken cancellationToken)
    {
        if (batch.Count == 0) return;

        await using var db = _database.CreateContext();
        db.ChangeTracker.AutoDetectChangesEnabled = false;
        foreach (var item in batch)
        {
            switch (item)
            {
                case RequestLogEntry r:
                    db.RequestLogs.Add(Clean(r));
                    break;
                case AuditLog a:
                    db.AuditLogs.Add(Clean(a));
                    break;
            }
        }
        await db.SaveChangesAsync(cancellationToken);
        _database.ReportOk();
    }

    private static RequestLogEntry Clean(RequestLogEntry e) => new()
    {
        Id = e.Id,
        Timestamp = e.Timestamp,
        Method = Cut(e.Method, 16) ?? string.Empty,
        Path = Cut(e.Path, 600) ?? string.Empty,
        QueryString = Cut(e.QueryString, MaxText),
        StatusCode = e.StatusCode,
        DurationMs = e.DurationMs,
        ClientIp = Cut(e.ClientIp, 64),
        UserAgent = Cut(e.UserAgent, MaxText),
        ApiKeyId = Cut(e.ApiKeyId, 40),
        ApiKeyName = Cut(e.ApiKeyName, 200),
        Username = Cut(e.Username, 256),
        Outcome = Cut(e.Outcome, 100),
        ErrorMessage = Cut(e.ErrorMessage, MaxText),
        TraceId = Cut(e.TraceId, 100),
        LdapStrategy = Cut(e.LdapStrategy, 100)
    };

    private static AuditLog Clean(AuditLog a) => new()
    {
        Id = a.Id,
        Timestamp = a.Timestamp,
        Action = a.Action,
        Username = Cut(a.Username, 256),
        Success = a.Success,
        IpAddress = Cut(a.IpAddress, 64),
        UserAgent = Cut(a.UserAgent, MaxText),
        Details = Cut(a.Details, MaxText),
        DurationMs = a.DurationMs,
        RequestPath = Cut(a.RequestPath, MaxText),
        HttpMethod = Cut(a.HttpMethod, 16),
        StatusCode = a.StatusCode
    };

    private static string? Cut(string? value, int max) => value == null || value.Length <= max ? value : value[..max];
}
