using AuthenAPI.Models;
using System.Collections.Concurrent;

namespace AuthenAPI.Services;

/// <summary>
/// Process-wide memory of which LDAP connection strategy works, so requests try it first
/// instead of walking through every failing combination on each call.
/// </summary>
public sealed class LdapStrategyCache
{
    private static readonly TimeSpan EndpointDownTtl = TimeSpan.FromMinutes(2);
    private static readonly TimeSpan ServiceAccountBackoff = TimeSpan.FromMinutes(15);

    private readonly ConcurrentDictionary<string, StrategyCounters> _stats = new();
    private readonly ConcurrentDictionary<string, DateTime> _downEndpoints = new();
    private volatile string? _preferred;
    private volatile ServiceAccountBlock? _serviceAccountBlock;

    public string? PreferredStrategy => _preferred;

    public void RecordSuccess(string strategy, string server, int port, bool ssl, bool secure, long latencyMs, bool makePreferred)
    {
        var c = _stats.GetOrAdd(strategy, _ => new StrategyCounters(strategy, server, port, ssl, secure));
        lock (c)
        {
            c.Success++;
            c.LastSuccessAt = DateTime.UtcNow;
            c.TotalLatencyMs += latencyMs;
        }

        _downEndpoints.TryRemove(EndpointKey(server, port, ssl), out _);
        if (makePreferred) _preferred = strategy;
    }

    public void RecordFailure(string strategy, string server, int port, bool ssl, bool secure, long latencyMs, string error, bool endpointDown)
    {
        var c = _stats.GetOrAdd(strategy, _ => new StrategyCounters(strategy, server, port, ssl, secure));
        lock (c)
        {
            c.Failure++;
            c.LastFailureAt = DateTime.UtcNow;
            c.LastError = error;
            c.TotalLatencyMs += latencyMs;
        }

        if (endpointDown)
        {
            _downEndpoints[EndpointKey(server, port, ssl)] = DateTime.UtcNow.Add(EndpointDownTtl);
            if (_preferred == strategy) _preferred = null;
        }
    }

    public bool IsEndpointRecentlyDown(string server, int port, bool ssl) =>
        _downEndpoints.TryGetValue(EndpointKey(server, port, ssl), out var until) && until > DateTime.UtcNow;

    /// <summary>
    /// Remember that AD rejected the service account password so we stop retrying
    /// (each retry counts toward the account's lockout threshold).
    /// </summary>
    public void BlockServiceAccount(string fingerprint, string reason) =>
        _serviceAccountBlock = new ServiceAccountBlock(fingerprint, DateTime.UtcNow.Add(ServiceAccountBackoff), reason);

    public bool IsServiceAccountBlocked(string fingerprint, out DateTime until, out string reason)
    {
        var block = _serviceAccountBlock;
        if (block != null && block.Fingerprint == fingerprint && block.Until > DateTime.UtcNow)
        {
            until = block.Until;
            reason = block.Reason;
            return true;
        }

        until = default;
        reason = string.Empty;
        return false;
    }

    public void Reset()
    {
        _preferred = null;
        _downEndpoints.Clear();
        _serviceAccountBlock = null;
    }

    public List<LdapStrategyStats> GetStats()
    {
        var preferred = _preferred;
        return _stats.Values.Select(c =>
        {
            lock (c)
            {
                var total = c.Success + c.Failure;
                return new LdapStrategyStats
                {
                    Name = c.Name,
                    Server = c.Server,
                    Port = c.Port,
                    Ssl = c.Ssl,
                    Secure = c.Secure,
                    SuccessCount = c.Success,
                    FailureCount = c.Failure,
                    LastSuccessAt = c.LastSuccessAt,
                    LastFailureAt = c.LastFailureAt,
                    LastError = c.LastError,
                    AvgLatencyMs = total == 0 ? 0 : Math.Round((double)c.TotalLatencyMs / total, 1),
                    IsPreferred = c.Name == preferred
                };
            }
        })
        .OrderByDescending(s => s.IsPreferred)
        .ThenByDescending(s => s.SuccessCount)
        .ThenBy(s => s.Name)
        .ToList();
    }

    public LdapStrategyStats? Get(string strategy) => GetStats().FirstOrDefault(s => s.Name == strategy);

    private static string EndpointKey(string server, int port, bool ssl) =>
        $"{server.ToLowerInvariant()}:{port}:{(ssl ? "ssl" : "plain")}";

    private sealed class StrategyCounters
    {
        public StrategyCounters(string name, string server, int port, bool ssl, bool secure)
        {
            Name = name;
            Server = server;
            Port = port;
            Ssl = ssl;
            Secure = secure;
        }

        public string Name { get; }
        public string Server { get; }
        public int Port { get; }
        public bool Ssl { get; }
        public bool Secure { get; }
        public long Success;
        public long Failure;
        public long TotalLatencyMs;
        public DateTime? LastSuccessAt;
        public DateTime? LastFailureAt;
        public string? LastError;
    }

    private sealed record ServiceAccountBlock(string Fingerprint, DateTime Until, string Reason);
}
