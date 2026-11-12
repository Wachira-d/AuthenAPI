using AuthenAPI.Models;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using System.Diagnostics;
using System.DirectoryServices.AccountManagement;
using System.DirectoryServices.Protocols;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace AuthenAPI.Services;

/// <summary>
/// Active Directory access over LDAP / LDAPS.
///
/// Authentication flow (designed so a wrong password costs AD exactly one bad-password count):
///   1. Bind as the service account (cached working strategy first) and look the user up
///      by sAMAccountName / userPrincipalName / mail.
///   2. Bind once as the user with the directory's own UPN (or DN).
///   3. Only if the directory cannot be searched, fall back to direct binds with a few
///      username formats, stopping at the first definitive answer from AD.
///   4. Only if every LDAP endpoint is unreachable, try Windows PrincipalContext once.
/// </summary>
public partial class LdapService : ILdapService
{
    private static readonly SemaphoreSlim ConnectionLock = new(20, 20);
    private static readonly TimeSpan SearchTimeout = TimeSpan.FromSeconds(5);

    private const string UserCachePrefix = "ldap_user_";
    private const string GroupsCachePrefix = "ldap_groups_";

    private static readonly string[] UserAttributes =
    {
        "distinguishedName", "sAMAccountName", "userPrincipalName",
        "displayName", "givenName", "sn", "mail", "department",
        "title", "physicalDeliveryOfficeName", "telephoneNumber",
        "mobile", "manager", "employeeID", "company",
        "userAccountControl", "lockoutTime", "memberOf",
        "whenCreated", "whenChanged", "lastLogonTimestamp"
    };

    private static readonly string[] SearchAttributes =
    {
        "distinguishedName", "sAMAccountName", "userPrincipalName",
        "displayName", "mail", "department", "memberOf",
        "userAccountControl", "lockoutTime"
    };

    private readonly LdapSettings _settings;
    private readonly ILogger<LdapService> _logger;
    private readonly IMemoryCache _cache;
    private readonly LdapStrategyCache _strategyCache;

    public LdapService(
        IOptionsSnapshot<LdapSettings> settings,
        ILogger<LdapService> logger,
        IMemoryCache cache,
        LdapStrategyCache strategyCache)
    {
        _settings = settings.Value;
        _logger = logger;
        _cache = cache;
        _strategyCache = strategyCache;
    }

    #region Public API

    /// <inheritdoc />
    public async Task<UserInfo?> AuthenticateAsync(string username, string password)
    {
        var result = await AuthenticateWithResultAsync(username, password);
        return result.Success ? result.User : null;
    }

    /// <inheritdoc />
    public async Task<LdapAuthResult> AuthenticateWithResultAsync(string username, string password)
    {
        if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password))
        {
            // An empty password would be an "unauthenticated bind", which AD reports as success.
            return LdapAuthResult.Fail(AuthFailureReason.InvalidCredentials, "Username and password are required");
        }

        var stopwatch = Stopwatch.StartNew();
        await ConnectionLock.WaitAsync();
        try
        {
            var result = await Task.Run(() => AuthenticateCore(username.Trim(), password));
            result.DurationMs = stopwatch.ElapsedMilliseconds;

            if (result.Success)
            {
                _logger.LogInformation(
                    "=== Authentication succeeded for {Username} via {Method} ({Strategy}) in {Ms}ms ===",
                    username, result.Method, result.Strategy, result.DurationMs);
            }
            else
            {
                _logger.LogWarning(
                    "=== Authentication failed for {Username}: {Reason} ({Message}) in {Ms}ms ===",
                    username, result.FailureReason, result.Message, result.DurationMs);
            }

            return result;
        }
        finally
        {
            ConnectionLock.Release();
        }
    }

    /// <inheritdoc />
    public async Task<bool> TestConnectionAsync() => (await ProbeAsync()).Ok;

    /// <inheritdoc />
    public async Task<LdapProbeResult> ProbeAsync(bool reevaluate = false, CancellationToken cancellationToken = default)
    {
        await ConnectionLock.WaitAsync(cancellationToken);
        try
        {
            return await Task.Run(() =>
            {
                var sw = Stopwatch.StartNew();
                var outcome = ConnectServiceAccount(_settings, honorBackoff: true, recordStats: true, ignorePreferred: reevaluate);
                outcome.Connection?.Dispose();

                return new LdapProbeResult
                {
                    Ok = outcome.Success,
                    Strategy = outcome.Strategy?.Name,
                    Secure = outcome.Strategy?.Secure ?? false,
                    LatencyMs = sw.ElapsedMilliseconds,
                    Error = outcome.Success ? null : outcome.ErrorMessage,
                    FailureReason = outcome.FailureReason
                };
            }, cancellationToken);
        }
        finally
        {
            ConnectionLock.Release();
        }
    }

    /// <inheritdoc />
    public async Task<LdapTestResult> TestSettingsAsync(LdapSettings candidate)
    {
        await ConnectionLock.WaitAsync();
        try
        {
            return await Task.Run(() =>
            {
                var sw = Stopwatch.StartNew();
                var attempts = new List<LdapAttempt>();
                var outcome = ConnectServiceAccount(candidate, honorBackoff: false, recordStats: false,
                    ignorePreferred: true, attempts: attempts);

                var result = new LdapTestResult { Attempts = attempts };
                if (!outcome.Success)
                {
                    result.Success = false;
                    result.Error = outcome.ErrorMessage;
                    result.LatencyMs = sw.ElapsedMilliseconds;
                    return result;
                }

                using (outcome.Connection)
                {
                    // Bind worked; make sure the Base DN exists too.
                    try
                    {
                        var request = new System.DirectoryServices.Protocols.SearchRequest(
                            candidate.BaseDN, "(objectClass=*)", SearchScope.Base, "distinguishedName");
                        outcome.Connection!.SendRequest(request, SearchTimeout);
                        result.Success = true;
                    }
                    catch (Exception ex)
                    {
                        result.Success = false;
                        result.Error = $"Service account bind succeeded, but Base DN '{candidate.BaseDN}' could not be read: {ex.Message}";
                    }
                }

                result.Strategy = outcome.Strategy?.Name;
                result.LatencyMs = sw.ElapsedMilliseconds;
                return result;
            });
        }
        finally
        {
            ConnectionLock.Release();
        }
    }

    /// <inheritdoc />
    public async Task<ConnectionTestResult> TestConnectionDetailedAsync()
    {
        await ConnectionLock.WaitAsync();
        try
        {
            return await Task.Run(RunDiagnostics);
        }
        finally
        {
            ConnectionLock.Release();
        }
    }

    /// <inheritdoc />
    public async Task<UserInfo?> GetUserAsync(string username)
    {
        if (string.IsNullOrWhiteSpace(username)) return null;

        var cacheKey = $"{UserCachePrefix}{username.ToLowerInvariant()}";
        if (_settings.EnableCache && _cache.TryGetValue(cacheKey, out UserInfo? cachedUser))
        {
            return cachedUser;
        }

        await ConnectionLock.WaitAsync();
        try
        {
            return await Task.Run(() =>
            {
                var service = ConnectServiceAccount(_settings, honorBackoff: true, recordStats: true);
                if (!service.Success)
                {
                    _logger.LogError("Cannot look up {Username}: {Error}", username, service.ErrorMessage);
                    return null;
                }

                using (service.Connection)
                {
                    try
                    {
                        var user = SearchUser(service.Connection!, _settings, username, out _);
                        if (user != null) CacheUserInfo(username, user);
                        return user;
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Error getting user: {Username}", username);
                        return null;
                    }
                }
            });
        }
        finally
        {
            ConnectionLock.Release();
        }
    }

    /// <inheritdoc />
    public async Task<List<UserInfo>> SearchUsersAsync(Models.SearchRequest request)
    {
        await ConnectionLock.WaitAsync();
        try
        {
            return await Task.Run(() =>
            {
                var users = new List<UserInfo>();
                var service = ConnectServiceAccount(_settings, honorBackoff: true, recordStats: true);
                if (!service.Success)
                {
                    _logger.LogError("Cannot search users: {Error}", service.ErrorMessage);
                    return users;
                }

                using (service.Connection)
                {
                    try
                    {
                        string filter;
                        if (!string.IsNullOrEmpty(request.Query))
                        {
                            var q = EscapeLdapFilter(request.Query);
                            filter = $"(&(objectClass=user)(objectCategory=person)(|(displayName=*{q}*)(sAMAccountName=*{q}*)(mail=*{q}*)(givenName=*{q}*)(sn=*{q}*)))";
                        }
                        else
                        {
                            filter = "(&(objectClass=user)(objectCategory=person))";
                        }

                        var searchRequest = new System.DirectoryServices.Protocols.SearchRequest(
                            _settings.BaseDN, filter, SearchScope.Subtree, SearchAttributes)
                        {
                            SizeLimit = request.MaxResults,
                            TimeLimit = TimeSpan.FromSeconds(Math.Max(1, _settings.ConnectionTimeout))
                        };

                        var response = (SearchResponse)service.Connection!.SendRequest(searchRequest, SearchTimeout);
                        foreach (SearchResultEntry entry in response.Entries)
                        {
                            users.Add(MapEntryToUserInfo(entry));
                            if (users.Count >= request.MaxResults) break;
                        }
                    }
                    catch (DirectoryOperationException ex) when (ex.Response is SearchResponse partial)
                    {
                        // Size limit exceeded: return what we have.
                        foreach (SearchResultEntry entry in partial.Entries)
                        {
                            if (users.Count >= request.MaxResults) break;
                            users.Add(MapEntryToUserInfo(entry));
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Error searching users with query: {Query}", request.Query);
                    }
                }

                return users;
            });
        }
        finally
        {
            ConnectionLock.Release();
        }
    }

    /// <inheritdoc />
    public async Task<List<string>> GetUserGroupsAsync(string username)
    {
        if (string.IsNullOrWhiteSpace(username)) return new List<string>();

        var cacheKey = $"{GroupsCachePrefix}{username.ToLowerInvariant()}";
        if (_settings.EnableCache && _cache.TryGetValue(cacheKey, out List<string>? cachedGroups))
        {
            return cachedGroups ?? new List<string>();
        }

        var user = await GetUserAsync(username);
        var groups = user?.Groups.ToList() ?? new List<string>();

        if (user != null && _settings.EnableCache)
        {
            _cache.Set(cacheKey, groups, new MemoryCacheEntryOptions()
                .SetAbsoluteExpiration(TimeSpan.FromMinutes(_settings.CacheDurationMinutes))
                .SetSize(1));
        }

        return groups;
    }

    /// <inheritdoc />
    public async Task<bool> IsUserInGroupAsync(string username, string groupName)
    {
        if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(groupName)) return false;

        var groups = await GetUserGroupsAsync(username);
        return groups.Any(g => g.Equals(groupName, StringComparison.OrdinalIgnoreCase));
    }

    /// <inheritdoc />
    public void ClearCache()
    {
        if (_cache is MemoryCache memoryCache)
        {
            memoryCache.Compact(1.0);
        }
    }

    #endregion

    #region Authentication core

    private LdapAuthResult AuthenticateCore(string username, string password)
    {
        var s = _settings;
        _logger.LogInformation("=== Starting Authentication for: {Username} ({Format}) ===",
            username, DetectUsernameFormat(username));

        // The service account is not a user login: refusing it here also stops anyone holding an
        // API key from locking it out (which would force every login onto the fallback path).
        if (!string.IsNullOrEmpty(s.ServiceAccountUsername) &&
            ExtractSamAccountName(username).Equals(ExtractSamAccountName(s.ServiceAccountUsername), StringComparison.OrdinalIgnoreCase))
        {
            return LdapAuthResult.Fail(AuthFailureReason.InvalidCredentials, "The service account cannot be used to sign in");
        }

        // Step 1: resolve the user with the service account.
        UserInfo? directoryUser = null;
        var lookupCompleted = false;

        var service = ConnectServiceAccount(s, honorBackoff: true, recordStats: true);
        if (service.Success)
        {
            using (service.Connection)
            {
                try
                {
                    directoryUser = SearchUser(service.Connection!, s, username, out var referralsOnly);
                    lookupCompleted = !referralsOnly;
                    if (referralsOnly)
                    {
                        _logger.LogWarning(
                            "Search for {Username} returned only referrals. Enable ChaseReferrals or use a Global Catalog port.",
                            username);
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning("User lookup failed for {Username} ({Error}); falling back to direct bind",
                        username, ex.Message);
                }
            }
        }
        else
        {
            _logger.LogWarning("Service account unavailable ({Error}); falling back to direct bind", service.ErrorMessage);
        }

        if (directoryUser == null && lookupCompleted)
        {
            // Nothing to bind to: answering here costs no bad-password count in AD.
            return LdapAuthResult.Fail(AuthFailureReason.UserNotFound, "User not found in directory");
        }

        // Step 2: bind once as the user found in the directory.
        if (directoryUser != null)
        {
            if (!directoryUser.IsEnabled)
            {
                return WithMethod(LdapAuthResult.Fail(AuthFailureReason.AccountDisabled, "Account is disabled"), "SearchThenBind");
            }

            var bindNames = new[] { directoryUser.UserPrincipalName, directoryUser.DistinguishedName }
                .Where(n => !string.IsNullOrWhiteSpace(n))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();

            var bind = TryBind(s, BuildStrategies(s, includeNegotiate: true), bindNames, password,
                serviceFingerprint: null, attempts: null, recordStats: true);

            if (!bind.Success)
            {
                var message = bind.ErrorMessage;
                if (directoryUser.IsLocked && bind.FailureReason == AuthFailureReason.InvalidCredentials)
                {
                    message += " (the account has lockoutTime set: it may be locked out)";
                }
                return WithMethod(LdapAuthResult.Fail(bind.FailureReason, message), "SearchThenBind", bind.Strategy?.Name);
            }

            bind.Connection?.Dispose();
            CacheAuthenticatedUser(directoryUser);
            return new LdapAuthResult
            {
                Success = true,
                User = directoryUser,
                Method = "SearchThenBind",
                Strategy = bind.Strategy?.Name
            };
        }

        // Step 3: the directory could not be searched; try direct binds (simple binds report AD sub-codes reliably).
        var formats = GetUsernameFormats(s, username);
        var direct = TryBind(s, BuildStrategies(s, includeNegotiate: false), formats, password,
            serviceFingerprint: null, attempts: null, recordStats: true);

        if (direct.Success)
        {
            UserInfo? user = null;
            using (direct.Connection)
            {
                try
                {
                    // Authenticated users can normally read their own entry.
                    user = SearchUser(direct.Connection!, s, username, out _);
                }
                catch (Exception ex)
                {
                    _logger.LogDebug("Could not read own entry after direct bind: {Error}", ex.Message);
                }
            }

            user ??= BasicUserInfo(username, direct.BoundAs);
            CacheAuthenticatedUser(user);
            return new LdapAuthResult { Success = true, User = user, Method = "DirectBind", Strategy = direct.Strategy?.Name };
        }

        if (direct.ReachedDirectory)
        {
            return WithMethod(LdapAuthResult.Fail(direct.FailureReason, direct.ErrorMessage), "DirectBind", direct.Strategy?.Name);
        }

        // Step 4: no LDAP endpoint answered at all; Windows PrincipalContext is the last resort.
        return TryPrincipalContext(s, username, password);
    }

    private LdapAuthResult TryPrincipalContext(LdapSettings s, string username, string password)
    {
        if (!OperatingSystem.IsWindows())
        {
            return LdapAuthResult.Fail(AuthFailureReason.ServerUnavailable, "No domain controller could be reached");
        }

        foreach (var server in Servers(s))
        {
            try
            {
                using var context = new PrincipalContext(ContextType.Domain, server);
                // Exactly one attempt: the default overload silently retries with other bind types.
                var valid = context.ValidateCredentials(username, password,
                    ContextOptions.Negotiate | ContextOptions.Signing | ContextOptions.Sealing);

                if (!valid)
                {
                    return WithMethod(LdapAuthResult.Fail(AuthFailureReason.InvalidCredentials, "Rejected by PrincipalContext"),
                        "PrincipalContext", server);
                }

                var user = BasicUserInfo(username, username);
                CacheAuthenticatedUser(user);
                return new LdapAuthResult { Success = true, User = user, Method = "PrincipalContext", Strategy = server };
            }
            catch (Exception ex)
            {
                _logger.LogWarning("PrincipalContext fallback failed on {Server}: {Error}", server, ex.Message);
            }
        }

        return LdapAuthResult.Fail(AuthFailureReason.ServerUnavailable, "No domain controller could be reached");
    }

    private static LdapAuthResult WithMethod(LdapAuthResult result, string method, string? strategy = null)
    {
        result.Method = method;
        result.Strategy = strategy;
        return result;
    }

    #endregion

    #region Connections and strategies

    private sealed record Strategy(string Name, string Server, int Port, bool Ssl, AuthType Auth, bool Seal)
    {
        public bool Secure => Ssl || Seal;
        public string EndpointKey => $"{Server.ToLowerInvariant()}:{Port}:{(Ssl ? "ssl" : "plain")}";
    }

    private sealed class BindOutcome
    {
        public bool Success { get; init; }
        public LdapConnection? Connection { get; init; }
        public Strategy? Strategy { get; init; }
        public string? BoundAs { get; init; }
        public AuthFailureReason FailureReason { get; init; }
        public string? ErrorMessage { get; init; }

        /// <summary>True when a DC answered (so credentials, not connectivity, decided the result)</summary>
        public bool ReachedDirectory { get; init; }
    }

    private static IEnumerable<string> Servers(LdapSettings s) =>
        new[] { s.Server }.Concat(s.FallbackServers ?? new List<string>())
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Select(x => x.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Ordered connection strategies: the cached working one first, then the configured
    /// port, then the most secure transports, then plain-text ones.
    /// </summary>
    private List<Strategy> BuildStrategies(LdapSettings s, bool includeNegotiate, bool ignorePreferred = false)
    {
        var transports = new List<(int Port, bool Ssl, AuthType Auth, bool Seal)>
        {
            (s.Port, s.UseSSL, AuthType.Basic, false),
            (636, true, AuthType.Basic, false),
            (3269, true, AuthType.Basic, false)
        };
        if (includeNegotiate) transports.Add((389, false, AuthType.Negotiate, true));
        transports.Add((636, false, AuthType.Basic, false));
        transports.Add((389, false, AuthType.Basic, false));
        transports.Add((3268, false, AuthType.Basic, false));

        var strategies = new List<Strategy>();
        var primary = true;
        foreach (var server in Servers(s))
        {
            foreach (var t in transports.Distinct())
            {
                var label = TransportLabel(t.Port, t.Ssl, t.Seal);
                strategies.Add(new Strategy(primary ? label : $"{label}@{server}", server, t.Port, t.Ssl, t.Auth, t.Seal));
            }
            primary = false;
        }

        if (!AllowsInsecure(s))
        {
            strategies.RemoveAll(st => !st.Secure);
        }

        var preferred = ignorePreferred ? null : _strategyCache.PreferredStrategy;

        // OrderBy is stable, so the declared order is kept within each group.
        return strategies
            .OrderBy(st => st.Name == preferred ? 0 : 1)
            .ThenBy(st => _strategyCache.IsEndpointRecentlyDown(st.Server, st.Port, st.Ssl) ? 1 : 0)
            .ToList();
    }

    /// <summary>
    /// Clear-text simple binds are only allowed when the admin chose plain LDAP (UseSSL=false)
    /// or explicitly opted in. Otherwise a TLS failure (e.g. an attacker's certificate) must not
    /// silently downgrade to sending passwords in clear text.
    /// </summary>
    private static bool AllowsInsecure(LdapSettings s) => !s.UseSSL || s.AllowInsecureFallback;

    private static string TransportLabel(int port, bool ssl, bool seal) => (port, ssl, seal) switch
    {
        (636, true, _) => "LDAPS-636",
        (3269, true, _) => "GC-SSL-3269",
        (389, false, true) => "LDAP-389-Sealed",
        (636, false, _) => "LDAP-636-NoSSL",
        (389, false, false) => "LDAP-389",
        (3268, false, _) => "GC-3268",
        _ => $"{(ssl ? "LDAPS" : "LDAP")}-{port}{(seal ? "-Sealed" : "")}"
    };

    private BindOutcome ConnectServiceAccount(LdapSettings s, bool honorBackoff, bool recordStats,
        bool ignorePreferred = false, List<LdapAttempt>? attempts = null)
    {
        if (string.IsNullOrWhiteSpace(s.ServiceAccountUsername) || string.IsNullOrEmpty(s.ServiceAccountPassword))
        {
            return new BindOutcome
            {
                FailureReason = AuthFailureReason.Error,
                ErrorMessage = "Service account username or password is not configured"
            };
        }

        var fingerprint = ServiceFingerprint(s);
        if (honorBackoff && _strategyCache.IsServiceAccountBlocked(fingerprint, out var until, out var reason))
        {
            return new BindOutcome
            {
                FailureReason = AuthFailureReason.InvalidCredentials,
                ReachedDirectory = true,
                ErrorMessage = $"Service account sign-in paused until {until:HH:mm} UTC because AD rejected its password " +
                               $"({reason}). Retrying would lock the account. Update the password in Settings > LDAP."
            };
        }

        return TryBind(s, BuildStrategies(s, includeNegotiate: true, ignorePreferred), ServiceAccountNames(s),
            s.ServiceAccountPassword, fingerprint, attempts, recordStats);
    }

    /// <summary>
    /// Try strategies (outer) and bind names (inner) until one binds or AD gives a definitive answer.
    /// </summary>
    private BindOutcome TryBind(
        LdapSettings s,
        IReadOnlyList<Strategy> strategies,
        IReadOnlyList<string> names,
        string password,
        string? serviceFingerprint,
        List<LdapAttempt>? attempts,
        bool recordStats)
    {
        var downEndpoints = new HashSet<string>();
        var errors = new List<string>();
        var reachedDirectory = false;
        var lastReason = AuthFailureReason.ServerUnavailable;
        Strategy? lastStrategy = null;

        foreach (var strategy in strategies)
        {
            if (downEndpoints.Contains(strategy.EndpointKey)) continue;

            // Negotiate needs a principal name (UPN or DOMAIN\user), not a DN.
            var candidateNames = strategy.Auth == AuthType.Negotiate
                ? names.Where(n => !n.Contains('=')).ToList()
                : names.ToList();

            var allNotFound = candidateNames.Count > 0;

            foreach (var name in candidateNames)
            {
                var sw = Stopwatch.StartNew();
                lastStrategy = strategy;
                try
                {
                    var connection = CreateConnection(s, strategy, name, password);
                    sw.Stop();

                    if (recordStats)
                    {
                        _strategyCache.RecordSuccess(strategy.Name, strategy.Server, strategy.Port, strategy.Ssl,
                            strategy.Secure, sw.ElapsedMilliseconds, makePreferred: serviceFingerprint != null);
                    }
                    attempts?.Add(new LdapAttempt { Strategy = $"{strategy.Name} as {name}", Success = true, LatencyMs = sw.ElapsedMilliseconds });
                    _logger.LogInformation("✓ LDAP bind OK - {Strategy} ({Server}:{Port}, secure={Secure}) as {Name} in {Ms}ms",
                        strategy.Name, strategy.Server, strategy.Port, strategy.Secure, name, sw.ElapsedMilliseconds);

                    return new BindOutcome { Success = true, Connection = connection, Strategy = strategy, BoundAs = name, ReachedDirectory = true };
                }
                catch (LdapException ex)
                {
                    sw.Stop();
                    var description = DescribeLdapError(ex);
                    attempts?.Add(new LdapAttempt { Strategy = $"{strategy.Name} as {name}", Success = false, Error = description, LatencyMs = sw.ElapsedMilliseconds });

                    // A sealed (Kerberos/NTLM) bind can fail with 81 for SASL reasons while plain binds on the
                    // same port still work, so it never marks the endpoint itself as down.
                    if (IsConnectivityError(ex.ErrorCode) && strategy.Seal)
                    {
                        Record(false, strategy, sw.ElapsedMilliseconds, description, endpointDown: false);
                        errors.Add($"{strategy.Name}: {description}");
                        _logger.LogWarning("✗ {Strategy}: {Error}", strategy.Name, description);
                        allNotFound = false;
                        break;
                    }

                    if (IsConnectivityError(ex.ErrorCode))
                    {
                        downEndpoints.Add(strategy.EndpointKey);
                        Record(false, strategy, sw.ElapsedMilliseconds, description, endpointDown: true);
                        errors.Add($"{strategy.Name}: {description}");
                        _logger.LogWarning("✗ {Strategy}: {Error}", strategy.Name, description);
                        allNotFound = false;
                        break; // next strategy: this endpoint is unreachable for every name
                    }

                    if (ex.ErrorCode == 49)
                    {
                        reachedDirectory = true;
                        var reason = MapAdError(ex.ServerErrorMessage);
                        Record(false, strategy, sw.ElapsedMilliseconds, description, endpointDown: false);

                        if (reason == AuthFailureReason.UserNotFound)
                        {
                            lastReason = reason;
                            continue; // this name format doesn't exist: try the next one (no lockout cost)
                        }

                        // Definitive answer about an existing account. Stop now: every further
                        // attempt would add another bad-password count toward AD lockout.
                        if (serviceFingerprint != null)
                        {
                            _strategyCache.BlockServiceAccount(serviceFingerprint, $"{reason}: {description}");
                        }
                        _logger.LogWarning("✗ {Strategy} as {Name}: {Reason} - stopping to avoid account lockout",
                            strategy.Name, name, reason);

                        return new BindOutcome
                        {
                            FailureReason = reason,
                            ErrorMessage = description,
                            Strategy = strategy,
                            ReachedDirectory = true
                        };
                    }

                    // Transport/auth level problem (e.g. signing required, auth method not supported).
                    Record(false, strategy, sw.ElapsedMilliseconds, description, endpointDown: false);
                    errors.Add($"{strategy.Name}: {description}");
                    _logger.LogWarning("✗ {Strategy}: {Error}", strategy.Name, description);
                    allNotFound = false;
                    break;
                }
                catch (Exception ex)
                {
                    sw.Stop();
                    var description = $"{ex.GetType().Name}: {ex.Message}";
                    attempts?.Add(new LdapAttempt { Strategy = $"{strategy.Name} as {name}", Success = false, Error = description, LatencyMs = sw.ElapsedMilliseconds });
                    Record(false, strategy, sw.ElapsedMilliseconds, description, endpointDown: false);
                    errors.Add($"{strategy.Name}: {description}");
                    _logger.LogWarning("✗ {Strategy}: {Error}", strategy.Name, description);
                    allNotFound = false;
                    break;
                }
            }

            if (allNotFound && reachedDirectory)
            {
                // Every name format was unknown to a DC that answered: other transports reach the same directory.
                return new BindOutcome
                {
                    FailureReason = AuthFailureReason.UserNotFound,
                    ErrorMessage = "No matching account for any username format",
                    Strategy = strategy,
                    ReachedDirectory = true
                };
            }
        }

        return new BindOutcome
        {
            FailureReason = reachedDirectory ? lastReason : AuthFailureReason.ServerUnavailable,
            ErrorMessage = errors.Count > 0 ? string.Join("; ", errors) : "No connection strategy succeeded",
            Strategy = lastStrategy,
            ReachedDirectory = reachedDirectory
        };

        void Record(bool ok, Strategy st, long ms, string error, bool endpointDown)
        {
            if (!recordStats) return;
            _strategyCache.RecordFailure(st.Name, st.Server, st.Port, st.Ssl, st.Secure, ms, error, endpointDown);
        }
    }

    private static LdapConnection CreateConnection(LdapSettings s, Strategy strategy, string username, string password)
    {
        var connection = new LdapConnection(new LdapDirectoryIdentifier(strategy.Server, strategy.Port))
        {
            AuthType = strategy.Auth,
            AutoBind = false,
            Timeout = TimeSpan.FromSeconds(Math.Max(1, s.ConnectionTimeout)),
            Credential = MakeCredential(username, password)
        };

        try
        {
            connection.SessionOptions.ProtocolVersion = 3;
            connection.SessionOptions.ReferralChasing = s.ChaseReferrals ? ReferralChasingOptions.All : ReferralChasingOptions.None;

            if (strategy.Ssl)
            {
                connection.SessionOptions.SecureSocketLayer = true;
                if (s.SkipCertificateValidation)
                {
                    connection.SessionOptions.VerifyServerCertificate = (_, _) => true;
                }
            }

            if (strategy.Seal)
            {
                connection.SessionOptions.Signing = true;
                connection.SessionOptions.Sealing = true;
            }

            connection.Bind();
            return connection;
        }
        catch
        {
            connection.Dispose();
            throw;
        }
    }

    private static NetworkCredential MakeCredential(string username, string password)
    {
        var slash = username.IndexOf('\\');
        return slash > 0
            ? new NetworkCredential(username[(slash + 1)..], password, username[..slash])
            : new NetworkCredential(username, password);
    }

    private static bool IsConnectivityError(int code) => code is 52 or 81 or 85 or 91;

    private static string DescribeLdapError(LdapException ex)
    {
        var detail = string.IsNullOrWhiteSpace(ex.ServerErrorMessage) ? string.Empty : $" [{ex.ServerErrorMessage.Trim().TrimEnd('\0')}]";
        return $"LDAP {ex.ErrorCode}: {ex.Message}{detail}";
    }

    [GeneratedRegex(@"data\s+([0-9a-fA-F]{3,4})")]
    private static partial Regex AdDataCodeRegex();

    /// <summary>
    /// Translate the AD "data xxx" sub-code of an LDAP 49 error. Unknown → InvalidCredentials (fail safe).
    /// </summary>
    internal static AuthFailureReason MapAdError(string? serverMessage)
    {
        if (string.IsNullOrEmpty(serverMessage)) return AuthFailureReason.InvalidCredentials;

        var match = AdDataCodeRegex().Match(serverMessage);
        if (!match.Success) return AuthFailureReason.InvalidCredentials;

        return match.Groups[1].Value.ToLowerInvariant() switch
        {
            "525" => AuthFailureReason.UserNotFound,
            "52e" => AuthFailureReason.InvalidCredentials,
            "530" or "531" => AuthFailureReason.LogonNotPermitted,
            "532" => AuthFailureReason.PasswordExpired,
            "533" => AuthFailureReason.AccountDisabled,
            "701" => AuthFailureReason.AccountExpired,
            "773" => AuthFailureReason.PasswordMustChange,
            "775" => AuthFailureReason.AccountLocked,
            _ => AuthFailureReason.InvalidCredentials
        };
    }

    private static string ServiceFingerprint(LdapSettings s)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes($"{s.Server}|{s.ServiceAccountUsername}|{s.ServiceAccountPassword}"));
        return Convert.ToHexString(bytes, 0, 8);
    }

    private static string NetBios(LdapSettings s) =>
        !string.IsNullOrWhiteSpace(s.NetBiosDomain)
            ? s.NetBiosDomain.Trim()
            : (s.Domain.Split('.').FirstOrDefault() ?? string.Empty).ToUpperInvariant();

    private static List<string> ServiceAccountNames(LdapSettings s)
    {
        var name = s.ServiceAccountUsername.Trim();
        var names = new List<string>();
        if (name.Contains('@') || name.Contains('\\') || name.Contains('=')) names.Add(name);

        var sam = ExtractSamAccountName(name);
        if (!name.Contains('=') && !string.IsNullOrEmpty(sam))
        {
            if (!string.IsNullOrEmpty(s.Domain)) names.Add($"{sam}@{s.Domain}");
            if (!string.IsNullOrEmpty(NetBios(s))) names.Add($"{NetBios(s)}\\{sam}");
        }

        return names.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }

    /// <summary>
    /// Username formats for direct binds when the directory cannot be searched.
    /// Supports email/UPN (user@domain), Pre-Windows 2000 (DOMAIN\user) and plain sAMAccountName.
    /// </summary>
    private static List<string> GetUsernameFormats(LdapSettings s, string username)
    {
        // Only this domain's canonical names. Binding with the raw input ("OTHER\\user", "user@other")
        // could authenticate an account in a trusted domain while the user record is then read from
        // this domain by sAMAccountName, mixing up identities. Canonical forms are also what AD
        // resolves reliably: an unresolvable name returns the same "data 52e" as a wrong password.
        var sam = ExtractSamAccountName(username);
        var formats = new List<string>();
        if (!string.IsNullOrEmpty(NetBios(s))) formats.Add($"{NetBios(s)}\\{sam}");
        if (!string.IsNullOrEmpty(s.Domain)) formats.Add($"{sam}@{s.Domain}");
        return formats.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }

    #endregion

    #region Diagnostics

    private ConnectionTestResult RunDiagnostics()
    {
        var s = _settings;
        var stopwatch = Stopwatch.StartNew();
        var result = new ConnectionTestResult
        {
            Server = s.Server,
            ConfiguredPort = s.Port,
            TestStartTime = DateTime.UtcNow
        };

        _logger.LogInformation("=== Starting LDAP diagnostics for {Server} (service account {Account}) ===",
            s.Server, s.ServiceAccountUsername);

        if (string.IsNullOrEmpty(s.ServiceAccountPassword))
        {
            result.Hints.Add("Service account password is not configured.");
            result.TotalTestTimeMs = stopwatch.ElapsedMilliseconds;
            return result;
        }

        var names = ServiceAccountNames(s);
        var downEndpoints = new HashSet<string>();
        var credentialsRejected = false;

        var diagnosticStrategies = BuildStrategies(s, includeNegotiate: true, ignorePreferred: true);
        if (!AllowsInsecure(s))
        {
            result.Hints.Add("Clear-text strategies (LDAP-389, LDAP-636-NoSSL, GC-3268) are not tried because UseSSL is on " +
                             "and AllowInsecureFallback is off.");
        }

        foreach (var strategy in diagnosticStrategies)
        {
            var attempt = new ConnectionAttemptResult
            {
                StrategyName = strategy.Name,
                Server = strategy.Server,
                Port = strategy.Port,
                UseSSL = strategy.Ssl,
                AuthType = strategy.Seal ? "Negotiate (signed+sealed)" : strategy.Auth.ToString()
            };

            if (credentialsRejected || downEndpoints.Contains(strategy.EndpointKey))
            {
                attempt.ErrorMessage = credentialsRejected
                    ? "Skipped: AD rejected the service account password (stopped to avoid account lockout)"
                    : "Skipped: endpoint unreachable";
                result.FailedStrategies.Add(attempt);
                continue;
            }

            var bindNames = strategy.Auth == AuthType.Negotiate ? names.Where(n => !n.Contains('=')).ToList() : names;
            foreach (var name in bindNames)
            {
                attempt.UsernameFormat = name;
                var sw = Stopwatch.StartNew();
                try
                {
                    using var connection = CreateConnection(s, strategy, name, s.ServiceAccountPassword);
                    attempt.Success = true;
                    attempt.ResponseTimeMs = sw.ElapsedMilliseconds;
                    attempt.ErrorMessage = null;
                    attempt.ErrorCode = null;
                    _strategyCache.RecordSuccess(strategy.Name, strategy.Server, strategy.Port, strategy.Ssl, strategy.Secure,
                        sw.ElapsedMilliseconds, makePreferred: false);
                    break;
                }
                catch (LdapException ex)
                {
                    attempt.ErrorCode = ex.ErrorCode;
                    attempt.ErrorMessage = $"{GetLdapErrorDescription(ex.ErrorCode)} - {DescribeLdapError(ex)}";
                    attempt.ResponseTimeMs = sw.ElapsedMilliseconds;

                    var endpointDown = IsConnectivityError(ex.ErrorCode) && !strategy.Seal;
                    _strategyCache.RecordFailure(strategy.Name, strategy.Server, strategy.Port, strategy.Ssl, strategy.Secure,
                        sw.ElapsedMilliseconds, attempt.ErrorMessage, endpointDown);

                    if (endpointDown)
                    {
                        downEndpoints.Add(strategy.EndpointKey);
                        break;
                    }

                    if (ex.ErrorCode == 49)
                    {
                        var reason = MapAdError(ex.ServerErrorMessage);
                        if (reason == AuthFailureReason.UserNotFound) continue;
                        credentialsRejected = true;
                        if (reason == AuthFailureReason.InvalidCredentials)
                        {
                            _strategyCache.BlockServiceAccount(ServiceFingerprint(s), attempt.ErrorMessage);
                        }
                        result.Hints.Add($"AD answered '{reason}' for the service account. Fix the service account before anything else.");
                    }
                    break;
                }
                catch (Exception ex)
                {
                    attempt.ErrorMessage = $"{ex.GetType().Name}: {ex.Message}";
                    attempt.ResponseTimeMs = sw.ElapsedMilliseconds;
                    break;
                }
            }

            if (attempt.Success)
            {
                result.SuccessfulStrategies.Add(attempt);
                result.RecommendedStrategy ??= attempt;
                result.Success = true;
                _logger.LogInformation("✓ {Strategy} as {Name} in {Ms}ms", attempt.StrategyName, attempt.UsernameFormat, attempt.ResponseTimeMs);
            }
            else
            {
                result.FailedStrategies.Add(attempt);
                _logger.LogInformation("✗ {Strategy}: {Error}", attempt.StrategyName, attempt.ErrorMessage);
            }
        }

        AddHints(s, result);
        result.TotalTestTimeMs = stopwatch.ElapsedMilliseconds;
        _logger.LogInformation("=== Diagnostics finished: {Summary} ({Ms}ms) ===", result.Summary, result.TotalTestTimeMs);
        return result;
    }

    private static void AddHints(LdapSettings s, ConnectionTestResult result)
    {
        var ldapsFailed = result.FailedStrategies.FirstOrDefault(f => f.UseSSL && f.Port == 636 && f.ErrorCode == 81);
        if (ldapsFailed != null && IsTcpPortOpen(ldapsFailed.Server, 636, 2000))
        {
            result.Hints.Add(
                "Port 636 accepts TCP connections (telnet works) but the LDAPS handshake fails. The domain controller's " +
                "certificate is most likely not trusted by this server, or its name does not match the server address " +
                "(connecting by IP usually fails certificate name checks). Fix: import the issuing CA into " +
                "'Trusted Root Certification Authorities' on this server and connect using the DC's FQDN, " +
                (s.SkipCertificateValidation
                    ? "or check that the DC has a valid server-authentication certificate."
                    : "or (less secure) enable SkipCertificateValidation."));
        }

        if (result.Success && result.SuccessfulStrategies.All(x => !x.UseSSL && !x.AuthType.StartsWith("Negotiate")))
        {
            result.Hints.Add("Only unencrypted strategies work: passwords travel in clear text between this server and the DC.");
        }
    }

    internal static bool IsTcpPortOpen(string host, int port, int timeoutMs)
    {
        try
        {
            using var client = new TcpClient();
            return client.ConnectAsync(host, port).Wait(timeoutMs) && client.Connected;
        }
        catch
        {
            return false;
        }
    }

    private static string GetLdapErrorDescription(int errorCode) => errorCode switch
    {
        0 => "Success",
        1 => "Operations Error",
        2 => "Protocol Error",
        3 => "Time Limit Exceeded",
        7 => "Authentication Method Not Supported",
        8 => "Strong Auth Required (DC requires signing/SSL)",
        32 => "No Such Object (Invalid BaseDN or user not found)",
        34 => "Invalid DN Syntax",
        48 => "Inappropriate Authentication",
        49 => "Invalid Credentials",
        50 => "Insufficient Access Rights",
        51 => "Server Busy",
        52 => "Server Unavailable",
        53 => "Unwilling To Perform",
        81 => "Server Down / Cannot Connect (for LDAPS often a certificate problem)",
        82 => "Local Error",
        85 => "Connection Timeout",
        91 => "Connect Error (network or SSL handshake)",
        _ => $"Error {errorCode}"
    };

    #endregion

    #region Search and mapping

    private UserInfo? SearchUser(LdapConnection connection, LdapSettings s, string username, out bool referralsOnly)
    {
        var filter = BuildUserFilter(username);
        var request = new System.DirectoryServices.Protocols.SearchRequest(s.BaseDN, filter, SearchScope.Subtree, UserAttributes)
        {
            TimeLimit = SearchTimeout
        };

        var sw = Stopwatch.StartNew();
        var response = (SearchResponse)connection.SendRequest(request, SearchTimeout);
        _logger.LogInformation("User search for {Username}: {Count} entries, {Refs} referrals in {Ms}ms",
            username, response.Entries.Count, response.References.Count, sw.ElapsedMilliseconds);

        // AD always returns referrals to the Configuration / DomainDnsZones / ForestDnsZones partitions for a
        // domain-root subtree search. Those never hold users; only referrals to other domains make an empty
        // result inconclusive.
        referralsOnly = response.Entries.Count == 0 &&
                        response.References.Cast<SearchResultReference>().Any(r => r.Reference.Any(IsUserBearingReferral));
        if (response.Entries.Count == 0) return null;

        var users = response.Entries.Cast<SearchResultEntry>().Select(MapEntryToUserInfo).ToList();
        return ChooseBestMatch(users, username);
    }

    private static bool IsUserBearingReferral(Uri uri)
    {
        var path = Uri.UnescapeDataString(uri.AbsolutePath).TrimStart('/');
        return !(path.StartsWith("CN=Configuration,", StringComparison.OrdinalIgnoreCase) ||
                 path.StartsWith("DC=DomainDnsZones,", StringComparison.OrdinalIgnoreCase) ||
                 path.StartsWith("DC=ForestDnsZones,", StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// The filter matches sAMAccountName OR userPrincipalName OR mail, so two different accounts can match
    /// (e.g. one user's mail equals another user's UPN). Prefer the attribute that matches the input style.
    /// </summary>
    private static UserInfo ChooseBestMatch(List<UserInfo> users, string input)
    {
        if (users.Count == 1) return users[0];

        var sam = ExtractSamAccountName(input);
        bool Eq(string? a, string b) => string.Equals(a, b, StringComparison.OrdinalIgnoreCase);

        if (input.Contains('@'))
        {
            return users.FirstOrDefault(u => Eq(u.UserPrincipalName, input))
                   ?? users.FirstOrDefault(u => Eq(u.Email, input))
                   ?? users.FirstOrDefault(u => Eq(u.SamAccountName, sam))
                   ?? users[0];
        }

        return users.FirstOrDefault(u => Eq(u.SamAccountName, sam)) ?? users[0];
    }

    private void CacheUserInfo(string key, UserInfo userInfo)
    {
        if (!_settings.EnableCache || _settings.CacheDurationMinutes <= 0) return;

        _cache.Set($"{UserCachePrefix}{key.ToLowerInvariant()}", userInfo, new MemoryCacheEntryOptions()
            .SetAbsoluteExpiration(TimeSpan.FromMinutes(_settings.CacheDurationMinutes))
            .SetSize(1));
    }

    private void CacheAuthenticatedUser(UserInfo user)
    {
        foreach (var key in new[] { user.SamAccountName, user.UserPrincipalName, user.Email }
                     .Where(k => !string.IsNullOrWhiteSpace(k))
                     .Distinct(StringComparer.OrdinalIgnoreCase))
        {
            CacheUserInfo(key!, user);
        }
    }

    private static UserInfo BasicUserInfo(string input, string? boundAs)
    {
        var sam = ExtractSamAccountName(input);
        return new UserInfo
        {
            SamAccountName = sam,
            UserPrincipalName = boundAs != null && boundAs.Contains('@') ? boundAs : string.Empty,
            DisplayName = sam,
            Email = input.Contains('@') ? input : string.Empty,
            IsEnabled = true
        };
    }

    private static string BuildUserFilter(string username)
    {
        var sam = EscapeLdapFilter(ExtractSamAccountName(username));
        var original = EscapeLdapFilter(username);
        return $"(&(objectClass=user)(objectCategory=person)(|(sAMAccountName={sam})(userPrincipalName={original})(mail={original})))";
    }

    /// <summary>
    /// Extract the sAMAccountName from DOMAIN\user, user@domain or user
    /// </summary>
    internal static string ExtractSamAccountName(string input)
    {
        if (string.IsNullOrEmpty(input)) return input;
        if (input.Contains('\\')) return input.Split('\\').Last();
        if (input.Contains('@')) return input.Split('@').First();
        return input;
    }

    internal static string DetectUsernameFormat(string input)
    {
        if (string.IsNullOrEmpty(input)) return "Empty";
        if (input.Contains('\\')) return "Pre-Windows 2000 (DOMAIN\\user)";
        if (input.Contains('@')) return "UPN/Email (user@domain)";
        return "sAMAccountName";
    }

    private static UserInfo MapEntryToUserInfo(SearchResultEntry entry)
    {
        var userInfo = new UserInfo
        {
            DistinguishedName = entry.DistinguishedName,
            SamAccountName = GetAttr(entry, "sAMAccountName"),
            UserPrincipalName = GetAttr(entry, "userPrincipalName"),
            DisplayName = GetAttr(entry, "displayName"),
            FirstName = GetAttr(entry, "givenName"),
            LastName = GetAttr(entry, "sn"),
            Email = GetAttr(entry, "mail"),
            Department = GetAttr(entry, "department"),
            Title = GetAttr(entry, "title"),
            Office = GetAttr(entry, "physicalDeliveryOfficeName"),
            Phone = GetAttr(entry, "telephoneNumber"),
            Mobile = GetAttr(entry, "mobile"),
            Manager = GetAttr(entry, "manager"),
            EmployeeId = GetAttr(entry, "employeeID"),
            Company = GetAttr(entry, "company")
        };

        if (int.TryParse(GetAttr(entry, "userAccountControl"), out var uac))
        {
            const int accountDisabled = 0x0002;
            userInfo.IsEnabled = (uac & accountDisabled) == 0;
        }

        var lockoutTime = GetAttr(entry, "lockoutTime");
        userInfo.IsLocked = !string.IsNullOrEmpty(lockoutTime) && lockoutTime != "0";

        var memberOf = entry.Attributes["memberOf"];
        if (memberOf != null)
        {
            foreach (string groupDn in memberOf.GetValues(typeof(string)))
            {
                var groupName = ExtractCnFromDn(groupDn);
                if (!string.IsNullOrEmpty(groupName)) userInfo.Groups.Add(groupName);
            }
        }

        userInfo.WhenCreated = ParseLdapTimestamp(GetAttr(entry, "whenCreated"));
        userInfo.WhenChanged = ParseLdapTimestamp(GetAttr(entry, "whenChanged"));
        userInfo.LastLogon = ParseFileTime(GetAttr(entry, "lastLogonTimestamp"));
        return userInfo;
    }

    private static string GetAttr(SearchResultEntry entry, string name)
    {
        try
        {
            var attr = entry.Attributes[name];
            if (attr != null && attr.Count > 0) return attr[0]?.ToString() ?? string.Empty;
        }
        catch
        {
            // attribute not present or not a string
        }
        return string.Empty;
    }

    private static string ExtractCnFromDn(string dn)
    {
        if (string.IsNullOrEmpty(dn)) return string.Empty;
        if (dn.StartsWith("CN=", StringComparison.OrdinalIgnoreCase))
        {
            var commaIndex = dn.IndexOf(',');
            if (commaIndex > 3) return dn.Substring(3, commaIndex - 3);
        }
        return dn;
    }

    private static string EscapeLdapFilter(string input)
    {
        if (string.IsNullOrEmpty(input)) return string.Empty;
        return input
            .Replace("\\", "\\5c")
            .Replace("*", "\\2a")
            .Replace("(", "\\28")
            .Replace(")", "\\29")
            .Replace("\0", "\\00");
    }

    private static DateTime? ParseLdapTimestamp(string timestamp)
    {
        if (string.IsNullOrEmpty(timestamp) || timestamp.Length < 14) return null;
        try
        {
            return new DateTime(
                int.Parse(timestamp[..4]), int.Parse(timestamp.Substring(4, 2)), int.Parse(timestamp.Substring(6, 2)),
                int.Parse(timestamp.Substring(8, 2)), int.Parse(timestamp.Substring(10, 2)), int.Parse(timestamp.Substring(12, 2)),
                DateTimeKind.Utc);
        }
        catch
        {
            return null;
        }
    }

    private static DateTime? ParseFileTime(string fileTimeString)
    {
        if (long.TryParse(fileTimeString, out var fileTime) && fileTime > 0)
        {
            try { return DateTime.FromFileTimeUtc(fileTime); }
            catch { return null; }
        }
        return null;
    }

    #endregion
}
