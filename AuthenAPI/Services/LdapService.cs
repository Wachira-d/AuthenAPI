using AuthenAPI.Models;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using System.DirectoryServices.AccountManagement;
using System.DirectoryServices.Protocols;
using System.Net;

namespace AuthenAPI.Services;

/// <summary>
/// LDAP service implementation using System.DirectoryServices.Protocols
/// for Active Directory operations via LDAPS with caching
/// </summary>
public class LdapService : ILdapService
{
    private readonly LdapSettings _settings;
    private readonly ILogger<LdapService> _logger;
    private readonly IMemoryCache _cache;
    private readonly SemaphoreSlim _connectionLock = new(10, 10);

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

    private static readonly string[] AuthAttributes =
    {
        "distinguishedName", "sAMAccountName", "userPrincipalName",
        "displayName", "mail", "department", "memberOf",
        "userAccountControl", "lockoutTime"
    };

    public LdapService(IOptions<LdapSettings> settings, ILogger<LdapService> logger, IMemoryCache cache)
    {
        _settings = settings.Value;
        _logger = logger;
        _cache = cache;
    }

    /// <inheritdoc />
    public async Task<UserInfo?> AuthenticateAsync(string username, string password)
    {
        if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password))
        {
            _logger.LogWarning("Authentication attempt with empty username or password");
            return null;
        }

        var stopwatch = System.Diagnostics.Stopwatch.StartNew();

        try
        {
            await _connectionLock.WaitAsync();

            return await Task.Run(() =>
            {
                try
                {
                    _logger.LogInformation("=== Starting Authentication for: {Username} ===", username);

                    // Detect input format
                    var inputFormat = DetectUsernameFormat(username);
                    _logger.LogInformation("Input format detected: {Format}", inputFormat);

                    // Step 1: Authenticate user credentials using combined fallback approach
                    _logger.LogDebug("Step 1: Authenticating user credentials (with fallback methods)...");
                    var (authSuccess, authMethod, usernameUsed) = AuthenticateWithFallback(username, password);

                    if (!authSuccess)
                    {
                        _logger.LogWarning("All authentication methods failed for user: {Username}", username);
                        return null;
                    }

                    _logger.LogInformation("✓ User authenticated successfully: {Username} using method: {Method} (format: {Format})",
                        username, authMethod, usernameUsed);

                    // Extract SAM from the username used for search
                    string searchIdentifier = ExtractSamAccountName(usernameUsed ?? username);
                    _logger.LogInformation("Search identifier (SAM): {SAM}", searchIdentifier);

                    // Prepare basic user info (return immediately if search fails/timeout)
                    var basicUserInfo = new UserInfo
                    {
                        SamAccountName = searchIdentifier,
                        UserPrincipalName = usernameUsed,
                        DisplayName = searchIdentifier,
                        Email = username.Contains("@") ? username : null,
                        IsEnabled = true
                    };

                    // Step 2: Try to get user details with service account (with timeout)
                    _logger.LogInformation("Step 2: Fetching user details (timeout: 10s)...");

                    try
                    {
                        var searchTask = Task.Run(() =>
                        {
                            _logger.LogInformation("Connecting with service account...");
                            var svcResult = TryMultipleConnectionStrategies(
                                _settings.ServiceAccountUsername,
                                _settings.ServiceAccountPassword);

                            _logger.LogInformation("Service account connection result: {Success}", svcResult.Success);

                            if (svcResult.Success && svcResult.Connection != null)
                            {
                                using (svcResult.Connection)
                                {
                                    _logger.LogInformation("Searching for user: {SAM}", searchIdentifier);
                                    return SearchUser(svcResult.Connection, searchIdentifier);
                                }
                            }
                            return null;
                        });

                        // Wait max 10 seconds for user details
                        _logger.LogInformation("Waiting for search task (max 10s)...");
                        if (searchTask.Wait(TimeSpan.FromSeconds(10)))
                        {
                            var result = searchTask.Result;
                            if (result != null)
                            {
                                if (_settings.EnableCache)
                                {
                                    CacheUserInfo(searchIdentifier, result);
                                    if (!string.IsNullOrEmpty(result.Email) &&
                                        !result.Email.Equals(searchIdentifier, StringComparison.OrdinalIgnoreCase))
                                    {
                                        CacheUserInfo(result.Email, result);
                                    }
                                }

                                _logger.LogInformation("=== Authentication completed with full details for: {Username} in {Ms}ms ===",
                                    username, stopwatch.ElapsedMilliseconds);
                                return result;
                            }

                            _logger.LogWarning("User authenticated but details not found. Returning basic info.");
                        }
                        else
                        {
                            _logger.LogWarning("User details search timed out (10s). Returning basic info.");
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "Failed to fetch user details. Returning basic info.");
                    }

                    // Return basic info - authentication was successful
                    _logger.LogInformation("=== Authentication completed (basic info) for: {Username} in {Ms}ms ===",
                        username, stopwatch.ElapsedMilliseconds);
                    return basicUserInfo;
                }
                catch (LdapException ex) when (ex.ErrorCode == 49)
                {
                    _logger.LogWarning("Invalid credentials for user: {Username}", username);
                    return null;
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error during authentication for user: {Username}", username);
                    return null;
                }
            });
        }
        finally
        {
            _connectionLock.Release();
            stopwatch.Stop();
            _logger.LogDebug("Authentication completed in {Ms}ms", stopwatch.ElapsedMilliseconds);
        }
    }

    /// <inheritdoc />
    public async Task<bool> TestConnectionAsync()
    {
        var result = await TestConnectionDetailedAsync();
        return result.Success;
    }

    /// <summary>
    /// Test connection with detailed diagnostics trying multiple strategies
    /// </summary>
    public async Task<ConnectionTestResult> TestConnectionDetailedAsync()
    {
        var stopwatch = System.Diagnostics.Stopwatch.StartNew();
        var testResult = new ConnectionTestResult
        {
            Server = _settings.Server,
            ConfiguredPort = _settings.Port,
            TestStartTime = DateTime.UtcNow
        };

        try
        {
            await _connectionLock.WaitAsync();

            return await Task.Run(() =>
            {
                _logger.LogInformation("=== Starting LDAP Connection Diagnostics ===");
                _logger.LogInformation("Target Server: {Server}", _settings.Server);
                _logger.LogInformation("Configured Port: {Port}", _settings.Port);
                _logger.LogInformation("Use SSL: {UseSSL}", _settings.UseSSL);
                _logger.LogInformation("Service Account: {Account}", _settings.ServiceAccountUsername);

                var strategies = BuildConnectionStrategies();
                _logger.LogInformation("Testing {Count} connection strategies...", strategies.Count);

                foreach (var strategy in strategies)
                {
                    var attemptResult = new ConnectionAttemptResult
                    {
                        StrategyName = strategy.Name,
                        Server = strategy.Server,
                        Port = strategy.Port,
                        UseSSL = strategy.UseSSL,
                        AuthType = strategy.AuthType.ToString()
                    };

                    try
                    {
                        var formattedUsername = strategy.UsernameFormatter(
                            _settings.ServiceAccountUsername, _settings.Domain);
                        attemptResult.UsernameFormat = formattedUsername;

                        var attemptStopwatch = System.Diagnostics.Stopwatch.StartNew();

                        using var connection = CreateConnectionWithStrategy(
                            formattedUsername,
                            _settings.ServiceAccountPassword,
                            strategy);

                        attemptStopwatch.Stop();
                        attemptResult.Success = true;
                        attemptResult.ResponseTimeMs = attemptStopwatch.ElapsedMilliseconds;

                        _logger.LogInformation(
                            "✓ SUCCESS: {Strategy} | Server: {Server}:{Port} | SSL: {SSL} | User: {User} | Time: {Time}ms",
                            strategy.Name, strategy.Server, strategy.Port, strategy.UseSSL,
                            formattedUsername, attemptStopwatch.ElapsedMilliseconds);

                        testResult.SuccessfulStrategies.Add(attemptResult);

                        // First success - record as recommended
                        if (testResult.RecommendedStrategy == null)
                        {
                            testResult.RecommendedStrategy = attemptResult;
                            testResult.Success = true;
                        }

                        connection.Dispose();
                    }
                    catch (LdapException ex)
                    {
                        attemptResult.Success = false;
                        attemptResult.ErrorCode = ex.ErrorCode;
                        attemptResult.ErrorMessage = $"LDAP Error {ex.ErrorCode}: {GetLdapErrorDescription(ex.ErrorCode)} - {ex.Message}";

                        _logger.LogDebug("✗ FAILED: {Strategy} | Error: {Error}",
                            strategy.Name, attemptResult.ErrorMessage);

                        testResult.FailedStrategies.Add(attemptResult);
                    }
                    catch (Exception ex)
                    {
                        attemptResult.Success = false;
                        attemptResult.ErrorMessage = $"{ex.GetType().Name}: {ex.Message}";

                        _logger.LogDebug("✗ FAILED: {Strategy} | Error: {Error}",
                            strategy.Name, attemptResult.ErrorMessage);

                        testResult.FailedStrategies.Add(attemptResult);
                    }
                }

                stopwatch.Stop();
                testResult.TotalTestTimeMs = stopwatch.ElapsedMilliseconds;

                // Log summary
                _logger.LogInformation("=== Connection Test Summary ===");
                _logger.LogInformation("Total strategies tested: {Total}", strategies.Count);
                _logger.LogInformation("Successful: {Success}", testResult.SuccessfulStrategies.Count);
                _logger.LogInformation("Failed: {Failed}", testResult.FailedStrategies.Count);
                _logger.LogInformation("Total test time: {Time}ms", testResult.TotalTestTimeMs);

                if (testResult.RecommendedStrategy != null)
                {
                    _logger.LogInformation("*** RECOMMENDED STRATEGY: {Strategy} ***",
                        testResult.RecommendedStrategy.StrategyName);
                    _logger.LogInformation("    Server: {Server}:{Port}",
                        testResult.RecommendedStrategy.Server, testResult.RecommendedStrategy.Port);
                    _logger.LogInformation("    SSL: {SSL}", testResult.RecommendedStrategy.UseSSL);
                    _logger.LogInformation("    Username Format: {Format}", testResult.RecommendedStrategy.UsernameFormat);
                }
                else
                {
                    _logger.LogError("*** NO WORKING STRATEGY FOUND ***");

                    // Log most common errors
                    var errorGroups = testResult.FailedStrategies
                        .Where(f => f.ErrorCode.HasValue)
                        .GroupBy(f => f.ErrorCode)
                        .OrderByDescending(g => g.Count());

                    foreach (var group in errorGroups.Take(3))
                    {
                        _logger.LogError("Common Error Code {Code}: {Description} ({Count} occurrences)",
                            group.Key, GetLdapErrorDescription(group.Key ?? 0), group.Count());
                    }
                }

                return testResult;
            });
        }
        finally
        {
            _connectionLock.Release();
        }
    }

    /// <summary>
    /// Get human-readable LDAP error description
    /// </summary>
    private static string GetLdapErrorDescription(int errorCode)
    {
        return errorCode switch
        {
            0 => "Success",
            1 => "Operations Error",
            2 => "Protocol Error",
            3 => "Time Limit Exceeded",
            4 => "Size Limit Exceeded",
            7 => "Authentication Method Not Supported",
            8 => "Strong Auth Required",
            32 => "No Such Object (Invalid BaseDN or User not found)",
            34 => "Invalid DN Syntax",
            48 => "Inappropriate Authentication",
            49 => "Invalid Credentials (Wrong username/password)",
            50 => "Insufficient Access Rights",
            51 => "Server Busy",
            52 => "Server Unavailable",
            53 => "Unwilling To Perform",
            65 => "Object Class Violation",
            81 => "Server Down / Cannot Connect",
            82 => "Local Error",
            83 => "Encoding Error",
            84 => "Decoding Error",
            85 => "Connection Timeout",
            91 => "Connect Error (Network issue or SSL handshake failed)",
            _ => $"Unknown Error ({errorCode})"
        };
    }

    /// <inheritdoc />
    public async Task<UserInfo?> GetUserAsync(string username)
    {
        if (string.IsNullOrWhiteSpace(username)) return null;

        var cacheKey = $"{UserCachePrefix}{username.ToLowerInvariant()}";
        if (_settings.EnableCache && _cache.TryGetValue(cacheKey, out UserInfo? cachedUser))
        {
            _logger.LogDebug("User info retrieved from cache: {Username}", username);
            return cachedUser;
        }

        try
        {
            await _connectionLock.WaitAsync();

            return await Task.Run(() =>
            {
                try
                {
                    var connResult = TryMultipleConnectionStrategies(
                        _settings.ServiceAccountUsername,
                        _settings.ServiceAccountPassword);

                    if (!connResult.Success || connResult.Connection == null)
                    {
                        _logger.LogError("Failed to connect for GetUser: {Errors}", connResult.ErrorMessage);
                        return null;
                    }

                    using (connResult.Connection)
                    {
                        var userInfo = SearchUser(connResult.Connection, username);

                        if (userInfo != null && _settings.EnableCache)
                        {
                            CacheUserInfo(username, userInfo);
                        }

                        return userInfo;
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error getting user: {Username}", username);
                    return null;
                }
            });
        }
        finally
        {
            _connectionLock.Release();
        }
    }

    /// <inheritdoc />
    public async Task<List<UserInfo>> SearchUsersAsync(Models.SearchRequest request)
    {
        try
        {
            await _connectionLock.WaitAsync();

            return await Task.Run(() =>
            {
                var users = new List<UserInfo>();

                try
                {
                    var connResult = TryMultipleConnectionStrategies(
                        _settings.ServiceAccountUsername,
                        _settings.ServiceAccountPassword);

                    if (!connResult.Success || connResult.Connection == null)
                    {
                        _logger.LogError("Failed to connect for SearchUsers: {Errors}", connResult.ErrorMessage);
                        return users;
                    }

                    using (connResult.Connection)
                    {
                        string filter;
                        if (!string.IsNullOrEmpty(request.Query))
                        {
                            var escaped = EscapeLdapFilter(request.Query);
                            filter = $"(&(objectClass=user)(objectCategory=person)(|(displayName=*{escaped}*)(sAMAccountName=*{escaped}*)(mail=*{escaped}*)(givenName=*{escaped}*)(sn=*{escaped}*)))";
                        }
                        else
                        {
                            filter = "(&(objectClass=user)(objectCategory=person))";
                        }

                        var searchRequest = new System.DirectoryServices.Protocols.SearchRequest(
                            _settings.BaseDN,
                            filter,
                            SearchScope.Subtree,
                            AuthAttributes);
                        searchRequest.SizeLimit = request.MaxResults;
                        searchRequest.TimeLimit = TimeSpan.FromSeconds(_settings.ConnectionTimeout);

                        var response = (SearchResponse)connResult.Connection.SendRequest(searchRequest);

                        foreach (SearchResultEntry entry in response.Entries)
                        {
                            users.Add(MapEntryToUserInfo(entry));
                            if (users.Count >= request.MaxResults) break;
                        }

                        _logger.LogInformation("Search returned {Count} users", users.Count);
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error searching users with query: {Query}", request.Query);
                }

                return users;
            });
        }
        finally
        {
            _connectionLock.Release();
        }
    }

    /// <inheritdoc />
    public async Task<List<string>> GetUserGroupsAsync(string username)
    {
        if (string.IsNullOrWhiteSpace(username)) return new List<string>();

        var cacheKey = $"{GroupsCachePrefix}{username.ToLowerInvariant()}";
        if (_settings.EnableCache && _cache.TryGetValue(cacheKey, out List<string>? cachedGroups))
        {
            _logger.LogDebug("User groups retrieved from cache: {Username}", username);
            return cachedGroups ?? new List<string>();
        }

        try
        {
            await _connectionLock.WaitAsync();

            return await Task.Run(() =>
            {
                var groups = new List<string>();

                try
                {
                    var connResult = TryMultipleConnectionStrategies(
                        _settings.ServiceAccountUsername,
                        _settings.ServiceAccountPassword);

                    if (!connResult.Success || connResult.Connection == null)
                    {
                        _logger.LogError("Failed to connect for GetUserGroups: {Errors}", connResult.ErrorMessage);
                        return groups;
                    }

                    using (connResult.Connection)
                    {
                        var filter = BuildUserFilter(username);
                        var searchRequest = new System.DirectoryServices.Protocols.SearchRequest(
                            _settings.BaseDN,
                            filter,
                            SearchScope.Subtree,
                            new[] { "memberOf" });

                        var response = (SearchResponse)connResult.Connection.SendRequest(searchRequest);

                        if (response.Entries.Count > 0)
                        {
                            var entry = response.Entries[0];
                            var memberOf = entry.Attributes["memberOf"];
                            if (memberOf != null)
                            {
                                foreach (string groupDn in memberOf.GetValues(typeof(string)))
                                {
                                    var groupName = ExtractCnFromDn(groupDn);
                                    if (!string.IsNullOrEmpty(groupName))
                                    {
                                        groups.Add(groupName);
                                    }
                                }
                            }
                        }

                        if (_settings.EnableCache)
                        {
                            _cache.Set(cacheKey, groups, TimeSpan.FromMinutes(_settings.CacheDurationMinutes));
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error getting groups for user: {Username}", username);
                }

                return groups;
            });
        }
        finally
        {
            _connectionLock.Release();
        }
    }

    /// <inheritdoc />
    public async Task<bool> IsUserInGroupAsync(string username, string groupName)
    {
        if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(groupName))
            return false;

        var groups = await GetUserGroupsAsync(username);
        return groups.Any(g => g.Equals(groupName, StringComparison.OrdinalIgnoreCase));
    }

    #region Private Helper Methods

    /// <summary>
    /// Connection strategy for multi-format LDAP authentication
    /// </summary>
    private class ConnectionStrategy
    {
        public string Name { get; set; } = "";
        public string Server { get; set; } = "";
        public int Port { get; set; }
        public bool UseSSL { get; set; }
        public AuthType AuthType { get; set; }
        public Func<string, string, string> UsernameFormatter { get; set; } = (u, d) => u;
    }

    /// <summary>
    /// Result of connection attempt with strategy info
    /// </summary>
    public class ConnectionResult
    {
        public bool Success { get; set; }
        public string StrategyName { get; set; } = "";
        public string UsernameFormat { get; set; } = "";
        public string? ErrorMessage { get; set; }
        public LdapConnection? Connection { get; set; }
    }

    /// <summary>
    /// Try multiple connection strategies and return the first successful one
    /// </summary>
    private ConnectionResult TryMultipleConnectionStrategies(string username, string password)
    {
        var strategies = BuildConnectionStrategies();
        var errors = new List<string>();

        foreach (var strategy in strategies)
        {
            try
            {
                var formattedUsername = strategy.UsernameFormatter(username, _settings.Domain);

                _logger.LogDebug("Trying connection strategy: {Strategy} with username format: {Username}",
                    strategy.Name, formattedUsername);

                var connection = CreateConnectionWithStrategy(formattedUsername, password, strategy);

                _logger.LogInformation(
                    "✓ CONNECTION SUCCESS - Strategy: {Strategy}, Server: {Server}:{Port}, SSL: {UseSSL}, Username: {Username}",
                    strategy.Name, strategy.Server, strategy.Port, strategy.UseSSL, formattedUsername);

                return new ConnectionResult
                {
                    Success = true,
                    StrategyName = strategy.Name,
                    UsernameFormat = formattedUsername,
                    Connection = connection
                };
            }
            catch (LdapException ex)
            {
                var errorMsg = $"Strategy '{strategy.Name}': LDAP Error {ex.ErrorCode} - {ex.Message}";
                errors.Add(errorMsg);
                _logger.LogWarning("✗ {Error}", errorMsg);
            }
            catch (Exception ex)
            {
                var errorMsg = $"Strategy '{strategy.Name}': {ex.GetType().Name} - {ex.Message}";
                errors.Add(errorMsg);
                _logger.LogWarning("✗ {Error}", errorMsg);
            }
        }

        // All strategies failed
        _logger.LogWarning("All connection strategies failed for user: {Username}. Errors:\n{Errors}",
            username, string.Join("\n", errors));

        return new ConnectionResult
        {
            Success = false,
            ErrorMessage = string.Join("; ", errors)
        };
    }

    /// <summary>
    /// Build list of connection strategies to try
    /// </summary>
    private List<ConnectionStrategy> BuildConnectionStrategies()
    {
        var strategies = new List<ConnectionStrategy>();
        var servers = new[] { _settings.Server };

        // Port combinations to try
        var portConfigs = new[]
        {
            (Port: 636, UseSSL: true, Name: "LDAPS-636"),
            (Port: 636, UseSSL: false, Name: "LDAP-636-NoSSL"),
            (Port: 389, UseSSL: false, Name: "LDAP-389"),
            (Port: 3269, UseSSL: true, Name: "GC-SSL-3269"),
            (Port: 3268, UseSSL: false, Name: "GC-3268")
        };

        // Username format functions
        var usernameFormats = new (string Name, Func<string, string, string> Formatter)[]
        {
            ("UPN", (u, d) => u.Contains("@") ? u : $"{u}@{d}"),
            ("UPN-Email", (u, d) => u.Contains("@") ? u : $"{u}@ipsos.com"),
            ("NetBIOS", (u, d) => {
                var domainShort = d.Split('.')[0].ToUpperInvariant();
                var cleanUser = u.Contains("@") ? u.Split('@')[0] : u;
                return $"{domainShort}\\{cleanUser}";
            }),
            ("SAM-Only", (u, d) => u.Contains("@") ? u.Split('@')[0] : u),
            ("DN-Format", (u, d) => {
                var cleanUser = u.Contains("@") ? u.Split('@')[0] : u;
                var dcParts = d.Split('.').Select(p => $"DC={p}").ToArray();
                return $"CN={cleanUser},CN=Users,{string.Join(",", dcParts)}";
            })
        };

        // Build all combinations - prioritize LDAPS with UPN first
        foreach (var portConfig in portConfigs)
        {
            foreach (var format in usernameFormats)
            {
                foreach (var server in servers)
                {
                    strategies.Add(new ConnectionStrategy
                    {
                        Name = $"{portConfig.Name}-{format.Name}",
                        Server = server,
                        Port = portConfig.Port,
                        UseSSL = portConfig.UseSSL,
                        AuthType = AuthType.Basic,
                        UsernameFormatter = format.Formatter
                    });
                }
            }
        }

        // Also try Negotiate auth type for Windows integrated auth
        strategies.Add(new ConnectionStrategy
        {
            Name = "LDAPS-Negotiate",
            Server = _settings.Server,
            Port = 636,
            UseSSL = true,
            AuthType = AuthType.Negotiate,
            UsernameFormatter = (u, d) => u.Contains("@") ? u : $"{u}@{d}"
        });

        return strategies;
    }

    /// <summary>
    /// Create connection using specific strategy
    /// </summary>
    private LdapConnection CreateConnectionWithStrategy(string username, string password, ConnectionStrategy strategy)
    {
        var identifier = new LdapDirectoryIdentifier(strategy.Server, strategy.Port);
        var credential = new NetworkCredential(username, password);
        var connection = new LdapConnection(identifier, credential)
        {
            AuthType = strategy.AuthType,
            AutoBind = false
        };

        connection.SessionOptions.ProtocolVersion = 3;
        connection.Timeout = TimeSpan.FromSeconds(_settings.ConnectionTimeout);

        if (strategy.UseSSL)
        {
            connection.SessionOptions.SecureSocketLayer = true;

            if (_settings.SkipCertificateValidation)
            {
                connection.SessionOptions.VerifyServerCertificate = (conn, cert) => true;
            }
        }

        connection.Bind();
        return connection;
    }

    private LdapConnection CreateConnection(string username, string password)
    {
        var identifier = new LdapDirectoryIdentifier(_settings.Server, _settings.Port);
        var credential = new NetworkCredential(username, password);
        var connection = new LdapConnection(identifier, credential)
        {
            AuthType = AuthType.Basic,
            AutoBind = false
        };

        connection.SessionOptions.ProtocolVersion = 3;
        connection.Timeout = TimeSpan.FromSeconds(_settings.ConnectionTimeout);

        if (_settings.UseSSL)
        {
            connection.SessionOptions.SecureSocketLayer = true;

            if (_settings.SkipCertificateValidation)
            {
                connection.SessionOptions.VerifyServerCertificate = (conn, cert) => true;
            }
        }

        connection.Bind();
        return connection;
    }

    private LdapConnection CreateServiceConnection()
    {
        var bindDn = _settings.ServiceAccountUsername;
        if (!bindDn.Contains("@") && !bindDn.Contains(","))
        {
            bindDn = $"{bindDn}@{_settings.Domain}";
        }

        return CreateConnection(bindDn, _settings.ServiceAccountPassword);
    }

    /// <summary>
    /// Create service connection trying multiple strategies
    /// </summary>
    private LdapConnection CreateServiceConnectionMultiStrategy()
    {
        var result = TryMultipleConnectionStrategies(
            _settings.ServiceAccountUsername,
            _settings.ServiceAccountPassword);

        if (result.Success && result.Connection != null)
        {
            return result.Connection;
        }

        throw new LdapException($"All connection strategies failed: {result.ErrorMessage}");
    }

    private UserInfo? SearchUser(LdapConnection connection, string username)
    {
        var filter = BuildUserFilter(username);
        _logger.LogInformation("SearchUser filter: {Filter}", filter);

        var searchRequest = new System.DirectoryServices.Protocols.SearchRequest(
            _settings.BaseDN,
            filter,
            SearchScope.Subtree,
            UserAttributes);

        // Set timeout for search request (5 seconds)
        var searchTimeout = TimeSpan.FromSeconds(5);
        _logger.LogInformation("Executing LDAP search (timeout: 5s)...");
        var response = (SearchResponse)connection.SendRequest(searchRequest, searchTimeout);

        _logger.LogInformation("SearchUser found {Count} entries", response.Entries.Count);

        if (response.Entries.Count > 0)
        {
            return MapEntryToUserInfo(response.Entries[0]);
        }

        return null;
    }

    private void CacheUserInfo(string username, UserInfo userInfo)
    {
        var cacheKey = $"{UserCachePrefix}{username.ToLowerInvariant()}";
        var cacheOptions = new MemoryCacheEntryOptions()
            .SetAbsoluteExpiration(TimeSpan.FromMinutes(_settings.CacheDurationMinutes))
            .SetSize(1);

        _cache.Set(cacheKey, userInfo, cacheOptions);
    }

    private static string BuildUserFilter(string username)
    {
        // Parse username to extract clean SAM account name
        var cleanUsername = ExtractSamAccountName(username);
        var escaped = EscapeLdapFilter(cleanUsername);
        var originalEscaped = EscapeLdapFilter(username);

        // Build filter that searches by:
        // - sAMAccountName (Pre-Windows 2000 logon name)
        // - userPrincipalName (UPN - user@domain.com)
        // - mail (email address)
        return $"(&(objectClass=user)(objectCategory=person)(|(sAMAccountName={escaped})(userPrincipalName={originalEscaped})(mail={originalEscaped})))";
    }

    /// <summary>
    /// Extract SAM account name from various input formats
    /// Supports: email@domain.com, DOMAIN\username, username
    /// </summary>
    private static string ExtractSamAccountName(string input)
    {
        if (string.IsNullOrEmpty(input)) return input;

        // Pre-Windows 2000 format: DOMAIN\username
        if (input.Contains("\\"))
        {
            return input.Split('\\').Last();
        }

        // Email/UPN format: user@domain.com
        if (input.Contains("@"))
        {
            return input.Split('@').First();
        }

        // Already SAM format
        return input;
    }

    /// <summary>
    /// Detect the format of the username input
    /// </summary>
    private static string DetectUsernameFormat(string input)
    {
        if (string.IsNullOrEmpty(input)) return "Empty";

        // Pre-Windows 2000 format: DOMAIN\username
        if (input.Contains("\\"))
        {
            var parts = input.Split('\\');
            return $"Pre-Windows 2000 (NetBIOS): Domain={parts[0]}, User={parts[1]}";
        }

        // Email/UPN format
        if (input.Contains("@"))
        {
            var parts = input.Split('@');
            var domain = parts[1].ToLowerInvariant();

            if (domain.Contains("."))
            {
                // Full domain like user@domain.company.com
                return $"UPN/Email: User={parts[0]}, Domain={domain}";
            }
            else
            {
                // Short domain like user@DOMAIN
                return $"UPN (Short): User={parts[0]}, Domain={domain}";
            }
        }

        // Plain SAM account name
        return $"SAM Account Name: {input}";
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

        var uacValue = GetAttr(entry, "userAccountControl");
        if (int.TryParse(uacValue, out var uac))
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
                if (!string.IsNullOrEmpty(groupName))
                {
                    userInfo.Groups.Add(groupName);
                }
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
            if (attr != null && attr.Count > 0)
            {
                return attr[0]?.ToString() ?? string.Empty;
            }
        }
        catch { }
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
                int.Parse(timestamp.Substring(0, 4)),
                int.Parse(timestamp.Substring(4, 2)),
                int.Parse(timestamp.Substring(6, 2)),
                int.Parse(timestamp.Substring(8, 2)),
                int.Parse(timestamp.Substring(10, 2)),
                int.Parse(timestamp.Substring(12, 2)),
                DateTimeKind.Utc);
        }
        catch { return null; }
    }

    private static DateTime? ParseFileTime(string fileTimeString)
    {
        if (string.IsNullOrEmpty(fileTimeString)) return null;

        if (long.TryParse(fileTimeString, out var fileTime) && fileTime > 0)
        {
            try { return DateTime.FromFileTimeUtc(fileTime); }
            catch { return null; }
        }

        return null;
    }

    #region Fallback Authentication Methods

    /// <summary>
    /// Fallback authentication using PrincipalContext (System.DirectoryServices.AccountManagement)
    /// This is simpler and may work when LDAP protocol methods fail
    /// </summary>
    private bool ValidateCredentialsFallback(string username, string password)
    {
        var servers = new[] { _settings.Server, _settings.Domain };
        var userFormats = GetUsernameFormats(username);

        foreach (var server in servers.Where(s => !string.IsNullOrEmpty(s)))
        {
            foreach (var userFormat in userFormats)
            {
                try
                {
                    _logger.LogDebug("Fallback auth attempt - Server: {Server}, User: {User}", server, userFormat);

                    using var pc = new PrincipalContext(ContextType.Domain, server);
                    var isValid = pc.ValidateCredentials(userFormat, password);

                    if (isValid)
                    {
                        _logger.LogInformation("✓ FALLBACK AUTH SUCCESS - Server: {Server}, User: {User}",
                            server, userFormat);
                        return true;
                    }

                    _logger.LogDebug("✗ Fallback auth failed - Server: {Server}, User: {User}", server, userFormat);
                }
                catch (PrincipalServerDownException ex)
                {
                    _logger.LogDebug("✗ Fallback server down - Server: {Server}, Error: {Error}", server, ex.Message);
                }
                catch (Exception ex)
                {
                    _logger.LogDebug("✗ Fallback auth error - Server: {Server}, Error: {Error}", server, ex.Message);
                }
            }
        }

        return false;
    }

    /// <summary>
    /// Get multiple username formats to try for authentication
    /// Supports: email@domain.com, DOMAIN\username, username (Pre-Windows 2000)
    /// </summary>
    private string[] GetUsernameFormats(string username)
    {
        var formats = new List<string>();
        var domainShort = _settings.Domain.Split('.').FirstOrDefault()?.ToUpperInvariant() ?? "IPSOSGROUP";

        // Original format
        formats.Add(username);

        // Parse to get clean SAM account name
        string sam;
        string? emailDomain = null;

        if (username.Contains("\\"))
        {
            // Pre-Windows 2000 format: DOMAIN\username
            var parts = username.Split('\\');
            sam = parts.Last();
            _logger.LogDebug("Detected Pre-2000 format. Extracted SAM: {SAM}", sam);
        }
        else if (username.Contains("@"))
        {
            // Email/UPN format: user@domain.com
            var parts = username.Split('@');
            sam = parts.First();
            emailDomain = parts.Last();
            _logger.LogDebug("Detected email/UPN format. Extracted SAM: {SAM}, Domain: {Domain}", sam, emailDomain);
        }
        else
        {
            // Already SAM format
            sam = username;
            _logger.LogDebug("Detected SAM format: {SAM}", sam);
        }

        // Add all possible formats
        formats.Add(sam);  // Just SAM

        // UPN formats
        formats.Add($"{sam}@{_settings.Domain}");  // SAM@full.domain.com
        formats.Add($"{sam}@ipsos.com");           // SAM@ipsos.com

        // Pre-Windows 2000 (NetBIOS) formats
        formats.Add($"{domainShort}\\{sam}");      // DOMAIN\SAM
        formats.Add($"IPSOSGROUP\\{sam}");         // IPSOSGROUP\SAM (hardcoded)

        // If original was email, also try with original domain
        if (!string.IsNullOrEmpty(emailDomain) && !emailDomain.Equals("ipsos.com", StringComparison.OrdinalIgnoreCase))
        {
            formats.Add($"{sam}@{emailDomain}");
        }

        var result = formats.Distinct().ToArray();
        _logger.LogDebug("Username formats to try: {Formats}", string.Join(", ", result));

        return result;
    }

    /// <summary>
    /// Combined authentication: Try LDAP first, then fallback to PrincipalContext
    /// </summary>
    private (bool Success, string Method, string? UsernameUsed) AuthenticateWithFallback(string username, string password)
    {
        // Method 1: Try multi-strategy LDAP connection
        _logger.LogDebug("Trying Method 1: Multi-strategy LDAP authentication");
        var ldapResult = TryMultipleConnectionStrategies(username, password);

        if (ldapResult.Success)
        {
            ldapResult.Connection?.Dispose();
            return (true, $"LDAP-{ldapResult.StrategyName}", ldapResult.UsernameFormat);
        }

        // Method 2: Try PrincipalContext fallback
        _logger.LogDebug("Method 1 failed. Trying Method 2: PrincipalContext fallback");
        var userFormats = GetUsernameFormats(username);

        foreach (var userFormat in userFormats)
        {
            if (ValidateCredentialsFallback(userFormat, password))
            {
                return (true, "PrincipalContext-Fallback", userFormat);
            }
        }

        // Method 3: Try direct LDAP bind with different options
        _logger.LogDebug("Method 2 failed. Trying Method 3: Direct LDAP simple bind");
        foreach (var userFormat in userFormats)
        {
            try
            {
                using var conn = new LdapConnection(
                    new LdapDirectoryIdentifier(_settings.Server, 389));
                conn.AuthType = AuthType.Basic;
                conn.SessionOptions.ProtocolVersion = 3;
                conn.Credential = new NetworkCredential(userFormat, password);
                conn.Bind();

                _logger.LogInformation("✓ DIRECT BIND SUCCESS - User: {User}", userFormat);
                return (true, "DirectBind-389", userFormat);
            }
            catch (Exception ex)
            {
                _logger.LogDebug("✗ Direct bind failed for {User}: {Error}", userFormat, ex.Message);
            }
        }

        return (false, "AllMethodsFailed", null);
    }

    #endregion

    #endregion
}
