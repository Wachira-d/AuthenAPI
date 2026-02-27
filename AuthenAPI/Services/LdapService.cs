using AuthenAPI.Models;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
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
                    string userPrincipal;
                    string searchIdentifier = username;

                    // Check if input looks like an email
                    if (username.Contains("@"))
                    {
                        var domainPart = username.Split('@')[1];
                        if (domainPart.Equals(_settings.Domain, StringComparison.OrdinalIgnoreCase))
                        {
                            userPrincipal = username;
                        }
                        else
                        {
                            // Email login - search for user by email first
                            _logger.LogDebug("Input appears to be email, searching for user: {Email}", username);

                            using var searchConn = CreateServiceConnection();
                            var userInfo = SearchUser(searchConn, username);
                            if (userInfo == null)
                            {
                                _logger.LogWarning("User not found with email: {Email}", username);
                                return null;
                            }

                            userPrincipal = userInfo.UserPrincipalName ?? $"{userInfo.SamAccountName}@{_settings.Domain}";
                            searchIdentifier = userInfo.SamAccountName ?? username;
                            _logger.LogDebug("Found user {SamAccountName} for email {Email}", userInfo.SamAccountName, username);
                        }
                    }
                    else
                    {
                        userPrincipal = $"{username}@{_settings.Domain}";
                    }

                    // Authenticate by binding with user credentials
                    using var connection = CreateConnection(userPrincipal, password);

                    // If we get here, bind succeeded - user is authenticated
                    _logger.LogInformation("User authenticated successfully: {Username} in {Ms}ms",
                        searchIdentifier, stopwatch.ElapsedMilliseconds);

                    // Search for user info using service account
                    using var svcConn = CreateServiceConnection();
                    var result = SearchUser(svcConn, searchIdentifier);

                    if (result != null && _settings.EnableCache)
                    {
                        CacheUserInfo(searchIdentifier, result);
                        if (!string.IsNullOrEmpty(result.Email) &&
                            !result.Email.Equals(searchIdentifier, StringComparison.OrdinalIgnoreCase))
                        {
                            CacheUserInfo(result.Email, result);
                        }
                    }

                    return result;
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
        var stopwatch = System.Diagnostics.Stopwatch.StartNew();

        try
        {
            await _connectionLock.WaitAsync();

            return await Task.Run(() =>
            {
                try
                {
                    using var connection = CreateServiceConnection();
                    _logger.LogInformation("LDAP connection test successful to {Server}:{Port} in {Ms}ms",
                        _settings.Server, _settings.Port, stopwatch.ElapsedMilliseconds);
                    return true;
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "LDAP connection test failed to {Server}:{Port}",
                        _settings.Server, _settings.Port);
                    return false;
                }
            });
        }
        finally
        {
            _connectionLock.Release();
        }
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
                    using var connection = CreateServiceConnection();
                    var userInfo = SearchUser(connection, username);

                    if (userInfo != null && _settings.EnableCache)
                    {
                        CacheUserInfo(username, userInfo);
                    }

                    return userInfo;
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
                    using var connection = CreateServiceConnection();

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

                    var response = (SearchResponse)connection.SendRequest(searchRequest);

                    foreach (SearchResultEntry entry in response.Entries)
                    {
                        users.Add(MapEntryToUserInfo(entry));
                        if (users.Count >= request.MaxResults) break;
                    }

                    _logger.LogInformation("Search returned {Count} users", users.Count);
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
                    using var connection = CreateServiceConnection();

                    var filter = BuildUserFilter(username);
                    var searchRequest = new System.DirectoryServices.Protocols.SearchRequest(
                        _settings.BaseDN,
                        filter,
                        SearchScope.Subtree,
                        new[] { "memberOf" });

                    var response = (SearchResponse)connection.SendRequest(searchRequest);

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

    private UserInfo? SearchUser(LdapConnection connection, string username)
    {
        var filter = BuildUserFilter(username);
        var searchRequest = new System.DirectoryServices.Protocols.SearchRequest(
            _settings.BaseDN,
            filter,
            SearchScope.Subtree,
            UserAttributes);

        var response = (SearchResponse)connection.SendRequest(searchRequest);

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
        var escaped = EscapeLdapFilter(username);
        return $"(&(objectClass=user)(objectCategory=person)(|(sAMAccountName={escaped})(userPrincipalName={escaped})(mail={escaped})))";
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

    #endregion
}
