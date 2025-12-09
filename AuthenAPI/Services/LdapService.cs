using AuthenAPI.Models;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using Novell.Directory.Ldap;
using System.Security.Authentication;

namespace AuthenAPI.Services;

/// <summary>
/// LDAP service implementation for Active Directory operations via LDAPS
/// with connection pooling and caching for improved performance
/// </summary>
public class LdapService : ILdapService
{
    private readonly LdapSettings _settings;
    private readonly ILogger<LdapService> _logger;
    private readonly IMemoryCache _cache;
    private readonly SemaphoreSlim _connectionLock = new(10, 10); // Max 10 concurrent connections

    // Cache keys
    private const string UserCachePrefix = "ldap_user_";
    private const string GroupsCachePrefix = "ldap_groups_";

    // Common AD attributes to retrieve
    private static readonly string[] UserAttributes =
    {
        "distinguishedName",
        "sAMAccountName",
        "userPrincipalName",
        "displayName",
        "givenName",
        "sn",
        "mail",
        "department",
        "title",
        "physicalDeliveryOfficeName",
        "telephoneNumber",
        "mobile",
        "manager",
        "employeeID",
        "company",
        "userAccountControl",
        "lockoutTime",
        "memberOf",
        "whenCreated",
        "whenChanged",
        "lastLogonTimestamp"
    };

    // Minimal attributes for authentication (faster)
    private static readonly string[] AuthAttributes =
    {
        "distinguishedName",
        "sAMAccountName",
        "userPrincipalName",
        "displayName",
        "mail",
        "department",
        "memberOf",
        "userAccountControl",
        "lockoutTime"
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
                    // Build user principal name for direct bind
                    var userPrincipal = username.Contains("@") ? username : $"{username}@{_settings.Domain}";

                    // Try direct bind first (faster - single connection)
                    using var connection = CreateConnection();
                    try
                    {
                        connection.Connect(_settings.Server, _settings.Port);
                        connection.Bind(userPrincipal, password);

                        if (connection.Bound)
                        {
                            _logger.LogInformation("User authenticated successfully: {Username} in {Ms}ms",
                                username, stopwatch.ElapsedMilliseconds);

                            // Get user info using the authenticated connection
                            var userInfo = GetUserInfoFromConnection(connection, username);

                            // Cache the user info
                            if (userInfo != null && _settings.EnableCache)
                            {
                                CacheUserInfo(username, userInfo);
                            }

                            return userInfo;
                        }
                    }
                    catch (LdapException ex) when (ex.ResultCode == LdapException.InvalidCredentials)
                    {
                        _logger.LogWarning("Invalid credentials for user: {Username}", username);
                        return null;
                    }

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
                    using var connection = CreateConnection();
                    ConnectAndBind(connection);
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
        if (string.IsNullOrWhiteSpace(username))
        {
            return null;
        }

        // Check cache first
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
                    using var connection = CreateConnection();
                    ConnectAndBind(connection);

                    var userInfo = GetUserInfoFromConnection(connection, username);

                    // Cache the result
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
    public async Task<List<UserInfo>> SearchUsersAsync(SearchRequest request)
    {
        try
        {
            await _connectionLock.WaitAsync();

            return await Task.Run(() =>
            {
                var users = new List<UserInfo>();

                try
                {
                    using var connection = CreateConnection();
                    ConnectAndBind(connection);

                    string filter;
                    if (!string.IsNullOrEmpty(request.LdapFilter))
                    {
                        filter = request.LdapFilter;
                    }
                    else if (!string.IsNullOrEmpty(request.Query))
                    {
                        filter = $"(&(objectClass=user)(objectCategory=person)(|(displayName=*{EscapeLdapFilter(request.Query)}*)(sAMAccountName=*{EscapeLdapFilter(request.Query)}*)(mail=*{EscapeLdapFilter(request.Query)}*)(givenName=*{EscapeLdapFilter(request.Query)}*)(sn=*{EscapeLdapFilter(request.Query)}*)))";
                    }
                    else
                    {
                        filter = "(&(objectClass=user)(objectCategory=person))";
                    }

                    var baseDn = request.BaseDN ?? _settings.BaseDN;

                    var constraints = new LdapSearchConstraints
                    {
                        MaxResults = request.MaxResults,
                        TimeLimit = _settings.ConnectionTimeout * 1000
                    };

                    var searchResults = connection.Search(
                        baseDn,
                        LdapConnection.ScopeSub,
                        filter,
                        AuthAttributes, // Use minimal attributes for search
                        false,
                        constraints);

                    while (searchResults.HasMore() && users.Count < request.MaxResults)
                    {
                        try
                        {
                            var entry = searchResults.Next();
                            var user = MapEntryToUserInfo(entry);
                            users.Add(user);
                        }
                        catch (LdapException ex) when (ex.ResultCode == LdapException.SizeLimitExceeded)
                        {
                            break;
                        }
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
        if (string.IsNullOrWhiteSpace(username))
        {
            return new List<string>();
        }

        // Check cache first
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
                    using var connection = CreateConnection();
                    ConnectAndBind(connection);

                    var filter = BuildUserFilter(username);
                    var searchResults = connection.Search(
                        _settings.BaseDN,
                        LdapConnection.ScopeSub,
                        filter,
                        new[] { "memberOf" },
                        false);

                    if (searchResults.HasMore())
                    {
                        var entry = searchResults.Next();
                        var memberOf = entry.GetAttribute("memberOf");
                        if (memberOf != null)
                        {
                            foreach (var groupDn in memberOf.StringValueArray)
                            {
                                var groupName = ExtractCnFromDn(groupDn);
                                if (!string.IsNullOrEmpty(groupName))
                                {
                                    groups.Add(groupName);
                                }
                            }
                        }
                    }

                    // Cache the result
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
        {
            return false;
        }

        var groups = await GetUserGroupsAsync(username);
        return groups.Any(g => g.Equals(groupName, StringComparison.OrdinalIgnoreCase));
    }

    #region Private Helper Methods

    private LdapConnection CreateConnection()
    {
        var connectionOptions = new LdapConnectionOptions();

        if (_settings.UseSSL)
        {
            connectionOptions.ConfigureSslProtocols(SslProtocols.Tls12 | SslProtocols.Tls13);

            if (_settings.SkipCertificateValidation)
            {
                connectionOptions.ConfigureRemoteCertificateValidationCallback((sender, certificate, chain, errors) => true);
            }
        }

        var connection = new LdapConnection(connectionOptions);

        if (_settings.UseSSL)
        {
            connection.SecureSocketLayer = true;
        }

        // Use milliseconds for timeout
        connection.ConnectionTimeout = _settings.ConnectionTimeout * 1000;

        return connection;
    }

    private void ConnectAndBind(LdapConnection connection)
    {
        connection.Connect(_settings.Server, _settings.Port);

        var bindDn = _settings.ServiceAccountUsername;
        if (!bindDn.Contains("@") && !bindDn.Contains(","))
        {
            bindDn = $"{bindDn}@{_settings.Domain}";
        }

        connection.Bind(bindDn, _settings.ServiceAccountPassword);
    }

    private UserInfo? GetUserInfoFromConnection(LdapConnection connection, string username)
    {
        var filter = BuildUserFilter(username);
        var searchResults = connection.Search(
            _settings.BaseDN,
            LdapConnection.ScopeSub,
            filter,
            UserAttributes,
            false);

        if (searchResults.HasMore())
        {
            return MapEntryToUserInfo(searchResults.Next());
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
        var escapedUsername = EscapeLdapFilter(username);
        return $"(&(objectClass=user)(objectCategory=person)(|(sAMAccountName={escapedUsername})(userPrincipalName={escapedUsername})))";
    }

    private static UserInfo MapEntryToUserInfo(LdapEntry entry)
    {
        var userInfo = new UserInfo
        {
            DistinguishedName = entry.Dn,
            SamAccountName = GetAttributeValue(entry, "sAMAccountName"),
            UserPrincipalName = GetAttributeValue(entry, "userPrincipalName"),
            DisplayName = GetAttributeValue(entry, "displayName"),
            FirstName = GetAttributeValue(entry, "givenName"),
            LastName = GetAttributeValue(entry, "sn"),
            Email = GetAttributeValue(entry, "mail"),
            Department = GetAttributeValue(entry, "department"),
            Title = GetAttributeValue(entry, "title"),
            Office = GetAttributeValue(entry, "physicalDeliveryOfficeName"),
            Phone = GetAttributeValue(entry, "telephoneNumber"),
            Mobile = GetAttributeValue(entry, "mobile"),
            Manager = GetAttributeValue(entry, "manager"),
            EmployeeId = GetAttributeValue(entry, "employeeID"),
            Company = GetAttributeValue(entry, "company")
        };

        var uacValue = GetAttributeValue(entry, "userAccountControl");
        if (int.TryParse(uacValue, out var uac))
        {
            const int accountDisabled = 0x0002;
            userInfo.IsEnabled = (uac & accountDisabled) == 0;
        }

        var lockoutTime = GetAttributeValue(entry, "lockoutTime");
        userInfo.IsLocked = !string.IsNullOrEmpty(lockoutTime) && lockoutTime != "0";

        var memberOf = entry.GetAttribute("memberOf");
        if (memberOf != null)
        {
            foreach (var groupDn in memberOf.StringValueArray)
            {
                var groupName = ExtractCnFromDn(groupDn);
                if (!string.IsNullOrEmpty(groupName))
                {
                    userInfo.Groups.Add(groupName);
                }
            }
        }

        userInfo.WhenCreated = ParseLdapTimestamp(GetAttributeValue(entry, "whenCreated"));
        userInfo.WhenChanged = ParseLdapTimestamp(GetAttributeValue(entry, "whenChanged"));
        userInfo.LastLogon = ParseFileTime(GetAttributeValue(entry, "lastLogonTimestamp"));

        return userInfo;
    }

    private static string GetAttributeValue(LdapEntry entry, string attributeName)
    {
        try
        {
            var attribute = entry.GetAttribute(attributeName);
            return attribute?.StringValue ?? string.Empty;
        }
        catch
        {
            return string.Empty;
        }
    }

    private static string ExtractCnFromDn(string dn)
    {
        if (string.IsNullOrEmpty(dn)) return string.Empty;

        if (dn.StartsWith("CN=", StringComparison.OrdinalIgnoreCase))
        {
            var commaIndex = dn.IndexOf(',');
            if (commaIndex > 3)
            {
                return dn.Substring(3, commaIndex - 3);
            }
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
            var year = int.Parse(timestamp.Substring(0, 4));
            var month = int.Parse(timestamp.Substring(4, 2));
            var day = int.Parse(timestamp.Substring(6, 2));
            var hour = int.Parse(timestamp.Substring(8, 2));
            var minute = int.Parse(timestamp.Substring(10, 2));
            var second = int.Parse(timestamp.Substring(12, 2));

            return new DateTime(year, month, day, hour, minute, second, DateTimeKind.Utc);
        }
        catch
        {
            return null;
        }
    }

    private static DateTime? ParseFileTime(string fileTimeString)
    {
        if (string.IsNullOrEmpty(fileTimeString)) return null;

        if (long.TryParse(fileTimeString, out var fileTime) && fileTime > 0)
        {
            try
            {
                return DateTime.FromFileTimeUtc(fileTime);
            }
            catch
            {
                return null;
            }
        }

        return null;
    }

    #endregion
}
