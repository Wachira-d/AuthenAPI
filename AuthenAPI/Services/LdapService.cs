using AuthenAPI.Models;
using Microsoft.Extensions.Options;
using Novell.Directory.Ldap;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

namespace AuthenAPI.Services;

/// <summary>
/// LDAP service implementation for Active Directory operations via LDAPS
/// </summary>
public class LdapService : ILdapService
{
    private readonly LdapSettings _settings;
    private readonly ILogger<LdapService> _logger;

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

    public LdapService(IOptions<LdapSettings> settings, ILogger<LdapService> logger)
    {
        _settings = settings.Value;
        _logger = logger;
    }

    /// <inheritdoc />
    public async Task<UserInfo?> AuthenticateAsync(string username, string password)
    {
        if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password))
        {
            _logger.LogWarning("Authentication attempt with empty username or password");
            return null;
        }

        return await Task.Run(() =>
        {
            try
            {
                using var connection = CreateConnection();
                ConnectAndBind(connection);

                // Search for the user first
                var userDn = FindUserDn(connection, username);
                if (string.IsNullOrEmpty(userDn))
                {
                    _logger.LogWarning("User not found: {Username}", username);
                    return null;
                }

                // Try to bind with user credentials
                using var userConnection = CreateConnection();
                try
                {
                    userConnection.Connect(_settings.Server, _settings.Port);
                    userConnection.Bind(userDn, password);

                    if (userConnection.Bound)
                    {
                        _logger.LogInformation("User authenticated successfully: {Username}", username);

                        // Get user info after successful authentication
                        return GetUserInfoFromDn(connection, userDn);
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

    /// <inheritdoc />
    public async Task<bool> TestConnectionAsync()
    {
        return await Task.Run(() =>
        {
            try
            {
                using var connection = CreateConnection();
                ConnectAndBind(connection);
                _logger.LogInformation("LDAP connection test successful to {Server}:{Port}", _settings.Server, _settings.Port);
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "LDAP connection test failed to {Server}:{Port}", _settings.Server, _settings.Port);
                return false;
            }
        });
    }

    /// <inheritdoc />
    public async Task<UserInfo?> GetUserAsync(string username)
    {
        if (string.IsNullOrWhiteSpace(username))
        {
            return null;
        }

        return await Task.Run(() =>
        {
            try
            {
                using var connection = CreateConnection();
                ConnectAndBind(connection);

                var filter = BuildUserFilter(username);
                var searchResults = connection.Search(
                    _settings.BaseDN,
                    LdapConnection.ScopeSub,
                    filter,
                    UserAttributes,
                    false);

                if (searchResults.HasMore())
                {
                    var entry = searchResults.Next();
                    return MapEntryToUserInfo(entry);
                }

                return null;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting user: {Username}", username);
                return null;
            }
        });
    }

    /// <inheritdoc />
    public async Task<List<UserInfo>> SearchUsersAsync(SearchRequest request)
    {
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
                    // Search in common fields
                    filter = $"(&(objectClass=user)(objectCategory=person)(|(displayName=*{EscapeLdapFilter(request.Query)}*)(sAMAccountName=*{EscapeLdapFilter(request.Query)}*)(mail=*{EscapeLdapFilter(request.Query)}*)(givenName=*{EscapeLdapFilter(request.Query)}*)(sn=*{EscapeLdapFilter(request.Query)}*)))";
                }
                else
                {
                    // Return all users if no query specified
                    filter = "(&(objectClass=user)(objectCategory=person))";
                }

                var baseDn = request.BaseDN ?? _settings.BaseDN;

                var constraints = new LdapSearchConstraints
                {
                    MaxResults = request.MaxResults
                };

                var searchResults = connection.Search(
                    baseDn,
                    LdapConnection.ScopeSub,
                    filter,
                    UserAttributes,
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
                        // Size limit reached, return what we have
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

    /// <inheritdoc />
    public async Task<List<string>> GetUserGroupsAsync(string username)
    {
        var groups = new List<string>();

        if (string.IsNullOrWhiteSpace(username))
        {
            return groups;
        }

        return await Task.Run(() =>
        {
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
                            // Extract CN from DN
                            var groupName = ExtractCnFromDn(groupDn);
                            if (!string.IsNullOrEmpty(groupName))
                            {
                                groups.Add(groupName);
                            }
                        }
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
        var connection = new LdapConnection();

        if (_settings.UseSSL)
        {
            connection.SecureSocketLayer = true;

            if (_settings.SkipCertificateValidation)
            {
                connection.UserDefinedServerCertValidationDelegate += (sender, certificate, chain, errors) => true;
            }
        }

        connection.ConnectionTimeout = _settings.ConnectionTimeout * 1000;

        return connection;
    }

    private void ConnectAndBind(LdapConnection connection)
    {
        connection.Connect(_settings.Server, _settings.Port);

        var bindDn = _settings.ServiceAccountUsername;
        if (!bindDn.Contains("@") && !bindDn.Contains(","))
        {
            // If it's just a username, append the domain
            bindDn = $"{bindDn}@{_settings.Domain}";
        }

        connection.Bind(bindDn, _settings.ServiceAccountPassword);
    }

    private string? FindUserDn(LdapConnection connection, string username)
    {
        var filter = BuildUserFilter(username);
        var searchResults = connection.Search(
            _settings.BaseDN,
            LdapConnection.ScopeSub,
            filter,
            new[] { "distinguishedName" },
            false);

        if (searchResults.HasMore())
        {
            return searchResults.Next().Dn;
        }

        return null;
    }

    private UserInfo? GetUserInfoFromDn(LdapConnection connection, string dn)
    {
        var searchResults = connection.Search(
            dn,
            LdapConnection.ScopeBase,
            "(objectClass=*)",
            UserAttributes,
            false);

        if (searchResults.HasMore())
        {
            return MapEntryToUserInfo(searchResults.Next());
        }

        return null;
    }

    private static string BuildUserFilter(string username)
    {
        var escapedUsername = EscapeLdapFilter(username);

        // Search by sAMAccountName or userPrincipalName
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

        // Parse user account control flags
        var uacValue = GetAttributeValue(entry, "userAccountControl");
        if (int.TryParse(uacValue, out var uac))
        {
            const int accountDisabled = 0x0002;
            userInfo.IsEnabled = (uac & accountDisabled) == 0;
        }

        // Check if account is locked
        var lockoutTime = GetAttributeValue(entry, "lockoutTime");
        userInfo.IsLocked = !string.IsNullOrEmpty(lockoutTime) && lockoutTime != "0";

        // Parse groups
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

        // Parse timestamps
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
        if (string.IsNullOrEmpty(dn))
        {
            return string.Empty;
        }

        // DN format: CN=GroupName,OU=Groups,DC=company,DC=com
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
        if (string.IsNullOrEmpty(input))
        {
            return string.Empty;
        }

        return input
            .Replace("\\", "\\5c")
            .Replace("*", "\\2a")
            .Replace("(", "\\28")
            .Replace(")", "\\29")
            .Replace("\0", "\\00");
    }

    private static DateTime? ParseLdapTimestamp(string timestamp)
    {
        if (string.IsNullOrEmpty(timestamp))
        {
            return null;
        }

        // Format: yyyyMMddHHmmss.0Z
        if (timestamp.Length >= 14)
        {
            var year = int.Parse(timestamp.Substring(0, 4));
            var month = int.Parse(timestamp.Substring(4, 2));
            var day = int.Parse(timestamp.Substring(6, 2));
            var hour = int.Parse(timestamp.Substring(8, 2));
            var minute = int.Parse(timestamp.Substring(10, 2));
            var second = int.Parse(timestamp.Substring(12, 2));

            return new DateTime(year, month, day, hour, minute, second, DateTimeKind.Utc);
        }

        return null;
    }

    private static DateTime? ParseFileTime(string fileTimeString)
    {
        if (string.IsNullOrEmpty(fileTimeString))
        {
            return null;
        }

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
