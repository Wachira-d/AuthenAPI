namespace AuthenAPI.Models;

/// <summary>
/// LDAP/Active Directory connection settings
/// </summary>
public class LdapSettings
{
    /// <summary>
    /// LDAP server hostname or IP address
    /// </summary>
    public string Server { get; set; } = string.Empty;

    /// <summary>
    /// LDAP server port (default: 636 for LDAPS)
    /// </summary>
    public int Port { get; set; } = 636;

    /// <summary>
    /// Use SSL/TLS connection (LDAPS)
    /// </summary>
    public bool UseSSL { get; set; } = true;

    /// <summary>
    /// Base DN for user search (e.g., "DC=company,DC=com")
    /// </summary>
    public string BaseDN { get; set; } = string.Empty;

    /// <summary>
    /// Domain name for user authentication (e.g., "company.com")
    /// </summary>
    public string Domain { get; set; } = string.Empty;

    /// <summary>
    /// Service account username for LDAP queries
    /// </summary>
    public string ServiceAccountUsername { get; set; } = string.Empty;

    /// <summary>
    /// Service account password for LDAP queries
    /// </summary>
    public string ServiceAccountPassword { get; set; } = string.Empty;

    /// <summary>
    /// Connection timeout in seconds
    /// </summary>
    public int ConnectionTimeout { get; set; } = 30;

    /// <summary>
    /// Skip SSL certificate validation (use only for development)
    /// </summary>
    public bool SkipCertificateValidation { get; set; } = false;
}
