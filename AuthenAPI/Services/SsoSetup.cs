using Microsoft.AspNetCore;
using AuthenAPI.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using OpenIddict.Server.AspNetCore;
using System.Collections.Concurrent;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace AuthenAPI.Services;

/// <summary>
/// Single sign-on: AuthenAPI as an OpenID Connect provider (authorization code flow + PKCE).
/// OpenIddict runs in "degraded mode": no OpenIddict database; clients come from <see cref="SsoClientService"/>
/// and are validated by the handlers below. Codes and tokens are self-contained and encrypted.
/// </summary>
public static class SsoSetup
{
    public const string CookieScheme = "SsoCookie";
    public const string GroupsScope = "groups";

    // Session claims kept in the SSO cookie
    public const string ClaimSessionId = "sid";
    public const string ClaimAuthTime = "auth_time";
    public const string ClaimChecked = "sso:checked";
    public const string ClaimParticipant = "sso:client";

    /// <summary>Random id put into each authorization code (never into tokens) to make the code single-use</summary>
    public const string ClaimCodeId = "sso:code_id";

    public static readonly string[] SupportedScopes = { Scopes.OpenId, Scopes.Profile, Scopes.Email, GroupsScope };

    public static readonly string[] SupportedClaims =
    {
        Claims.Subject, Claims.Name, Claims.PreferredUsername, Claims.Email, Claims.GivenName, Claims.FamilyName,
        "upn", "groups", "department", "employee_id"
    };

    public static void AddSso(this WebApplicationBuilder builder)
    {
        var services = builder.Services;
        services.Configure<SsoSettings>(builder.Configuration.GetSection("SsoSettings"));
        services.AddSingleton<SsoClientService>();
        services.AddHostedService(sp => sp.GetRequiredService<SsoClientService>());
        services.AddSingleton<SsoKeyStore>();
        services.AddSingleton<SsoSessionTracker>();
        var ssoSettings = builder.Configuration.GetSection("SsoSettings").Get<SsoSettings>() ?? new SsoSettings();
        services.AddKeyedSingleton("sso", (_, _) => new LoginAttemptTracker { MaxFailuresPerIp = Math.Max(5, ssoSettings.MaxFailedLoginsPerIp) });
        services.AddAntiforgery(o =>
        {
            o.Cookie.Name = "AuthenAPI.SSO.XSRF";
            o.Cookie.SameSite = SameSiteMode.Strict;
            o.Cookie.SecurePolicy = CookieSecurePolicy.Always;
            o.FormFieldName = "__xsrf";
        });

        var sso = builder.Configuration.GetSection("SsoSettings").Get<SsoSettings>() ?? new SsoSettings();

        services.AddAuthentication()
            .AddCookie(CookieScheme, o =>
            {
                o.Cookie.Name = "AuthenAPI.SSO";
                o.Cookie.HttpOnly = true;
                // Lax: the cookie must travel on the top-level redirect from another site to /connect/authorize.
                o.Cookie.SameSite = SameSiteMode.Lax;
                o.Cookie.SecurePolicy = CookieSecurePolicy.Always;
                o.SlidingExpiration = false;
                o.ExpireTimeSpan = TimeSpan.FromHours(Math.Clamp(sso.SessionHours, 1, 24 * 14));
                o.Events = new CookieAuthenticationEvents
                {
                    OnRedirectToLogin = ctx => { ctx.Response.StatusCode = 401; return Task.CompletedTask; },
                    OnValidatePrincipal = ValidateSessionAsync
                };
            });

        services.AddOpenIddict()
            .AddServer(o =>
            {
                o.SetAuthorizationEndpointUris("connect/authorize")
                 .SetTokenEndpointUris("connect/token")
                 .SetUserinfoEndpointUris("connect/userinfo")
                 .SetLogoutEndpointUris("connect/logout");

                o.AllowAuthorizationCodeFlow();
                o.RegisterScopes(SupportedScopes);
                o.RegisterClaims(SupportedClaims);

                o.SetAuthorizationCodeLifetime(TimeSpan.FromMinutes(5));
                o.SetIdentityTokenLifetime(TimeSpan.FromMinutes(Math.Clamp(sso.IdentityTokenMinutes, 1, 60)));
                o.SetAccessTokenLifetime(TimeSpan.FromMinutes(Math.Clamp(sso.AccessTokenMinutes, 1, 240)));

                if (!string.IsNullOrWhiteSpace(sso.Issuer)) o.SetIssuer(new Uri(sso.Issuer));

                o.EnableDegradedMode();
                o.AddEventHandler<ValidateAuthorizationRequestContext>(b => b.UseInlineHandler(ValidateAuthorizationRequest));
                o.AddEventHandler<ValidateTokenRequestContext>(b => b.UseInlineHandler(ValidateTokenRequest));
                o.AddEventHandler<ValidateLogoutRequestContext>(b => b.UseInlineHandler(ValidateLogoutRequest));

                o.UseAspNetCore()
                 .EnableAuthorizationEndpointPassthrough()
                 .EnableTokenEndpointPassthrough()
                 .EnableUserinfoEndpointPassthrough()
                 .EnableLogoutEndpointPassthrough();
            });

        // Signing / encryption keys come from SsoKeyStore (persisted, shared across servers).
        services.AddSingleton<IConfigureOptions<OpenIddictServerOptions>, SsoCredentialsSetup>();
    }

    #region OpenIddict validation handlers (degraded mode)

    private static SsoClientService Clients(BaseContext context) =>
        context.Transaction.GetHttpRequest()!.HttpContext.RequestServices.GetRequiredService<SsoClientService>();

    private static ValueTask ValidateAuthorizationRequest(ValidateAuthorizationRequestContext context)
    {
        var client = Clients(context).FindActive(context.ClientId);
        if (client == null)
        {
            context.Reject(Errors.InvalidClient, "The application is not registered for single sign-on, or is disabled.");
            return default;
        }

        if (string.IsNullOrEmpty(context.RedirectUri) || !client.RedirectUris.Contains(context.RedirectUri, StringComparer.Ordinal))
        {
            context.Reject(Errors.InvalidRequest, "The redirect_uri is not registered for this application.");
            return default;
        }

        if (client.RequirePkce && string.IsNullOrEmpty(context.Request.CodeChallenge))
        {
            context.Reject(Errors.InvalidRequest, "This application must use PKCE (code_challenge).");
            return default;
        }

        if (!string.IsNullOrEmpty(context.Request.CodeChallenge) &&
            context.Request.CodeChallengeMethod is not CodeChallengeMethods.Sha256)
        {
            context.Reject(Errors.InvalidRequest, "Only code_challenge_method=S256 is supported.");
        }
        return default;
    }

    private static ValueTask ValidateTokenRequest(ValidateTokenRequestContext context)
    {
        if (!context.Request.IsAuthorizationCodeGrantType())
        {
            context.Reject(Errors.UnsupportedGrantType, "Only the authorization_code grant is supported.");
            return default;
        }

        var clients = Clients(context);
        var client = clients.FindActive(context.ClientId);
        if (client == null)
        {
            context.Reject(Errors.InvalidClient, "Unknown or disabled client.");
            return default;
        }

        if (client.Type == SsoClientTypes.Confidential && !clients.VerifySecret(client, context.ClientSecret))
        {
            context.Reject(Errors.InvalidClient, "Invalid client credentials.");
            return default;
        }

        return default;
    }

    private static ValueTask ValidateLogoutRequest(ValidateLogoutRequestContext context)
    {
        var uri = context.PostLogoutRedirectUri;
        if (string.IsNullOrEmpty(uri)) return default;

        if (Clients(context).FindByPostLogoutUri(uri, context.Request.ClientId) == null)
        {
            context.Reject(Errors.InvalidRequest, "The post_logout_redirect_uri is not registered.");
        }
        return default;
    }

    #endregion

    #region SSO session validation

    /// <summary>
    /// Ends SSO sessions of accounts that were disabled or removed in AD (checked every few minutes).
    /// If AD cannot be reached the session is kept, so a directory hiccup does not sign everyone out.
    /// </summary>
    private static async Task ValidateSessionAsync(CookieValidatePrincipalContext context)
    {
        var services = context.HttpContext.RequestServices;
        var settings = services.GetRequiredService<IOptionsMonitor<SsoSettings>>().CurrentValue;
        var tracker = services.GetRequiredService<SsoSessionTracker>();
        var principal = context.Principal;
        var sid = principal?.FindFirstValue(ClaimSessionId);

        if (principal == null || !settings.Enabled || sid == null || tracker.IsRevoked(sid))
        {
            context.RejectPrincipal();
            return;
        }

        var checkedTicks = long.TryParse(principal.FindFirstValue(ClaimChecked), out var t) ? t : 0;
        if (DateTime.UtcNow - new DateTime(checkedTicks, DateTimeKind.Utc) < TimeSpan.FromMinutes(Math.Max(1, settings.AccountRecheckMinutes)))
        {
            return;
        }

        var ldap = services.GetRequiredService<ILdapService>();
        var upn = principal.FindFirstValue("upn") ?? principal.FindFirstValue(Claims.PreferredUsername) ?? principal.Identity?.Name;
        var user = upn == null ? null : await ldap.GetUserFreshAsync(upn);

        if (user == null)
        {
            if (await ldap.TestConnectionAsync())
            {
                context.RejectPrincipal(); // AD answered and the account is gone
                tracker.Revoke(sid);
            }
            return;
        }

        if (!user.IsEnabled)
        {
            context.RejectPrincipal();
            tracker.Revoke(sid);
            return;
        }

        var identity = new ClaimsIdentity(principal.Claims.Where(c => c.Type is not (ClaimChecked or "groups" or "group_dn")), CookieScheme);
        identity.AddClaim(new Claim(ClaimChecked, DateTime.UtcNow.Ticks.ToString()));
        foreach (var g in user.Groups) identity.AddClaim(new Claim("groups", g));
        foreach (var dn in user.GroupDistinguishedNames) identity.AddClaim(new Claim("group_dn", dn));
        context.ReplacePrincipal(new ClaimsPrincipal(identity));
        context.ShouldRenew = true;
    }

    /// <summary>Claims stored in the SSO cookie after a successful login</summary>
    public static ClaimsPrincipal CreateSessionPrincipal(UserInfo user, string sessionId)
    {
        var upn = (string.IsNullOrWhiteSpace(user.UserPrincipalName) ? user.SamAccountName : user.UserPrincipalName).Trim();
        var identity = new ClaimsIdentity(CookieScheme, Claims.Name, Claims.Role);
        identity.AddClaim(new Claim(Claims.Subject, upn.ToLowerInvariant()));
        identity.AddClaim(new Claim(Claims.Name, string.IsNullOrWhiteSpace(user.DisplayName) ? upn : user.DisplayName));
        identity.AddClaim(new Claim(Claims.PreferredUsername, upn));
        identity.AddClaim(new Claim("upn", upn));
        identity.AddClaim(new Claim("sam", user.SamAccountName ?? string.Empty));
        if (!string.IsNullOrWhiteSpace(user.Email)) identity.AddClaim(new Claim(Claims.Email, user.Email));
        if (!string.IsNullOrWhiteSpace(user.FirstName)) identity.AddClaim(new Claim(Claims.GivenName, user.FirstName));
        if (!string.IsNullOrWhiteSpace(user.LastName)) identity.AddClaim(new Claim(Claims.FamilyName, user.LastName));
        if (!string.IsNullOrWhiteSpace(user.Department)) identity.AddClaim(new Claim("department", user.Department));
        if (!string.IsNullOrWhiteSpace(user.EmployeeId)) identity.AddClaim(new Claim("employee_id", user.EmployeeId));
        foreach (var g in user.Groups) identity.AddClaim(new Claim("groups", g));
        foreach (var dn in user.GroupDistinguishedNames) identity.AddClaim(new Claim("group_dn", dn));
        identity.AddClaim(new Claim(ClaimSessionId, sessionId));
        identity.AddClaim(new Claim(ClaimAuthTime, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString()));
        identity.AddClaim(new Claim(ClaimChecked, DateTime.UtcNow.Ticks.ToString()));
        return new ClaimsPrincipal(identity);
    }

    #endregion
}

/// <summary>Adds the persisted RSA signing key and AES encryption key to OpenIddict</summary>
public sealed class SsoCredentialsSetup : IConfigureOptions<OpenIddictServerOptions>
{
    private readonly SsoKeyStore _keys;

    public SsoCredentialsSetup(SsoKeyStore keys) => _keys = keys;

    public void Configure(OpenIddictServerOptions options)
    {
        var k = _keys.Keys;
        var rsa = RSA.Create();
        rsa.ImportPkcs8PrivateKey(Convert.FromBase64String(k.SigningRsaPrivateKey), out _);
        options.SigningCredentials.Add(new SigningCredentials(new RsaSecurityKey(rsa) { KeyId = k.SigningKeyId }, SecurityAlgorithms.RsaSha256));
        options.EncryptionCredentials.Add(new EncryptingCredentials(
            new SymmetricSecurityKey(Convert.FromBase64String(k.EncryptionKey)) { KeyId = k.EncryptionKeyId },
            SecurityAlgorithms.Aes256KW, SecurityAlgorithms.Aes256CbcHmacSha512));
    }
}

/// <summary>
/// SSO state that must hold across requests and, with a database, across servers:
/// sessions ended by logout or account disable, and authorization codes already exchanged.
/// Without a database it is kept in memory (single server).
/// </summary>
public sealed class SsoSessionTracker
{
    private readonly AuthenAPI.Data.Database _database;
    private readonly ILogger<SsoSessionTracker> _logger;
    private readonly ConcurrentDictionary<string, DateTime> _active = new();
    private readonly ConcurrentDictionary<string, DateTime> _revoked = new();
    private readonly ConcurrentDictionary<string, DateTime> _redeemed = new();
    private long _lastCleanupTicks;

    public SsoSessionTracker(AuthenAPI.Data.Database database, ILogger<SsoSessionTracker> logger)
    {
        _database = database;
        _logger = logger;
    }

    public void Started(string sid, DateTime expiresUtc)
    {
        _active[sid] = expiresUtc;
        Cleanup();
    }

    public void Revoke(string sid, DateTime? expiresUtc = null)
    {
        var until = expiresUtc ?? (_active.TryGetValue(sid, out var e) ? e : DateTime.UtcNow.AddDays(14));
        _active.TryRemove(sid, out _);
        _revoked[sid] = until;

        if (!_database.Enabled) return;
        try
        {
            using var db = _database.CreateContext();
            if (!db.SsoRevokedSessions.Any(r => r.SessionId == sid))
            {
                db.SsoRevokedSessions.Add(new AuthenAPI.Data.SsoRevokedSession { SessionId = sid, ExpiresAt = until });
                db.SaveChanges();
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning("Could not record ended SSO session in the database: {Error}", ex.GetBaseException().Message);
        }
    }

    public bool IsRevoked(string sid)
    {
        if (_revoked.ContainsKey(sid)) return true;
        if (!_database.Enabled) return false;
        try
        {
            using var db = _database.CreateContext();
            if (db.SsoRevokedSessions.Any(r => r.SessionId == sid))
            {
                _revoked[sid] = DateTime.UtcNow.AddDays(1);
                return true;
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning("Could not check ended SSO sessions in the database: {Error}", ex.GetBaseException().Message);
        }
        return false;
    }

    /// <summary>
    /// Mark an authorization code (by the unique id embedded in it at issue time) as used.
    /// False when it was already used, here or on another server. Fails closed if the shared store is unreachable.
    /// </summary>
    public bool TryRedeemCode(string codeId)
    {
        var expires = DateTime.UtcNow.AddMinutes(10);
        if (!_redeemed.TryAdd(codeId, expires)) return false;
        Cleanup();

        if (!_database.Enabled) return true;
        try
        {
            using var db = _database.CreateContext();
            db.SsoRedeemedCodes.Add(new AuthenAPI.Data.SsoRedeemedCode { CodeId = codeId, ExpiresAt = expires });
            db.SaveChanges();
            return true;
        }
        catch (Microsoft.EntityFrameworkCore.DbUpdateException)
        {
            return false; // primary key violation: redeemed on another server
        }
        catch (Exception ex)
        {
            _logger.LogWarning("Could not record redeemed code in the database: {Error}", ex.GetBaseException().Message);
            return false;
        }
    }

    public int ActiveCount
    {
        get
        {
            Cleanup();
            return _active.Count;
        }
    }

    private void Cleanup()
    {
        var now = DateTime.UtcNow;
        var last = Interlocked.Read(ref _lastCleanupTicks);
        if (now.Ticks - last < TimeSpan.TicksPerMinute || Interlocked.CompareExchange(ref _lastCleanupTicks, now.Ticks, last) != last) return;

        foreach (var (k, v) in _active) if (v < now) _active.TryRemove(k, out _);
        foreach (var (k, v) in _revoked) if (v < now) _revoked.TryRemove(k, out _);
        foreach (var (k, v) in _redeemed) if (v < now) _redeemed.TryRemove(k, out _);

        if (!_database.Enabled) return;
        try
        {
            using var db = _database.CreateContext();
            db.SsoRedeemedCodes.Where(c => c.ExpiresAt < now).ExecuteDelete();
            db.SsoRevokedSessions.Where(c => c.ExpiresAt < now).ExecuteDelete();
        }
        catch (Exception ex)
        {
            _logger.LogDebug("SSO state cleanup failed: {Error}", ex.GetBaseException().Message);
        }
    }
}
