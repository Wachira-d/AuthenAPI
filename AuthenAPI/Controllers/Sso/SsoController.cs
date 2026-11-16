using AuthenAPI.Models;
using AuthenAPI.Services;
using AuthenAPI.Utilities;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace AuthenAPI.Controllers.Sso;

/// <summary>
/// OpenID Connect endpoints (passthrough from OpenIddict) and the central login / logout pages
/// </summary>
[ApiExplorerSettings(IgnoreApi = true)]
public class SsoController : Controller
{
    private const string OidcScheme = OpenIddictServerAspNetCoreDefaults.AuthenticationScheme;

    // OpenIddict's form_post page submits itself with this inline script; it is allowed by hash in the CSP.
    private const string FormPostScript = "document.form.submit();";
    private static readonly string FormPostScriptHash =
        "sha256-" + Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(FormPostScript)));

    private readonly SsoClientService _clients;
    private readonly SsoSessionTracker _sessions;
    private readonly IOptionsMonitor<SsoSettings> _settings;
    private readonly IAuditService _audit;
    private readonly ILogger<SsoController> _logger;

    public SsoController(SsoClientService clients, SsoSessionTracker sessions, IOptionsMonitor<SsoSettings> settings,
        IAuditService audit, ILogger<SsoController> logger)
    {
        _clients = clients;
        _sessions = sessions;
        _settings = settings;
        _audit = audit;
        _logger = logger;
    }

    #region /connect/authorize

    [HttpGet("~/connect/authorize"), HttpPost("~/connect/authorize")]
    [IgnoreAntiforgeryToken]
    public async Task<IActionResult> Authorize()
    {
        var request = HttpContext.GetOpenIddictServerRequest()
                      ?? throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        if (!_settings.CurrentValue.Enabled)
        {
            return ForbidOidc(Errors.ServerError, "Single sign-on is disabled.");
        }

        var client = _clients.FindActive(request.ClientId)!; // validated by the OpenIddict handler
        var session = await HttpContext.AuthenticateAsync(SsoSetup.CookieScheme);

        var mustLogin = !session.Succeeded || request.HasPrompt(Prompts.Login) || MaxAgeExceeded(request, session.Principal!);
        if (mustLogin)
        {
            if (request.HasPrompt(Prompts.None))
            {
                return ForbidOidc(Errors.LoginRequired, "The user is not signed in.");
            }

            // Come back here after login. "prompt=login" is dropped so the user is not asked again in a loop.
            var parameters = request.GetParameters()
                .Where(p => p.Key != Parameters.Prompt || !request.HasPrompt(Prompts.Login))
                .Select(p => KeyValuePair.Create(p.Key, (StringValues)p.Value.ToString()));
            var returnUrl = Request.PathBase + "/connect/authorize" + QueryString.Create(parameters);
            var force = request.HasPrompt(Prompts.Login) || MaxAgeExceeded(request, session.Principal) ? "&force=1" : string.Empty;
            return Redirect($"{Request.PathBase}/sso/login?returnUrl={Uri.EscapeDataString(returnUrl)}{force}");
        }

        var user = session.Principal!;

        if (client.AllowedGroups.Count > 0 &&
            !user.FindAll("groups").Any(g => client.AllowedGroups.Contains(g.Value, StringComparer.OrdinalIgnoreCase)))
        {
            await AuditAsync(AuditAction.SsoAuthorize, false, user, $"{client.ClientId}: not in allowed groups");
            return ForbidOidc(Errors.AccessDenied, "Your account is not allowed to use this application.");
        }

        // Remember that this application takes part in the session (for single logout).
        if (!user.HasClaim(SsoSetup.ClaimParticipant, client.ClientId))
        {
            var updated = new ClaimsIdentity(user.Claims, SsoSetup.CookieScheme);
            updated.AddClaim(new Claim(SsoSetup.ClaimParticipant, client.ClientId));
            await HttpContext.SignInAsync(SsoSetup.CookieScheme, new ClaimsPrincipal(updated), session.Properties!);
        }

        var identity = new ClaimsIdentity(OidcScheme, Claims.Name, Claims.Role);
        foreach (var type in new[] { Claims.Subject, Claims.Name, Claims.PreferredUsername, Claims.Email, Claims.GivenName,
                     Claims.FamilyName, "upn", "department", "employee_id", SsoSetup.ClaimSessionId, SsoSetup.ClaimAuthTime })
        {
            var value = user.FindFirstValue(type);
            if (string.IsNullOrEmpty(value)) continue;
            identity.AddClaim(type == SsoSetup.ClaimAuthTime
                ? new Claim(type, value, ClaimValueTypes.Integer64)   // OIDC requires a numeric auth_time
                : new Claim(type, value));
        }
        foreach (var group in user.FindAll("groups")) identity.AddClaim(new Claim("groups", group.Value));

        var granted = request.GetScopes().Intersect(SsoSetup.SupportedScopes).ToList();
        identity.SetScopes(granted);
        identity.SetDestinations(claim => Destinations(claim, granted));

        _clients.RecordLogin(client.ClientId);
        await AuditAsync(AuditAction.SsoAuthorize, true, user, $"Signed in to {client.ClientId}");

        // response_mode=form_post renders a self-submitting form; allow exactly that script.
        Response.Headers.ContentSecurityPolicy = $"default-src 'self'; script-src '{FormPostScriptHash}'; frame-ancestors 'none'";
        return SignIn(new ClaimsPrincipal(identity), OidcScheme);
    }

    private static IEnumerable<string> Destinations(Claim claim, IReadOnlyCollection<string> scopes)
    {
        switch (claim.Type)
        {
            case Claims.Subject:
            case SsoSetup.ClaimSessionId:
            case SsoSetup.ClaimAuthTime:
                yield return OpenIddictConstants.Destinations.AccessToken;
                yield return OpenIddictConstants.Destinations.IdentityToken;
                yield break;

            case Claims.Name or Claims.PreferredUsername or Claims.GivenName or Claims.FamilyName
                or "upn" or "department" or "employee_id" when scopes.Contains(Scopes.Profile):
            case Claims.Email when scopes.Contains(Scopes.Email):
            case "groups" when scopes.Contains(SsoSetup.GroupsScope):
                yield return OpenIddictConstants.Destinations.AccessToken;
                yield return OpenIddictConstants.Destinations.IdentityToken;
                yield break;

            default:
                yield break; // not released to this client
        }
    }

    private static bool MaxAgeExceeded(OpenIddictRequest request, ClaimsPrincipal? user)
    {
        if (request.MaxAge is not { } maxAge || user == null) return false;
        return !long.TryParse(user.FindFirstValue(SsoSetup.ClaimAuthTime), out var authTime) ||
               DateTimeOffset.UtcNow.ToUnixTimeSeconds() - authTime > maxAge;
    }

    private IActionResult ForbidOidc(string error, string description) =>
        Forbid(new AuthenticationProperties(new Dictionary<string, string?>
        {
            [OpenIddictServerAspNetCoreConstants.Properties.Error] = error,
            [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = description
        }), OidcScheme);

    #endregion

    #region /connect/token, /connect/userinfo

    [HttpPost("~/connect/token")]
    [IgnoreAntiforgeryToken]
    [Produces("application/json")]
    public async Task<IActionResult> Token()
    {
        var request = HttpContext.GetOpenIddictServerRequest()
                      ?? throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        if (!request.IsAuthorizationCodeGrantType())
        {
            return ForbidOidc(Errors.UnsupportedGrantType, "Only the authorization_code grant is supported.");
        }

        // The code was validated (signature, expiry, client, redirect_uri, PKCE) by OpenIddict.
        var result = await HttpContext.AuthenticateAsync(OidcScheme);
        if (result.Principal == null)
        {
            return ForbidOidc(Errors.InvalidGrant, "The authorization code is no longer valid.");
        }

        var sid = result.Principal.FindFirstValue(SsoSetup.ClaimSessionId);
        if (sid != null && _sessions.IsRevoked(sid))
        {
            return ForbidOidc(Errors.InvalidGrant, "The user has signed out.");
        }

        return SignIn(result.Principal, OidcScheme);
    }

    [HttpGet("~/connect/userinfo"), HttpPost("~/connect/userinfo")]
    [IgnoreAntiforgeryToken]
    [Produces("application/json")]
    public async Task<IActionResult> Userinfo()
    {
        var result = await HttpContext.AuthenticateAsync(OidcScheme);
        if (result.Principal == null)
        {
            return Challenge(new AuthenticationProperties(new Dictionary<string, string?>
            {
                [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidToken,
                [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The access token is not valid."
            }), OidcScheme);
        }

        var p = result.Principal;
        var claims = new Dictionary<string, object>(StringComparer.Ordinal) { [Claims.Subject] = p.GetClaim(Claims.Subject)! };

        if (p.HasScope(Scopes.Profile))
        {
            foreach (var type in new[] { Claims.Name, Claims.PreferredUsername, Claims.GivenName, Claims.FamilyName, "upn", "department", "employee_id" })
            {
                var v = p.GetClaim(type);
                if (!string.IsNullOrEmpty(v)) claims[type] = v;
            }
        }
        if (p.HasScope(Scopes.Email) && p.GetClaim(Claims.Email) is { Length: > 0 } email) claims[Claims.Email] = email;
        if (p.HasScope(SsoSetup.GroupsScope)) claims["groups"] = p.GetClaims("groups").ToArray();

        return Ok(claims);
    }

    #endregion

    #region /connect/logout

    [HttpGet("~/connect/logout"), HttpPost("~/connect/logout")]
    [IgnoreAntiforgeryToken]
    public async Task<IActionResult> Logout()
    {
        var request = HttpContext.GetOpenIddictServerRequest();
        var session = await HttpContext.AuthenticateAsync(SsoSetup.CookieScheme);
        await HttpContext.SignOutAsync(SsoSetup.CookieScheme);

        var frontChannel = new List<string>();
        if (session.Principal is { } user)
        {
            var sid = user.FindFirstValue(SsoSetup.ClaimSessionId);
            if (sid != null) _sessions.Revoke(sid);

            var issuer = $"{Request.Scheme}://{Request.Host}{Request.PathBase}/";
            foreach (var clientId in user.FindAll(SsoSetup.ClaimParticipant).Select(c => c.Value).Distinct())
            {
                if (_clients.FindActive(clientId)?.FrontChannelLogoutUri is { Length: > 0 } uri)
                {
                    var separator = uri.Contains('?') ? '&' : '?';
                    frontChannel.Add($"{uri}{separator}iss={Uri.EscapeDataString(issuer)}&sid={Uri.EscapeDataString(sid ?? string.Empty)}");
                }
            }
            await AuditAsync(AuditAction.SsoLogout, true, user, $"Signed out of {frontChannel.Count} application(s) by front-channel logout");
        }

        // post_logout_redirect_uri was validated against the registered applications by the OpenIddict handler.
        string next;
        if (!string.IsNullOrEmpty(request?.PostLogoutRedirectUri))
        {
            next = request.PostLogoutRedirectUri;
            if (!string.IsNullOrEmpty(request.State))
            {
                next += (next.Contains('?') ? "&" : "?") + "state=" + Uri.EscapeDataString(request.State);
            }
        }
        else
        {
            next = $"{Request.PathBase}/sso/signed-out";
        }

        var frameOrigins = string.Join(' ', frontChannel.Select(u => new Uri(u).GetLeftPart(UriPartial.Authority)).Distinct());
        Response.Headers.ContentSecurityPolicy =
            $"default-src 'self'; frame-src {(frameOrigins.Length > 0 ? frameOrigins : "'none'")}; frame-ancestors 'none'";

        var frames = string.Concat(frontChannel.Select(u => $"<iframe class=\"hidden-frame\" src=\"{HtmlEncoder.Default.Encode(u)}\" title=\"logout\"></iframe>"));
        return Page("ออกจากระบบแล้ว · Signed out",
            $"""
             <h1>ออกจากระบบแล้ว</h1>
             <p class="sub">Signed out of all applications</p>
             <p>ระบบกำลังออกจากทุกแอปพลิเคชันที่ใช้ SSO และจะพาคุณกลับไปในอีกสักครู่</p>
             <p><a class="button" href="{HtmlEncoder.Default.Encode(next)}">ดำเนินการต่อ · Continue</a></p>
             {frames}
             """,
            refreshTo: next, refreshSeconds: frontChannel.Count > 0 ? 3 : 0);
    }

    [HttpGet("~/sso/signed-out")]
    public IActionResult SignedOut() =>
        Page("ออกจากระบบแล้ว · Signed out",
            "<h1>ออกจากระบบแล้ว</h1><p class=\"sub\">You have been signed out of all applications.</p><p>ปิดหน้าต่างนี้ได้</p>");

    #endregion

    #region /sso/login

    [HttpGet("~/sso/login")]
    public async Task<IActionResult> LoginPage(string? returnUrl, string? force, [FromServices] IAntiforgery antiforgery)
    {
        if (!IsSafeReturnUrl(returnUrl)) returnUrl = null;

        if (force != "1" && returnUrl != null && (await HttpContext.AuthenticateAsync(SsoSetup.CookieScheme)).Succeeded)
        {
            return Redirect(returnUrl);
        }

        return LoginForm(returnUrl, force, null, null, antiforgery);
    }

    [HttpPost("~/sso/login")]
    [IgnoreAntiforgeryToken] // validated explicitly below (MVC's attribute needs the Views services)
    public async Task<IActionResult> LoginSubmit(
        [FromForm] string? username, [FromForm] string? password, [FromForm] string? returnUrl, [FromForm] string? force,
        [FromServices] ILdapService ldap, [FromServices] IAntiforgery antiforgery,
        [FromKeyedServices("sso")] LoginAttemptTracker tracker)
    {
        if (!IsSafeReturnUrl(returnUrl)) returnUrl = null;
        if (!await antiforgery.IsRequestValidAsync(HttpContext))
        {
            return LoginForm(returnUrl, force, null,
                "หน้านี้หมดอายุ กรุณากรอกอีกครั้ง · This page expired, please sign in again.", antiforgery);
        }

        username = (username ?? string.Empty).Trim();
        HttpContext.Items[RequestLogItems.Username] = username;
        var settings = _settings.CurrentValue;

        if (username.Length == 0 || string.IsNullOrEmpty(password) || username.Length > 256 || password.Length > 256)
        {
            return LoginForm(returnUrl, force, username, "กรุณากรอกชื่อผู้ใช้และรหัสผ่าน · Enter your username and password.", antiforgery);
        }

        var ip = HttpContext.GetClientIpString();
        if (!tracker.TryBegin(username, ip, settings.MaxFailedLogins, TimeSpan.FromMinutes(Math.Max(1, settings.LockoutMinutes)), out var retry))
        {
            HttpContext.SetRequestOutcome("SsoLogin:LockedOut");
            await AuditLoginAsync(username, false, $"Locked out ({retry}s left)");
            return LoginForm(returnUrl, force, username,
                $"ลองผิดหลายครั้งเกินไป กรุณาลองใหม่ในอีก {Math.Ceiling(retry / 60.0)} นาที · Too many attempts, try again later.", antiforgery);
        }

        var result = await ldap.AuthenticateWithResultAsync(username, password);
        HttpContext.Items[RequestLogItems.LdapStrategy] = result.Strategy;

        if (!result.Success || result.User == null)
        {
            HttpContext.SetRequestOutcome($"SsoLogin:{result.FailureReason}", result.Message);
            await AuditLoginAsync(username, false, $"{result.FailureReason} via {result.Method}: {result.Message}");
            var message = result.FailureReason switch
            {
                AuthFailureReason.ServerUnavailable or AuthFailureReason.Error =>
                    "ระบบยืนยันตัวตนขัดข้องชั่วคราว กรุณาลองใหม่ภายหลัง · The sign-in service is temporarily unavailable.",
                AuthFailureReason.AccountLocked =>
                    "บัญชีถูกล็อก กรุณาติดต่อฝ่าย IT · Your account is locked. Contact IT.",
                AuthFailureReason.PasswordExpired or AuthFailureReason.PasswordMustChange =>
                    "รหัสผ่านหมดอายุหรือต้องเปลี่ยนก่อนใช้งาน กรุณาเปลี่ยนรหัสผ่าน Windows ก่อน · Your password has expired or must be changed.",
                _ => "ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง · Incorrect username or password."
            };
            return LoginForm(returnUrl, force, username, message, antiforgery);
        }

        tracker.Succeeded(username, ip);
        var sid = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();
        var expires = DateTimeOffset.UtcNow.AddHours(Math.Clamp(settings.SessionHours, 1, 24 * 14));
        await HttpContext.SignInAsync(SsoSetup.CookieScheme, SsoSetup.CreateSessionPrincipal(result.User, sid),
            new AuthenticationProperties { IsPersistent = true, ExpiresUtc = expires, IssuedUtc = DateTimeOffset.UtcNow, AllowRefresh = false });
        _sessions.Started(sid, expires.UtcDateTime);

        HttpContext.SetRequestOutcome("SsoLogin:Success");
        await AuditLoginAsync(username, true, $"SSO session started via {result.Method} ({result.Strategy}), expires {expires:u}");

        return Redirect(returnUrl ?? $"{Request.PathBase}/sso/signed-in");
    }

    [HttpGet("~/sso/signed-in")]
    public async Task<IActionResult> SignedIn()
    {
        var session = await HttpContext.AuthenticateAsync(SsoSetup.CookieScheme);
        if (!session.Succeeded) return Redirect($"{Request.PathBase}/sso/login");
        var name = HtmlEncoder.Default.Encode(session.Principal!.FindFirstValue(Claims.Name) ?? string.Empty);
        return Page("เข้าสู่ระบบแล้ว · Signed in",
            $"<h1>เข้าสู่ระบบแล้ว</h1><p class=\"sub\">Signed in as {name}</p><p>เปิดระบบที่ใช้ SSO ได้เลย โดยไม่ต้องกรอกรหัสผ่านอีก</p>" +
            $"<p><a class=\"button secondary\" href=\"{Request.PathBase}/connect/logout\">ออกจากระบบ · Sign out</a></p>");
    }

    /// <summary>Only our own authorize endpoint is a valid place to return to (no open redirect).</summary>
    private bool IsSafeReturnUrl(string? url) =>
        !string.IsNullOrEmpty(url) &&
        url.StartsWith($"{Request.PathBase}/connect/authorize?", StringComparison.Ordinal) &&
        !url.Contains("//", StringComparison.Ordinal) &&
        !url.Contains('\\');

    private IActionResult LoginForm(string? returnUrl, string? force, string? username, string? error, IAntiforgery antiforgery)
    {
        var tokens = antiforgery.GetAndStoreTokens(HttpContext);
        var enc = HtmlEncoder.Default;

        string? appName = null;
        if (returnUrl != null)
        {
            var clientId = QueryHelpersParse(returnUrl, Parameters.ClientId);
            appName = _clients.FindActive(clientId)?.DisplayName;
        }

        var heading = appName != null
            ? $"<p class=\"app\">เข้าสู่ระบบเพื่อใช้งาน <strong>{enc.Encode(appName)}</strong></p>"
            : string.Empty;
        var errorHtml = error != null ? $"<div class=\"error\" role=\"alert\">{enc.Encode(error)}</div>" : string.Empty;

        return Page("เข้าสู่ระบบ · Sign in",
            $"""
             <h1>เข้าสู่ระบบ</h1>
             <p class="sub">Sign in with your company account</p>
             {heading}
             {errorHtml}
             <form method="post" action="{Request.PathBase}/sso/login" autocomplete="on">
               <input type="hidden" name="{enc.Encode(tokens.FormFieldName)}" value="{enc.Encode(tokens.RequestToken ?? string.Empty)}">
               <input type="hidden" name="returnUrl" value="{enc.Encode(returnUrl ?? string.Empty)}">
               <input type="hidden" name="force" value="{enc.Encode(force ?? string.Empty)}">
               <label for="username">ชื่อผู้ใช้ หรือ อีเมล · Username or email</label>
               <input id="username" name="username" type="text" value="{enc.Encode(username ?? string.Empty)}" autocomplete="username" autocapitalize="off" spellcheck="false" required {(username == null ? "autofocus" : string.Empty)}>
               <label for="password">รหัสผ่าน · Password</label>
               <input id="password" name="password" type="password" autocomplete="current-password" required {(username != null ? "autofocus" : string.Empty)}>
               <button type="submit">เข้าสู่ระบบ · Sign in</button>
             </form>
             <p class="hint">ใช้ชื่อผู้ใช้และรหัสผ่านเดียวกับที่ใช้เข้าเครื่อง Windows (เช่น name@ipsos.com) · Use your Windows account.</p>
             """);
    }

    private static string? QueryHelpersParse(string url, string key)
    {
        var q = url.IndexOf('?');
        if (q < 0) return null;
        var parsed = Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(url[q..]);
        return parsed.TryGetValue(key, out var v) ? v.ToString() : null;
    }

    private ContentResult Page(string title, string body, string? refreshTo = null, int refreshSeconds = 0)
    {
        var enc = HtmlEncoder.Default;
        var refresh = refreshTo != null
            ? $"<meta http-equiv=\"refresh\" content=\"{refreshSeconds};url={enc.Encode(refreshTo)}\">"
            : string.Empty;
        Response.Headers.CacheControl = "no-store";
        return Content($"""
            <!DOCTYPE html>
            <html lang="th">
            <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <meta name="color-scheme" content="light dark">
            <meta name="referrer" content="no-referrer">
            {refresh}
            <title>{enc.Encode(title)}</title>
            <link rel="stylesheet" href="{Request.PathBase}/sso/sso.css">
            <link rel="icon" href="{Request.PathBase}/favicon.svg" type="image/svg+xml">
            </head>
            <body>
            <main class="card">
            <div class="brand"><span class="logo">A</span> AuthenAPI SSO</div>
            {body}
            </main>
            </body>
            </html>
            """, "text/html; charset=utf-8");
    }

    #endregion

    #region Audit

    private Task AuditLoginAsync(string username, bool success, string details) =>
        _audit.LogAsync(new AuditLog
        {
            Action = AuditAction.SsoLogin,
            Username = username,
            Success = success,
            IpAddress = HttpContext.GetClientIpString(),
            UserAgent = Request.Headers.UserAgent.ToString(),
            RequestPath = Request.Path,
            HttpMethod = Request.Method,
            Details = details
        });

    private Task AuditAsync(AuditAction action, bool success, ClaimsPrincipal user, string details) =>
        _audit.LogAsync(new AuditLog
        {
            Action = action,
            Username = user.FindFirstValue(Claims.PreferredUsername) ?? user.Identity?.Name,
            Success = success,
            IpAddress = HttpContext.GetClientIpString(),
            UserAgent = Request.Headers.UserAgent.ToString(),
            RequestPath = Request.Path,
            HttpMethod = Request.Method,
            Details = details
        });

    #endregion
}
