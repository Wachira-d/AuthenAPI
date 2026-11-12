using AuthenAPI.Data;
using AuthenAPI.Middleware;
using AuthenAPI.Models;
using AuthenAPI.Services;
using AuthenAPI.Utilities;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.OpenApi.Models;
using System.Text.Json.Serialization;

// CLI helper for local break-glass admin accounts:  AuthenAPI.exe hash-password "my long password"
if (args.Length > 0 && args[0].Equals("hash-password", StringComparison.OrdinalIgnoreCase))
{
    var plain = args.Length > 1 ? args[1] : PromptPassword();
    if (string.IsNullOrEmpty(plain) || plain.Length < 12)
    {
        Console.Error.WriteLine("Password must be at least 12 characters.");
        return 1;
    }
    Console.WriteLine(LocalPasswordHasher.Hash(plain));
    return 0;
}

var builder = WebApplication.CreateBuilder(args);

// EF Core logs every SQL command at Information level; keep only warnings and errors.
builder.Logging.AddFilter("Microsoft.EntityFrameworkCore", LogLevel.Warning);

// ---------------------------------------------------------------------------
// Data directory (API keys, runtime settings, Data Protection keys)
// ---------------------------------------------------------------------------
var dataDirectory = builder.Configuration["DataDirectory"];
if (string.IsNullOrWhiteSpace(dataDirectory)) dataDirectory = "App_Data";
if (!Path.IsPathRooted(dataDirectory)) dataDirectory = Path.Combine(builder.Environment.ContentRootPath, dataDirectory);
var dataPaths = new DataPaths(dataDirectory);
try
{
    Directory.CreateDirectory(dataPaths.DataDirectory);
}
catch (Exception ex)
{
    Console.Error.WriteLine($"Cannot create data directory {dataPaths.DataDirectory}: {ex.Message}");
}
builder.Services.AddSingleton(dataPaths);

// Keys protect the admin session cookie and the stored service-account password.
// Persisted so sessions and secrets survive app-pool recycles; DPAPI-encrypted at rest on Windows.
var dataProtection = builder.Services.AddDataProtection()
    .SetApplicationName("AuthenAPI")
    .PersistKeysToFileSystem(new DirectoryInfo(dataPaths.DataProtectionKeysDirectory));
if (OperatingSystem.IsWindows())
{
    dataProtection.ProtectKeysWithDpapi(protectToLocalMachine: true);
}

// ---------------------------------------------------------------------------
// Settings: appsettings.json + runtime overrides from the admin portal
// ---------------------------------------------------------------------------
builder.Services.Configure<LdapSettings>(builder.Configuration.GetSection("LdapSettings"));
builder.Services.Configure<AuditSettings>(builder.Configuration.GetSection("AuditSettings"));
builder.Services.Configure<SecuritySettings>(builder.Configuration.GetSection("SecuritySettings"));
builder.Services.Configure<AdminSettings>(builder.Configuration.GetSection("AdminSettings"));

builder.Services.AddSingleton<RuntimeSettingsStore>();
builder.Services.AddSingleton<RuntimeOverridesPostConfigure>();
builder.Services.AddSingleton<IPostConfigureOptions<LdapSettings>>(sp => sp.GetRequiredService<RuntimeOverridesPostConfigure>());
builder.Services.AddSingleton<IPostConfigureOptions<SecuritySettings>>(sp => sp.GetRequiredService<RuntimeOverridesPostConfigure>());
builder.Services.AddSingleton<IPostConfigureOptions<AuditSettings>>(sp => sp.GetRequiredService<RuntimeOverridesPostConfigure>());
builder.Services.AddSingleton<IPostConfigureOptions<AdminSettings>>(sp => sp.GetRequiredService<RuntimeOverridesPostConfigure>());
builder.Services.AddSingleton<IOptionsChangeTokenSource<LdapSettings>, RuntimeOverridesChangeTokenSource<LdapSettings>>();
builder.Services.AddSingleton<IOptionsChangeTokenSource<SecuritySettings>, RuntimeOverridesChangeTokenSource<SecuritySettings>>();
builder.Services.AddSingleton<IOptionsChangeTokenSource<AuditSettings>, RuntimeOverridesChangeTokenSource<AuditSettings>>();
builder.Services.AddSingleton<IOptionsChangeTokenSource<AdminSettings>, RuntimeOverridesChangeTokenSource<AdminSettings>>();

// ---------------------------------------------------------------------------
// Optional SQL Server storage (ConnectionStrings:AuthenAPI). Without it, files in App_Data / logs are used.
// ---------------------------------------------------------------------------
var connectionString = builder.Configuration.GetConnectionString("AuthenAPI");
if (!string.IsNullOrWhiteSpace(connectionString))
{
    builder.Services.AddDbContextFactory<AuthenDbContext>(o => o.UseSqlServer(connectionString, sql =>
    {
        sql.CommandTimeout(30);
        sql.EnableRetryOnFailure(maxRetryCount: 2, maxRetryDelay: TimeSpan.FromSeconds(3), errorNumbersToAdd: null);
    }));
}
builder.Services.AddSingleton<Database>();
builder.Services.AddSingleton<DatabaseLogWriter>();
builder.Services.AddHostedService(sp => sp.GetRequiredService<DatabaseLogWriter>());

// ---------------------------------------------------------------------------
// Application services
// ---------------------------------------------------------------------------
builder.Services.AddMemoryCache(options =>
{
    options.SizeLimit = 1000; // Max 1000 cached items
    options.TrackStatistics = true;
});

builder.Services.AddSingleton<LdapStrategyCache>();
builder.Services.AddScoped<ILdapService, LdapService>();

builder.Services.AddSingleton<IAuditService, AuditService>();
builder.Services.AddHostedService<AuditPurgeService>();

builder.Services.AddSingleton<ApiKeyService>();
builder.Services.AddHostedService(sp => sp.GetRequiredService<ApiKeyService>());

builder.Services.AddSingleton<RequestLogService>();
builder.Services.AddHostedService(sp => sp.GetRequiredService<RequestLogService>());

builder.Services.AddSingleton<HealthMonitorService>();
builder.Services.AddHostedService(sp => sp.GetRequiredService<HealthMonitorService>());

builder.Services.AddSingleton<LoginAttemptTracker>();
builder.Services.AddScoped<AdminAuthService>();

// ---------------------------------------------------------------------------
// Admin portal authentication (cookie) and authorization (Admin / Viewer)
// ---------------------------------------------------------------------------
builder.Services.AddAuthentication(AdminRoles.Scheme)
    .AddCookie(AdminRoles.Scheme, options =>
    {
        options.Cookie.Name = "AuthenAPI.Admin";
        options.Cookie.HttpOnly = true;
        options.Cookie.SameSite = SameSiteMode.Strict;
        options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
        options.SlidingExpiration = true;
        options.Events = new CookieAuthenticationEvents
        {
            // API semantics: never redirect to a login page.
            OnRedirectToLogin = ctx => WriteJsonError(ctx.Response, StatusCodes.Status401Unauthorized, "Not signed in"),
            OnRedirectToAccessDenied = ctx => WriteJsonError(ctx.Response, StatusCodes.Status403Forbidden, "Insufficient permission"),
            OnValidatePrincipal = AdminAuthService.ValidatePrincipalAsync
        };
    });

builder.Services.AddOptions<CookieAuthenticationOptions>(AdminRoles.Scheme)
    .Configure<IOptionsMonitor<AdminSettings>>((options, admin) =>
        options.ExpireTimeSpan = TimeSpan.FromMinutes(Math.Clamp(admin.CurrentValue.SessionTimeoutMinutes, 5, 1440)));

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy(AdminRoles.ReadPolicy, p => p
        .AddAuthenticationSchemes(AdminRoles.Scheme)
        .RequireAuthenticatedUser()
        .RequireRole(AdminRoles.Admin, AdminRoles.Viewer));
    options.AddPolicy(AdminRoles.WritePolicy, p => p
        .AddAuthenticationSchemes(AdminRoles.Scheme)
        .RequireAuthenticatedUser()
        .RequireRole(AdminRoles.Admin));
});

builder.Services.AddControllers()
    .AddJsonOptions(o => o.JsonSerializerOptions.Converters.Add(new JsonStringEnumConverter()));

// Configure Swagger with API Key authentication (admin endpoints are hidden)
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "Active Directory LDAPS API",
        Version = "v1",
        Description = "API for authenticating and querying users from Active Directory via LDAPS"
    });

    c.AddSecurityDefinition("ApiKey", new OpenApiSecurityScheme
    {
        Type = SecuritySchemeType.ApiKey,
        In = ParameterLocation.Header,
        Name = "X-API-Key",
        Description = "API Key authentication. Enter your API key."
    });

    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference { Type = ReferenceType.SecurityScheme, Id = "ApiKey" }
            },
            Array.Empty<string>()
        }
    });
});

var app = builder.Build();

// Create/upgrade database tables before any store loads its data (keys, settings).
app.Services.GetRequiredService<Database>().Initialize();

// ---------------------------------------------------------------------------
// HTTP pipeline
// ---------------------------------------------------------------------------
app.UseSecurityHeaders();

// Early, so requests rejected by the whitelist / rate limiter / API-key check are logged too.
app.UseRequestLogging();

app.UseSwagger();
app.UseSwaggerUI(c =>
{
    c.SwaggerEndpoint("/swagger/v1/swagger.json", "Active Directory LDAPS API v1");
    c.RoutePrefix = "swagger";
});

app.UseHttpsRedirection();

app.UseIpWhitelist();
app.UseRateLimiting();

// Admin portal UI (wwwroot/admin). Hidden entirely when AdminSettings:Enabled is false.
app.Use(async (context, next) =>
{
    if (context.IsAdminPath() && !context.RequestServices.GetRequiredService<IOptionsMonitor<AdminSettings>>().CurrentValue.Enabled)
    {
        context.Response.StatusCode = StatusCodes.Status404NotFound;
        return;
    }

    // "/admin" -> "/admin/" so relative asset paths resolve. Not a routed endpoint: routing treats
    // "/admin/" as the same route, which would stop the static-file middleware from serving index.html.
    // Site root has no page of its own: send people to the admin portal.
    if (context.Request.Path == "/" && HttpMethods.IsGet(context.Request.Method))
    {
        context.Response.Redirect("/admin/");
        return;
    }

    if (context.Request.Path.Equals("/admin", StringComparison.OrdinalIgnoreCase))
    {
        context.Response.Redirect("/admin/");
        return;
    }

    await next();
});
app.UseDefaultFiles();
app.UseStaticFiles();

app.UseApiKeyAuth();

app.UseAuthentication();
app.UseAdminCsrfProtection();

// A database outage while saving a key or setting must give the admin a clear message, not a bare 500.
app.Use(async (context, next) =>
{
    try
    {
        await next();
    }
    catch (Exception ex) when (context.IsAdminPath() && !context.Response.HasStarted &&
                               (ex is DbUpdateException || ex.GetBaseException() is Microsoft.Data.SqlClient.SqlException))
    {
        context.RequestServices.GetRequiredService<ILogger<Database>>().LogError(ex, "Database error on {Path}", context.Request.Path);
        context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
        await context.Response.WriteAsJsonAsync(ApiResponse.Fail("Database is unavailable. The change was not saved.",
            ex.GetBaseException().Message));
    }
});
app.UseAuthorization();

app.MapControllers();

// Liveness: the process is up.
app.MapGet("/health", () => Results.Ok(new { status = "healthy", timestamp = DateTime.UtcNow }))
    .ExcludeFromDescription();

// Readiness for external monitors: 503 when the last LDAP probe failed. No internal details exposed.
app.MapGet("/health/ready", (HealthMonitorService health) => health.LastProbeOk switch
    {
        true => Results.Ok(new { status = "ready" }),
        false => Results.Json(new { status = "unavailable" }, statusCode: StatusCodes.Status503ServiceUnavailable),
        null => Results.Ok(new { status = "starting" })
    })
    .ExcludeFromDescription();

WarnIfNoAdmins(app);

app.Run();
return 0;

static Task WriteJsonError(HttpResponse response, int statusCode, string message)
{
    response.StatusCode = statusCode;
    return response.WriteAsJsonAsync(ApiResponse.Fail(message));
}

static void WarnIfNoAdmins(WebApplication app)
{
    var admin = app.Services.GetRequiredService<IOptionsMonitor<AdminSettings>>().CurrentValue;
    if (admin.Enabled && admin.AdminUsers.Count == 0 && admin.AdminGroups.Count == 0 &&
        !admin.LocalAdmins.Any(a => !string.IsNullOrWhiteSpace(a.PasswordHash)))
    {
        app.Logger.LogWarning(
            "Admin portal has no administrators. Add your AD username to AdminSettings:AdminUsers in appsettings.json, " +
            "or create a break-glass account: run 'AuthenAPI.exe hash-password' and add it to AdminSettings:LocalAdmins.");
    }
}

static string PromptPassword()
{
    Console.Write("Password: ");
    var sb = new System.Text.StringBuilder();
    while (!Console.IsInputRedirected)
    {
        var key = Console.ReadKey(intercept: true);
        if (key.Key == ConsoleKey.Enter) break;
        if (key.Key == ConsoleKey.Backspace) { if (sb.Length > 0) sb.Length--; continue; }
        sb.Append(key.KeyChar);
    }
    Console.WriteLine();
    return Console.IsInputRedirected ? Console.ReadLine() ?? string.Empty : sb.ToString();
}
