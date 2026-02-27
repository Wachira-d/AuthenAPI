using AuthenAPI.Middleware;
using AuthenAPI.Models;
using AuthenAPI.Services;
using Microsoft.OpenApi.Models;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

// Configure LDAP settings
builder.Services.Configure<LdapSettings>(builder.Configuration.GetSection("LdapSettings"));

// Configure Audit settings
builder.Services.Configure<AuditSettings>(builder.Configuration.GetSection("AuditSettings"));

// Configure Security settings
builder.Services.Configure<SecuritySettings>(builder.Configuration.GetSection("SecuritySettings"));

// Add Memory Cache for LDAP user caching
builder.Services.AddMemoryCache(options =>
{
    options.SizeLimit = 1000; // Max 1000 cached items
});

// Register LDAP service
builder.Services.AddScoped<ILdapService, LdapService>();

// Register Audit service (singleton for in-memory storage)
builder.Services.AddSingleton<IAuditService, AuditService>();

// Register Audit Auto-Purge background service
builder.Services.AddHostedService<AuditPurgeService>();

builder.Services.AddControllers();

// Configure Swagger with API Key authentication
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "Active Directory LDAPS API",
        Version = "v1",
        Description = "API for authenticating and querying users from Active Directory via LDAPS"
    });

    // Add API Key authentication to Swagger
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
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "ApiKey"
                }
            },
            Array.Empty<string>()
        }
    });
});

var app = builder.Build();

// Configure the HTTP request pipeline.

// Security headers should be first
app.UseSecurityHeaders();

// Enable Swagger in all environments
app.UseSwagger();
app.UseSwaggerUI(c =>
{
    c.SwaggerEndpoint("/swagger/v1/swagger.json", "Active Directory LDAPS API v1");
    c.RoutePrefix = "swagger";
});

app.UseHttpsRedirection();

// IP Whitelist filtering
app.UseIpWhitelist();

// Rate limiting
app.UseRateLimiting();

// API Key authentication
app.UseApiKeyAuth();

app.UseAuthorization();

app.MapControllers();

// Add health check endpoint
app.MapGet("/health", () => Results.Ok(new { status = "healthy", timestamp = DateTime.UtcNow }))
    .ExcludeFromDescription();

app.Run();
