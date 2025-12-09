using AuthenAPI.Models;
using AuthenAPI.Services;
using System.Net;

// Enable all TLS versions for LDAPS connections (AD server may use TLS 1.0)
ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls | SecurityProtocolType.Tls11 | SecurityProtocolType.Tls12 | SecurityProtocolType.Tls13;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

// Configure LDAP settings
builder.Services.Configure<LdapSettings>(builder.Configuration.GetSection("LdapSettings"));

// Configure Audit settings
builder.Services.Configure<AuditSettings>(builder.Configuration.GetSection("AuditSettings"));

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
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new Microsoft.OpenApi.Models.OpenApiInfo
    {
        Title = "Active Directory LDAPS API",
        Version = "v1",
        Description = "API for authenticating and querying users from Active Directory via LDAPS"
    });
});

var app = builder.Build();

// Configure the HTTP request pipeline.
// Enable Swagger in all environments
app.UseSwagger();
app.UseSwaggerUI(c =>
{
    c.SwaggerEndpoint("/swagger/v1/swagger.json", "Active Directory LDAPS API v1");
    c.RoutePrefix = "swagger";
});

app.UseHttpsRedirection();

app.UseAuthorization();

app.MapControllers();

app.Run();
