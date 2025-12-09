using AuthenAPI.Models;
using AuthenAPI.Services;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

// Configure LDAP settings
builder.Services.Configure<LdapSettings>(builder.Configuration.GetSection("LdapSettings"));

// Register LDAP service
builder.Services.AddScoped<ILdapService, LdapService>();

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
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthorization();

app.MapControllers();

app.Run();
