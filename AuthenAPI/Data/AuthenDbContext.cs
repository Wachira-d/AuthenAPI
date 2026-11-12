using AuthenAPI.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.ChangeTracking;
using System.Text.Json;

namespace AuthenAPI.Data;

/// <summary>Single-row table holding the runtime settings overrides as JSON</summary>
public class RuntimeSettingsRow
{
    public int Id { get; set; } = 1;
    public string Json { get; set; } = "{}";
    public int Version { get; set; }
    public DateTime UpdatedAt { get; set; }
    public string? UpdatedBy { get; set; }
}

/// <summary>Every saved version of the runtime settings (replaces file backups when a database is used)</summary>
public class RuntimeSettingsHistoryRow
{
    public long Id { get; set; }
    public int Version { get; set; }
    public string Json { get; set; } = "{}";
    public DateTime ChangedAt { get; set; }
    public string? ChangedBy { get; set; }
}

public class AuthenDbContext : DbContext
{
    public AuthenDbContext(DbContextOptions<AuthenDbContext> options) : base(options) { }

    public DbSet<ManagedApiKey> ApiKeys => Set<ManagedApiKey>();
    public DbSet<RuntimeSettingsRow> RuntimeSettings => Set<RuntimeSettingsRow>();
    public DbSet<RuntimeSettingsHistoryRow> RuntimeSettingsHistory => Set<RuntimeSettingsHistoryRow>();
    public DbSet<RequestLogEntry> RequestLogs => Set<RequestLogEntry>();
    public DbSet<AuditLog> AuditLogs => Set<AuditLog>();

    protected override void OnModelCreating(ModelBuilder b)
    {
        var listConverter = new Microsoft.EntityFrameworkCore.Storage.ValueConversion.ValueConverter<List<string>, string>(
            v => JsonSerializer.Serialize(v, (JsonSerializerOptions?)null),
            v => string.IsNullOrEmpty(v) ? new List<string>() : JsonSerializer.Deserialize<List<string>>(v, (JsonSerializerOptions?)null) ?? new List<string>());
        var listComparer = new ValueComparer<List<string>>(
            (a, c) => (a ?? new()).SequenceEqual(c ?? new()),
            v => v.Aggregate(0, (h, s) => HashCode.Combine(h, s.GetHashCode())),
            v => v.ToList());

        b.Entity<ManagedApiKey>(e =>
        {
            e.ToTable("ApiKeys");
            e.HasKey(x => x.Id);
            e.Property(x => x.Scopes).HasConversion(listConverter, listComparer);
            e.Property(x => x.AllowedIps).HasConversion(listConverter, listComparer);
        });

        b.Entity<RuntimeSettingsRow>(e =>
        {
            e.ToTable("RuntimeSettings");
            e.HasKey(x => x.Id);
            e.Property(x => x.Id).ValueGeneratedNever();
        });

        b.Entity<RuntimeSettingsHistoryRow>(e =>
        {
            e.ToTable("RuntimeSettingsHistory");
            e.HasKey(x => x.Id);
        });

        b.Entity<RequestLogEntry>(e =>
        {
            e.ToTable("RequestLogs");
            e.HasKey(x => x.Id);
        });

        b.Entity<AuditLog>(e =>
        {
            e.ToTable("AuditLogs");
            e.HasKey(x => x.Id);
            e.Property(x => x.Action).HasConversion<string>();
        });

        // datetime2 has no time zone: everything is stored in UTC and must come back marked as UTC,
        // otherwise JSON would omit the "Z" and browsers would show the wrong local time.
        var utc = new Microsoft.EntityFrameworkCore.Storage.ValueConversion.ValueConverter<DateTime, DateTime>(
            v => v.Kind == DateTimeKind.Utc ? v : v.ToUniversalTime(), v => DateTime.SpecifyKind(v, DateTimeKind.Utc));
        var utcNullable = new Microsoft.EntityFrameworkCore.Storage.ValueConversion.ValueConverter<DateTime?, DateTime?>(
            v => v.HasValue ? (v.Value.Kind == DateTimeKind.Utc ? v : v.Value.ToUniversalTime()) : v,
            v => v.HasValue ? DateTime.SpecifyKind(v.Value, DateTimeKind.Utc) : v);
        foreach (var entity in b.Model.GetEntityTypes())
        {
            foreach (var property in entity.GetProperties())
            {
                if (property.ClrType == typeof(DateTime)) property.SetValueConverter(utc);
                else if (property.ClrType == typeof(DateTime?)) property.SetValueConverter(utcNullable);
            }
        }
    }
}
