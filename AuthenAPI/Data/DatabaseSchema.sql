-- AuthenAPI database schema. Idempotent: safe to run again. The app runs it automatically at startup
-- when the SQL login may create tables; otherwise a DBA can run it once by hand.

IF OBJECT_ID(N'dbo.SchemaVersion', N'U') IS NULL
    CREATE TABLE dbo.SchemaVersion (Version int NOT NULL, AppliedAt datetime2 NOT NULL CONSTRAINT DF_SchemaVersion_AppliedAt DEFAULT SYSUTCDATETIME());

IF OBJECT_ID(N'dbo.ApiKeys', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.ApiKeys (
        Id                 nvarchar(40)   NOT NULL CONSTRAINT PK_ApiKeys PRIMARY KEY,
        Name               nvarchar(100)  NOT NULL,
        Description        nvarchar(500)  NULL,
        Prefix             nvarchar(40)   NOT NULL,
        KeyHash            nvarchar(64)   NOT NULL,
        Scopes             nvarchar(max)  NOT NULL,
        AllowedIps         nvarchar(max)  NOT NULL,
        RateLimitPerMinute int            NULL,
        IsActive           bit            NOT NULL,
        ExpiresAt          datetime2      NULL,
        CreatedAt          datetime2      NOT NULL,
        CreatedBy          nvarchar(256)  NULL,
        UpdatedAt          datetime2      NULL,
        UpdatedBy          nvarchar(256)  NULL,
        LastUsedAt         datetime2      NULL,
        LastUsedIp         nvarchar(64)   NULL,
        UsageCount         bigint         NOT NULL CONSTRAINT DF_ApiKeys_UsageCount DEFAULT 0,
        RevokedAt          datetime2      NULL,
        RevokedBy          nvarchar(256)  NULL
    );
    CREATE UNIQUE INDEX IX_ApiKeys_KeyHash ON dbo.ApiKeys (KeyHash);
END

IF OBJECT_ID(N'dbo.RuntimeSettings', N'U') IS NULL
    CREATE TABLE dbo.RuntimeSettings (
        Id        int            NOT NULL CONSTRAINT PK_RuntimeSettings PRIMARY KEY,
        Json      nvarchar(max)  NOT NULL,
        Version   int            NOT NULL,
        UpdatedAt datetime2      NOT NULL,
        UpdatedBy nvarchar(256)  NULL
    );

IF OBJECT_ID(N'dbo.RuntimeSettingsHistory', N'U') IS NULL
    CREATE TABLE dbo.RuntimeSettingsHistory (
        Id        bigint IDENTITY(1,1) NOT NULL CONSTRAINT PK_RuntimeSettingsHistory PRIMARY KEY,
        Version   int            NOT NULL,
        Json      nvarchar(max)  NOT NULL,
        ChangedAt datetime2      NOT NULL,
        ChangedBy nvarchar(256)  NULL
    );

IF OBJECT_ID(N'dbo.RequestLogs', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.RequestLogs (
        Id           nvarchar(32)   NOT NULL CONSTRAINT PK_RequestLogs PRIMARY KEY NONCLUSTERED,
        Timestamp    datetime2      NOT NULL,
        Method       nvarchar(16)   NOT NULL,
        Path         nvarchar(600)  NOT NULL,
        QueryString  nvarchar(max)  NULL,
        StatusCode   int            NOT NULL,
        DurationMs   bigint         NOT NULL,
        ClientIp     nvarchar(64)   NULL,
        UserAgent    nvarchar(max)  NULL,
        ApiKeyId     nvarchar(40)   NULL,
        ApiKeyName   nvarchar(200)  NULL,
        Username     nvarchar(256)  NULL,
        Outcome      nvarchar(100)  NULL,
        ErrorMessage nvarchar(max)  NULL,
        TraceId      nvarchar(100)  NULL,
        LdapStrategy nvarchar(100)  NULL
    );
    CREATE CLUSTERED INDEX IX_RequestLogs_Timestamp ON dbo.RequestLogs (Timestamp);
    CREATE INDEX IX_RequestLogs_ApiKey ON dbo.RequestLogs (ApiKeyId, Timestamp);
    CREATE INDEX IX_RequestLogs_Status ON dbo.RequestLogs (StatusCode, Timestamp);
    CREATE INDEX IX_RequestLogs_Username ON dbo.RequestLogs (Username, Timestamp);
END

IF OBJECT_ID(N'dbo.AuditLogs', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.AuditLogs (
        Id          uniqueidentifier NOT NULL CONSTRAINT PK_AuditLogs PRIMARY KEY NONCLUSTERED,
        Timestamp   datetime2      NOT NULL,
        Action      nvarchar(40)   NOT NULL,
        Username    nvarchar(256)  NULL,
        Success     bit            NOT NULL,
        IpAddress   nvarchar(64)   NULL,
        UserAgent   nvarchar(max)  NULL,
        Details     nvarchar(max)  NULL,
        DurationMs  bigint         NULL,
        RequestPath nvarchar(max)  NULL,
        HttpMethod  nvarchar(16)   NULL,
        StatusCode  int            NULL
    );
    CREATE CLUSTERED INDEX IX_AuditLogs_Timestamp ON dbo.AuditLogs (Timestamp);
    CREATE INDEX IX_AuditLogs_Username ON dbo.AuditLogs (Username, Timestamp);
    CREATE INDEX IX_AuditLogs_Action ON dbo.AuditLogs (Action, Timestamp);
END

IF NOT EXISTS (SELECT 1 FROM dbo.SchemaVersion WHERE Version = 1)
    INSERT INTO dbo.SchemaVersion (Version) VALUES (1);
