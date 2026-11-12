# Admin Portal — Design & API Contract

The Admin Portal is a web UI served by AuthenAPI itself at `/admin/` plus a
cookie-authenticated JSON API under `/api/admin/*`. It lets operators see system
health, manage API keys, change settings at runtime, inspect every API call and
audit event, and run LDAP diagnostics — without editing files on the server.

## 1. Features

| Area | What it does |
|------|--------------|
| Dashboard | Overall status (Healthy / Degraded / Unhealthy), LDAP availability over 24h, request volume & error timeline, latency p50/p95, auth success/fail, top API keys / endpoints / client IPs |
| Health | Background probe every 60s: TCP reachability of each LDAP port, service-account bind via the active strategy, process memory/CPU/threads, disk & log-dir writability, cache stats |
| API Keys | Create (shown once), rotate, revoke, disable, set expiry, per-key scopes, per-key allowed IPs (CIDR), per-key rate limit, last-used / usage counters. Legacy keys from `appsettings.json` are listed read-only |
| Request Logs | Every `/api/*` call (except `/api/admin/*`): time, method, path, status, duration, client IP, API key, username, outcome, LDAP strategy. Filter, paginate, detail view, CSV export. Persisted to `logs/requests_yyyyMMdd.jsonl` and reloaded after app-pool recycles |
| Audit Logs | Existing audit trail plus admin actions (login, key changes, settings changes). Filter, CSV export |
| Settings | Edit LDAP, Security, Audit and Admin settings at runtime; "Test before save" for LDAP; revert a section to `appsettings.json`; automatic backup of every change |
| Tools | Full LDAP diagnostics, test a user login (shows failure reason: bad password / locked / disabled / expired), user lookup, clear cache, reset preferred LDAP strategy, per-strategy statistics |
| Security | Cookie session (HttpOnly, SameSite=Strict, 12-hour absolute lifetime), CSRF header, Admin/Viewer roles, atomic login lockout (per user+IP, per user, per IP), access by AD group or user list with group membership re-checked every 10 minutes, local break-glass admin for when AD is down |

## 2. Conventions

- Base path: `/api/admin`. JSON is **camelCase**. Enums are **strings**. Times are ISO-8601 UTC.
- Every response is wrapped:
  ```json
  { "success": true, "message": "…", "data": { }, "error": null, "timestamp": "2026-01-01T00:00:00Z" }
  ```
- Auth: cookie `AuthenAPI.Admin` set by login. Browser `fetch` must use `credentials: "same-origin"`.
- **CSRF:** every non-GET request to `/api/admin/*` MUST send header `X-Admin-Request: 1`, otherwise `400`.
- Status codes: `401` not logged in / session expired → show login. `403` role insufficient. `423` login locked out (`data.retryAfterSeconds`). `400` validation: `error` is one string with messages joined by `"; "`, each starting with the field name. `404` not found. `503` on login: AD unreachable (use a break-glass account).
- Roles: `Admin` (everything) and `Viewer` (read-only: dashboard, health, logs, keys list, settings view, user lookup). Endpoints marked **[Admin]** return 403 for Viewer.

## 3. Endpoints

### Auth
| Method | Path | Body | `data` |
|---|---|---|---|
| POST | `/auth/login` | `{ "username": "", "password": "" }` | `AdminSession` |
| POST | `/auth/logout` | – | null |
| GET | `/auth/me` | – | `AdminSession` (401 if not logged in) |

`AdminSession`: `{ username, displayName, role: "Admin"|"Viewer", authMethod: "local"|"ldap", expiresAt }`

### Health
| Method | Path | `data` |
|---|---|---|
| GET | `/health` | `HealthReport` |
| GET | `/health/history?hours=24` | `HealthSample[]` (oldest first, ~1/min) |
| POST | `/health/check-now` | `HealthReport` (forces a probe) |

```jsonc
// HealthReport
{
  "status": "Healthy",              // Healthy | Degraded | Unhealthy
  "checkedAt": "…", "startedAt": "…", "uptimeSeconds": 12345,
  "version": "1.0.0", "environment": "Production", "machineName": "WEB01", "frameworkVersion": ".NET 8.0.x",
  "ldap": {
    "status": "Healthy", "server": "10.137.184.98", "fallbackServers": [],
    "activeStrategy": "LDAP-389-UPN", "secure": false,          // secure=false when the active strategy is not SSL
    "lastSuccessAt": "…", "lastFailureAt": null, "lastError": null,
    "latencyMs": 42, "availability24h": 99.8,
    "ports": [ { "server": "10.137.184.98", "port": 636, "ssl": true, "reachable": true, "latencyMs": 3, "error": null } ]
  },
  "process": { "workingSetMb": 120.5, "gcHeapMb": 40.1, "threadCount": 30, "cpuPercent": 1.2 },
  "storage": { "logDirectory": "…", "logDirectoryWritable": true, "dataDirectory": "…", "dataDirectoryWritable": true, "diskFreeGb": 50.2 },
  "cache": { "entries": 12, "hits": 100, "misses": 20 },
  "checks": [ { "name": "LDAP bind", "status": "Healthy", "message": "…" } ]
}
// HealthSample
{ "timestamp": "…", "ok": true, "latencyMs": 40, "strategy": "LDAP-389-UPN", "error": null }
```

### Metrics
`GET /metrics?range=1h|24h|7d[&apiKeyId=…]` → `Metrics`

```jsonc
{
  "range": "24h", "from": "…", "to": "…", "bucketMinutes": 60,
  "totalRequests": 0, "successRequests": 0, "clientErrors": 0, "serverErrors": 0, "errorRate": 0.0,
  "avgLatencyMs": 0, "p50LatencyMs": 0, "p95LatencyMs": 0, "p99LatencyMs": 0,
  "authAttempts": 0, "authSuccesses": 0, "authFailures": 0, "uniqueClients": 0,
  "timeline": [ { "bucketStart": "…", "total": 0, "errors": 0, "avgLatencyMs": 0, "authSuccess": 0, "authFailure": 0 } ],
  "byEndpoint": [ { "endpoint": "POST /api/ldap/authenticate", "count": 0, "errors": 0, "avgLatencyMs": 0 } ],
  "byApiKey":   [ { "apiKeyId": "…", "apiKeyName": "…", "count": 0, "errors": 0, "lastSeen": "…" } ],
  "byClientIp": [ { "ip": "…", "count": 0, "errors": 0 } ],
  "byStatusCode": [ { "statusCode": 200, "count": 0 } ],
  "topFailedUsers": [ { "username": "…", "count": 0 } ]
}
```
Timeline buckets: `1h` → 1-minute buckets, `24h` → 60-minute, `7d` → 360-minute. Every bucket in range is present (zero-filled).

### Request logs
| Method | Path | Notes |
|---|---|---|
| GET | `/requests` | Query: `from, to, method, path, status` (`2xx`/`4xx`/`5xx` or exact e.g. `401`), `apiKeyId, ip, username, search, minDurationMs, skip=0, take=50` (max 500) → `{ total, items: RequestLogEntry[] }` newest first |
| GET | `/requests/{id}` | `RequestLogEntry` |
| GET | `/requests/export` | same filters, returns `text/csv` file (not wrapped) |

`RequestLogEntry`: `{ id, timestamp, method, path, queryString, statusCode, durationMs, clientIp, userAgent, apiKeyId, apiKeyName, username, outcome, errorMessage, traceId, ldapStrategy }`
`outcome` examples: `Success`, `AuthFailed:InvalidCredentials`, `AuthFailed:AccountLocked`, `ApiKey:Missing`, `ApiKey:Invalid`, `ApiKey:Expired`, `ApiKey:ScopeDenied`, `ApiKey:IpDenied`, `RateLimited`, `IpBlocked`, `Error`.

### Audit logs
| Method | Path | Notes |
|---|---|---|
| GET | `/audit` | Query: `username, action, success, from, to, ip, skip=0, take=50` → `{ total, items: AuditLog[] }` newest first |
| GET | `/audit/export` | same filters, `text/csv` |
| GET | `/audit/actions` | `string[]` of action names |

`AuditLog`: `{ id, timestamp, action, username, success, ipAddress, userAgent, details, durationMs, requestPath, httpMethod, statusCode }`
Actions: `Authenticate, GetUser, SearchUsers, GetUserGroups, CheckGroupMembership, TestConnection, ViewAuditLogs, ApiKeyAuth, AdminLogin, AdminLogout, ApiKeyCreated, ApiKeyUpdated, ApiKeyRotated, ApiKeyRevoked, ApiKeyDeleted, SettingsChanged, AdminTool`.

### API keys
| Method | Path | Body | `data` |
|---|---|---|---|
| GET | `/keys` | – | `ApiKeyView[]` |
| GET | `/keys/scopes` | – | `[{ scope, description }]` |
| POST | `/keys` **[Admin]** | `ApiKeyInput` | `{ key: ApiKeyView, plainTextKey: "ak_…" }` — plaintext shown ONCE |
| PUT | `/keys/{id}` **[Admin]** | `ApiKeyInput` + `isActive` | `ApiKeyView` |
| POST | `/keys/{id}/rotate` **[Admin]** | – | `{ key, plainTextKey }` (old value stops working immediately) |
| POST | `/keys/{id}/revoke` **[Admin]** | – | `ApiKeyView` (permanent) |
| DELETE | `/keys/{id}` **[Admin]** | – | null |

`ApiKeyInput`: `{ name (required, ≤100), description, scopes: string[] (empty = all scopes), allowedIps: string[] (IP or CIDR, empty = any), rateLimitPerMinute: number|null, expiresAt: string|null }`
`ApiKeyView`: `{ id, name, description, prefix, source: "managed"|"appsettings", scopes, allowedIps, rateLimitPerMinute, isActive, status: "Active"|"Disabled"|"Expired"|"Revoked", expiresAt, createdAt, createdBy, lastUsedAt, lastUsedIp, usageCount, revokedAt, revokedBy }`
`appsettings` keys are read-only (PUT/rotate/revoke/delete → 400).
Scopes: `authenticate`, `users.read`, `search`, `groups`, `test`, `audit`.

### Settings
| Method | Path | Body |
|---|---|---|
| GET | `/settings` | → `{ ldap, security, audit, admin, overridden: { ldap, security, audit, admin }, dataDirectory }` |
| PUT | `/settings/ldap` **[Admin]** | `LdapSettingsDto` |
| PUT | `/settings/security` **[Admin]** | `SecuritySettingsDto` |
| PUT | `/settings/audit` **[Admin]** | `AuditSettingsDto` |
| PUT | `/settings/admin` **[Admin]** | `AdminSettingsDto` |
| DELETE | `/settings/{section}` **[Admin]** | revert section (`ldap`/`security`/`audit`/`admin`) to appsettings.json |
| POST | `/settings/ldap/test` **[Admin]** | `LdapSettingsDto` → `LdapTestResult` (does not save) |

PUT returns the updated section DTO. `overridden.x = true` means the section has a runtime override.

```jsonc
// LdapSettingsDto — serviceAccountPassword is write-only: GET returns "" and serviceAccountPasswordSet; PUT with ""/null keeps the current password
{ "server": "", "fallbackServers": [], "port": 636, "useSSL": true, "baseDN": "", "domain": "",
  "netBiosDomain": null, "serviceAccountUsername": "", "serviceAccountPassword": "", "serviceAccountPasswordSet": true,
  "connectionTimeout": 10, "skipCertificateValidation": false, "allowInsecureFallback": false, "chaseReferrals": false,
  "enableCache": true, "cacheDurationMinutes": 5 }
// SecuritySettingsDto
{ "enableIpWhitelist": true, "allowedIpAddresses": [], "enableApiKeyAuth": true, "apiKeyHeaderName": "X-API-Key",
  "enableRateLimiting": true, "rateLimitMaxRequests": 100, "rateLimitWindowSeconds": 60 }
// AuditSettingsDto
{ "enabled": true, "enableFileLogging": true, "retentionDays": 90, "failedLoginThreshold": 5,
  "failedLoginWindowMinutes": 15, "autoPurgeEnabled": true, "requestLogRetentionDays": 30 }
// AdminSettingsDto
{ "adminUsers": [], "viewerUsers": [], "adminGroups": [], "viewerGroups": [],
  "allowedIpAddresses": [], "sessionTimeoutMinutes": 60 }
// LdapTestResult
{ "success": true, "strategy": "LDAP-389-UPN", "latencyMs": 40, "error": null,
  "attempts": [ { "strategy": "LDAPS-636-UPN", "success": false, "error": "LDAP Error 81: …", "latencyMs": 2000 } ] }
```

### Tools
| Method | Path | Body | `data` |
|---|---|---|---|
| POST | `/tools/ldap-diagnostics` **[Admin]** | – | `ConnectionTestResult` (slow: tries every strategy) |
| POST | `/tools/test-auth` **[Admin]** | `{ username, password }` | `{ success, failureReason, method, strategy, durationMs, user }` |
| GET | `/tools/lookup-user?username=` | – | `UserInfo` |
| POST | `/tools/clear-cache` **[Admin]** | – | `{ cleared: true }` |
| POST | `/tools/reset-ldap-strategy` **[Admin]** | – | null |
| GET | `/ldap/strategies` | – | `[{ name, server, port, ssl, successCount, failureCount, lastSuccessAt, lastFailureAt, lastError, avgLatencyMs, isPreferred }]` |

`failureReason`: `None, InvalidCredentials, UserNotFound, AccountLocked, AccountDisabled, AccountExpired, PasswordExpired, PasswordMustChange, LogonNotPermitted, ServerUnavailable, Error`.

`ConnectionTestResult` (existing model): `{ server, configuredPort, testStartTime, totalTestTimeMs, success, recommendedStrategy (object, same shape as a strategy), successfulStrategies[], failedStrategies[], hints[], summary }`, each strategy: `{ strategyName, server, port, useSSL, authType, usernameFormat, success, responseTimeMs, errorCode, errorMessage }`.

`UserInfo` (existing model): `{ distinguishedName, samAccountName, userPrincipalName, displayName, firstName, lastName, email, department, title, office, phone, mobile, manager, employeeId, company, isEnabled, isLocked, groups[], whenCreated, whenChanged, lastLogon }`.

## 4. Server setup

See section "Admin Portal" in `docs/IIS_DEPLOYMENT_GUIDE.md` (data folder permissions, first admin, break-glass account).

## 5. LDAP authentication behaviour

1. The service account looks the user up by `sAMAccountName`, `userPrincipalName` or `mail`. This works for every input format: `user`, `DOMAIN\user`, UPN and email.
2. The user is bound **once** with the directory's own UPN (or DN). A wrong password therefore adds exactly one to AD's `badPwdCount`. Unknown and disabled users cost no bind at all.
3. The working connection strategy is cached and tried first. Endpoints that are unreachable are skipped for the rest of the call. Every 15 minutes the health monitor re-tries the most secure strategies, so a fixed LDAPS certificate is picked up automatically.
4. Strategy order: configured port, then `LDAPS-636`, `GC-SSL-3269`, `LDAP-389-Sealed` (Kerberos/NTLM signed and sealed, encrypted without a certificate), `LDAP-636-NoSSL`, `LDAP-389` (clear text), `GC-3268`. **With `UseSSL=true`, the clear-text strategies are only used when `AllowInsecureFallback=true`.** Otherwise a TLS failure, for example an attacker presenting their own certificate, cannot downgrade the connection to clear text.
7. Changing the server, port, TLS options or service account requires re-entering the service-account password. This prevents the stored password from being sent to a new host.
5. If AD rejects the service account password, service binds pause for 15 minutes, so the health probe cannot lock the account. Saving new LDAP settings clears the pause.
6. If the directory can't be searched, the fallback is a direct bind (`DOMAIN\user`, then `user@domain`) that stops at the first definitive answer. If no endpoint is reachable at all, Windows `PrincipalContext` gets one attempt.
