# Client Integration Guide: Authentication with AuthenAPI

## Overview

เอกสารนี้อธิบายวิธีการพัฒนาระบบ Login ที่ใช้ AuthenAPI เป็น backend สำหรับตรวจสอบ credentials กับ Active Directory โดยใช้ **Hybrid Authentication** (Local Cache + AD Verification)

---

## Authentication Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        USER LOGIN FLOW                                       │
└─────────────────────────────────────────────────────────────────────────────┘

User Input (Username + Password)
              │
              ▼
    ┌─────────────────────┐
    │  Hash Password      │
    │  (SHA256 + Salt)    │
    └──────────┬──────────┘
               │
               ▼
    ┌─────────────────────┐
    │  Check User Cache   │
    │  (Local Database)   │
    └──────────┬──────────┘
               │
       ┌───────┴───────┐
       │               │
    NO CACHE      HAS CACHE
       │               │
       ▼               ▼
┌─────────────┐  ┌─────────────────────┐
│ Call API    │  │ Check Cache Status  │
│ Authenticate│  └──────────┬──────────┘
└──────┬──────┘             │
       │          ┌─────────┼─────────┐
       │          │         │         │
       │      EXPIRED   PASSWORD    VALID
       │          │      CHANGED      │
       │          │         │         │
       │          ▼         ▼         ▼
       │    ┌──────────────────┐  ┌─────────────┐
       │    │ Call API         │  │ Verify Hash │
       │    │ Re-authenticate  │  │ Locally     │
       │    └────────┬─────────┘  └──────┬──────┘
       │             │                   │
       └─────────────┼───────────────────┘
                     │
              ┌──────┴──────┐
              │             │
           SUCCESS       FAILED
              │             │
              ▼             ▼
    ┌─────────────────┐  ┌─────────────────┐
    │ Update Cache    │  │ Return Error    │
    │ Create Session  │  │ Log Attempt     │
    └─────────────────┘  └─────────────────┘
```

---

## Decision Matrix

| Scenario | Cache Exists | Cache Expired | Password Match | Action |
|----------|--------------|---------------|----------------|--------|
| First Login | ❌ No | - | - | Call API → Save Cache |
| Return User (Same Password) | ✅ Yes | ❌ No | ✅ Yes | Verify Locally |
| Return User (Cache Expired) | ✅ Yes | ✅ Yes | - | Call API → Update Cache |
| Password Changed | ✅ Yes | ❌ No | ❌ No | Call API → Update Cache |
| Invalid Credentials | - | - | - | Return Error |

---

## API Endpoints

### Base URL
```
https://your-authen-api.com/api
```

### Authentication Endpoint

**POST** `/ldap/authenticate`

```json
// Request
{
  "username": "john.doe",
  "password": "user_password"
}

// Response (Success - 200)
{
  "success": true,
  "message": "Authentication successful",
  "data": {
    "distinguishedName": "CN=John Doe,OU=Users,DC=company,DC=com",
    "samAccountName": "john.doe",
    "userPrincipalName": "john.doe@company.com",
    "displayName": "John Doe",
    "firstName": "John",
    "lastName": "Doe",
    "email": "john.doe@company.com",
    "department": "IT",
    "title": "Developer",
    "groups": ["IT Staff", "Developers", "VPN Users"],
    "isEnabled": true,
    "isLocked": false
  },
  "timestamp": "2025-12-09T10:00:00Z"
}

// Response (Failed - 401)
{
  "success": false,
  "message": "Authentication failed. Invalid username or password.",
  "timestamp": "2025-12-09T10:00:00Z"
}
```

### Get User Info (Optional)

**GET** `/ldap/users/{username}`

### Check Group Membership (Optional)

**GET** `/ldap/users/{username}/groups/{groupName}/membership`

---

## User Cache Data Model

### Database Table Schema

```sql
CREATE TABLE User_Cache (
    id              INT PRIMARY KEY AUTO_INCREMENT,
    username        VARCHAR(100) NOT NULL UNIQUE,
    password_hash   VARCHAR(256) NOT NULL,
    salt            VARCHAR(64) NOT NULL,

    -- User Info from AD
    display_name    VARCHAR(200),
    email           VARCHAR(200),
    department      VARCHAR(100),
    title           VARCHAR(100),
    employee_id     VARCHAR(50),
    groups          TEXT,                    -- JSON array

    -- Status & Timestamps
    is_enabled      BOOLEAN DEFAULT TRUE,
    last_login      DATETIME,
    last_ad_sync    DATETIME NOT NULL,       -- Last successful AD verification
    cache_expires   DATETIME NOT NULL,       -- When cache expires

    -- Audit
    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at      DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    INDEX idx_username (username),
    INDEX idx_cache_expires (cache_expires)
);
```

---

## Implementation Guide

### Configuration

```yaml
# config.yaml
authentication:
  api_base_url: "https://your-authen-api.com/api"
  api_timeout_seconds: 30

cache:
  enabled: true
  duration_days: 90              # Cache validity period
  hash_algorithm: "sha256"
  salt: "your_unique_salt_here"  # Change this!

security:
  max_failed_attempts: 5
  lockout_duration_minutes: 15
  session_timeout_hours: 8
```

### Python Implementation

```python
import hashlib
import requests
from datetime import datetime, timedelta
from typing import Optional, Dict
import json

class AuthenticationService:
    """
    Hybrid Authentication Service
    Uses local cache + AuthenAPI for AD verification
    """

    def __init__(self, config: dict):
        self.api_base_url = config['api_base_url']
        self.api_timeout = config.get('api_timeout_seconds', 30)
        self.cache_duration_days = config.get('cache_duration_days', 90)
        self.salt = config.get('salt', 'default_salt')

    def authenticate(self, username: str, password: str) -> dict:
        """
        Main authentication method

        Returns:
            dict: {
                'success': bool,
                'user': UserInfo or None,
                'message': str,
                'auth_source': 'cache' | 'api'
            }
        """
        username = username.lower().strip()
        password_hash = self._hash_password(password)

        # Step 1: Check if user exists in cache
        cached_user = self._get_cached_user(username)

        if cached_user is None:
            # Case 1: No cache - First time login
            return self._authenticate_via_api(username, password, password_hash)

        # Step 2: Check if cache is expired
        if self._is_cache_expired(cached_user):
            # Case 2: Cache expired - Re-verify with AD
            return self._authenticate_via_api(username, password, password_hash)

        # Step 3: Check if password matches cached hash
        if cached_user['password_hash'] != password_hash:
            # Case 3: Password changed - Verify with AD
            return self._authenticate_via_api(username, password, password_hash)

        # Case 4: Valid cache & matching password - Authenticate locally
        return self._authenticate_from_cache(cached_user)

    def _hash_password(self, password: str) -> str:
        """Hash password with SHA256 + salt"""
        salted = f"{password}{self.salt}"
        return hashlib.sha256(salted.encode()).hexdigest()

    def _get_cached_user(self, username: str) -> Optional[dict]:
        """
        Get user from local cache/database

        TODO: Implement database query
        Example:
            SELECT * FROM User_Cache WHERE username = ?
        """
        # Placeholder - implement your database logic
        # return db.query("SELECT * FROM User_Cache WHERE username = ?", username)
        pass

    def _is_cache_expired(self, cached_user: dict) -> bool:
        """Check if cache has expired"""
        cache_expires = cached_user.get('cache_expires')
        if cache_expires is None:
            return True

        if isinstance(cache_expires, str):
            cache_expires = datetime.fromisoformat(cache_expires)

        return datetime.utcnow() > cache_expires

    def _authenticate_via_api(self, username: str, password: str,
                               password_hash: str) -> dict:
        """
        Authenticate via AuthenAPI
        """
        try:
            response = requests.post(
                f"{self.api_base_url}/ldap/authenticate",
                json={
                    "username": username,
                    "password": password
                },
                timeout=self.api_timeout,
                headers={"Content-Type": "application/json"}
            )

            result = response.json()

            if response.status_code == 200 and result.get('success'):
                # Success - Update cache
                user_data = result.get('data', {})
                self._update_cache(username, password_hash, user_data)

                return {
                    'success': True,
                    'user': user_data,
                    'message': 'Authentication successful',
                    'auth_source': 'api'
                }
            else:
                # Failed - Log attempt
                self._log_failed_attempt(username, 'api')

                return {
                    'success': False,
                    'user': None,
                    'message': result.get('message', 'Authentication failed'),
                    'auth_source': 'api'
                }

        except requests.exceptions.Timeout:
            # API Timeout - Try cache if available (fallback)
            return self._handle_api_timeout(username, password_hash)

        except requests.exceptions.RequestException as e:
            # API Error - Try cache if available (fallback)
            return self._handle_api_error(username, password_hash, str(e))

    def _authenticate_from_cache(self, cached_user: dict) -> dict:
        """
        Authenticate using cached credentials
        """
        # Update last login timestamp
        self._update_last_login(cached_user['username'])

        return {
            'success': True,
            'user': {
                'samAccountName': cached_user['username'],
                'displayName': cached_user.get('display_name'),
                'email': cached_user.get('email'),
                'department': cached_user.get('department'),
                'title': cached_user.get('title'),
                'groups': json.loads(cached_user.get('groups', '[]')),
                'isEnabled': cached_user.get('is_enabled', True)
            },
            'message': 'Authentication successful (cached)',
            'auth_source': 'cache'
        }

    def _update_cache(self, username: str, password_hash: str,
                      user_data: dict) -> None:
        """
        Update or insert user cache

        TODO: Implement database upsert
        """
        cache_expires = datetime.utcnow() + timedelta(days=self.cache_duration_days)

        cache_entry = {
            'username': username,
            'password_hash': password_hash,
            'display_name': user_data.get('displayName'),
            'email': user_data.get('email'),
            'department': user_data.get('department'),
            'title': user_data.get('title'),
            'employee_id': user_data.get('employeeId'),
            'groups': json.dumps(user_data.get('groups', [])),
            'is_enabled': user_data.get('isEnabled', True),
            'last_login': datetime.utcnow(),
            'last_ad_sync': datetime.utcnow(),
            'cache_expires': cache_expires
        }

        # Placeholder - implement your database logic
        # db.upsert("User_Cache", cache_entry, key="username")
        pass

    def _update_last_login(self, username: str) -> None:
        """Update last login timestamp"""
        # db.update("User_Cache", {"last_login": datetime.utcnow()},
        #           where={"username": username})
        pass

    def _log_failed_attempt(self, username: str, source: str) -> None:
        """Log failed login attempt"""
        # Implement your logging logic
        pass

    def _handle_api_timeout(self, username: str, password_hash: str) -> dict:
        """
        Handle API timeout - fallback to cache if valid
        """
        cached_user = self._get_cached_user(username)

        if cached_user and not self._is_cache_expired(cached_user):
            if cached_user['password_hash'] == password_hash:
                # Use cache as fallback
                result = self._authenticate_from_cache(cached_user)
                result['message'] += ' (API timeout, used cache)'
                return result

        return {
            'success': False,
            'user': None,
            'message': 'Authentication service unavailable. Please try again.',
            'auth_source': 'error'
        }

    def _handle_api_error(self, username: str, password_hash: str,
                          error: str) -> dict:
        """
        Handle API error - fallback to cache if valid
        """
        cached_user = self._get_cached_user(username)

        if cached_user and not self._is_cache_expired(cached_user):
            if cached_user['password_hash'] == password_hash:
                # Use cache as fallback
                result = self._authenticate_from_cache(cached_user)
                result['message'] += ' (API error, used cache)'
                return result

        return {
            'success': False,
            'user': None,
            'message': f'Authentication service error: {error}',
            'auth_source': 'error'
        }


# =============================================================================
# Usage Example
# =============================================================================

if __name__ == "__main__":
    config = {
        'api_base_url': 'https://your-authen-api.com/api',
        'api_timeout_seconds': 30,
        'cache_duration_days': 90,
        'salt': 'your_unique_salt_2024'
    }

    auth_service = AuthenticationService(config)

    # Authenticate user
    result = auth_service.authenticate("john.doe", "password123")

    if result['success']:
        print(f"Welcome, {result['user']['displayName']}!")
        print(f"Authenticated via: {result['auth_source']}")
    else:
        print(f"Login failed: {result['message']}")
```

---

## C# Implementation

```csharp
using System;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

public class AuthenticationService
{
    private readonly HttpClient _httpClient;
    private readonly AuthConfig _config;
    private readonly IUserCacheRepository _cacheRepo;

    public AuthenticationService(AuthConfig config, IUserCacheRepository cacheRepo)
    {
        _config = config;
        _cacheRepo = cacheRepo;
        _httpClient = new HttpClient
        {
            BaseAddress = new Uri(config.ApiBaseUrl),
            Timeout = TimeSpan.FromSeconds(config.ApiTimeoutSeconds)
        };
    }

    public async Task<AuthResult> AuthenticateAsync(string username, string password)
    {
        username = username.ToLower().Trim();
        var passwordHash = HashPassword(password);

        // Step 1: Check cache
        var cachedUser = await _cacheRepo.GetByUsernameAsync(username);

        if (cachedUser == null)
        {
            // Case 1: No cache - First login
            return await AuthenticateViaApiAsync(username, password, passwordHash);
        }

        if (cachedUser.CacheExpires < DateTime.UtcNow)
        {
            // Case 2: Cache expired
            return await AuthenticateViaApiAsync(username, password, passwordHash);
        }

        if (cachedUser.PasswordHash != passwordHash)
        {
            // Case 3: Password changed
            return await AuthenticateViaApiAsync(username, password, passwordHash);
        }

        // Case 4: Valid cache - Authenticate locally
        return AuthenticateFromCache(cachedUser);
    }

    private string HashPassword(string password)
    {
        using var sha256 = SHA256.Create();
        var salted = $"{password}{_config.Salt}";
        var bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(salted));
        return Convert.ToHexString(bytes).ToLower();
    }

    private async Task<AuthResult> AuthenticateViaApiAsync(
        string username, string password, string passwordHash)
    {
        try
        {
            var request = new { username, password };
            var json = JsonSerializer.Serialize(request);
            var content = new StringContent(json, Encoding.UTF8, "application/json");

            var response = await _httpClient.PostAsync("/ldap/authenticate", content);
            var responseBody = await response.Content.ReadAsStringAsync();
            var apiResult = JsonSerializer.Deserialize<ApiResponse>(responseBody);

            if (response.IsSuccessStatusCode && apiResult?.Success == true)
            {
                // Update cache
                await UpdateCacheAsync(username, passwordHash, apiResult.Data);

                return new AuthResult
                {
                    Success = true,
                    User = apiResult.Data,
                    Message = "Authentication successful",
                    AuthSource = "api"
                };
            }

            return new AuthResult
            {
                Success = false,
                Message = apiResult?.Message ?? "Authentication failed",
                AuthSource = "api"
            };
        }
        catch (TaskCanceledException)
        {
            // Timeout - try fallback
            return await HandleApiFailureAsync(username, passwordHash, "API timeout");
        }
        catch (Exception ex)
        {
            return await HandleApiFailureAsync(username, passwordHash, ex.Message);
        }
    }

    private AuthResult AuthenticateFromCache(UserCache cachedUser)
    {
        _cacheRepo.UpdateLastLoginAsync(cachedUser.Username);

        return new AuthResult
        {
            Success = true,
            User = new UserInfo
            {
                SamAccountName = cachedUser.Username,
                DisplayName = cachedUser.DisplayName,
                Email = cachedUser.Email,
                Department = cachedUser.Department,
                Groups = cachedUser.GetGroupsList()
            },
            Message = "Authentication successful (cached)",
            AuthSource = "cache"
        };
    }

    private async Task UpdateCacheAsync(
        string username, string passwordHash, UserInfo userData)
    {
        var cacheEntry = new UserCache
        {
            Username = username,
            PasswordHash = passwordHash,
            DisplayName = userData.DisplayName,
            Email = userData.Email,
            Department = userData.Department,
            Groups = JsonSerializer.Serialize(userData.Groups),
            IsEnabled = userData.IsEnabled,
            LastLogin = DateTime.UtcNow,
            LastAdSync = DateTime.UtcNow,
            CacheExpires = DateTime.UtcNow.AddDays(_config.CacheDurationDays)
        };

        await _cacheRepo.UpsertAsync(cacheEntry);
    }

    private async Task<AuthResult> HandleApiFailureAsync(
        string username, string passwordHash, string error)
    {
        // Try cache fallback
        var cachedUser = await _cacheRepo.GetByUsernameAsync(username);

        if (cachedUser != null &&
            cachedUser.CacheExpires > DateTime.UtcNow &&
            cachedUser.PasswordHash == passwordHash)
        {
            var result = AuthenticateFromCache(cachedUser);
            result.Message += $" (API unavailable: {error})";
            return result;
        }

        return new AuthResult
        {
            Success = false,
            Message = $"Authentication service unavailable: {error}",
            AuthSource = "error"
        };
    }
}

// Models
public class AuthConfig
{
    public string ApiBaseUrl { get; set; }
    public int ApiTimeoutSeconds { get; set; } = 30;
    public int CacheDurationDays { get; set; } = 90;
    public string Salt { get; set; }
}

public class AuthResult
{
    public bool Success { get; set; }
    public UserInfo User { get; set; }
    public string Message { get; set; }
    public string AuthSource { get; set; }
}

public class UserCache
{
    public string Username { get; set; }
    public string PasswordHash { get; set; }
    public string DisplayName { get; set; }
    public string Email { get; set; }
    public string Department { get; set; }
    public string Groups { get; set; }
    public bool IsEnabled { get; set; }
    public DateTime LastLogin { get; set; }
    public DateTime LastAdSync { get; set; }
    public DateTime CacheExpires { get; set; }

    public List<string> GetGroupsList() =>
        JsonSerializer.Deserialize<List<string>>(Groups ?? "[]");
}
```

---

## Edge Cases & Error Handling

### Case 1: API Unavailable (Network Error / Timeout)

```
IF API unavailable:
    IF valid cache exists AND password matches:
        → Allow login (with warning)
        → Log: "Authenticated via cache - API unavailable"
    ELSE:
        → Deny login
        → Message: "Authentication service unavailable"
```

### Case 2: Account Disabled in AD

```
IF API returns user with isEnabled = false:
    → Deny login
    → Update cache: set is_enabled = false
    → Message: "Account is disabled"
```

### Case 3: Account Locked in AD

```
IF API returns user with isLocked = true:
    → Deny login
    → Message: "Account is locked. Contact administrator."
```

### Case 4: Brute Force Protection

```
Track failed attempts per username/IP:
    IF failed_attempts >= threshold (e.g., 5):
        → Lock out for X minutes
        → Don't even call API
        → Message: "Too many failed attempts. Try again later."
```

### Case 5: Password Expired in AD

```
IF API returns specific error for expired password:
    → Deny login
    → Clear cache
    → Message: "Password expired. Please reset your password."
```

### Case 6: User Deleted from AD

```
IF API returns 404 (user not found):
    → Deny login
    → Delete from cache
    → Message: "User account not found."
```

---

## Security Best Practices

### 1. Password Hashing

```python
# Use strong hashing
import hashlib
import secrets

def hash_password(password: str, salt: str = None) -> tuple:
    if salt is None:
        salt = secrets.token_hex(32)

    # Use PBKDF2 or bcrypt for production
    salted = f"{password}{salt}"
    hash_value = hashlib.sha256(salted.encode()).hexdigest()

    return hash_value, salt
```

### 2. Secure API Communication

```python
# Always use HTTPS
# Validate SSL certificates
# Use API keys or JWT for additional security

headers = {
    "Content-Type": "application/json",
    "X-API-Key": "your-api-key",  # Optional
    "User-Agent": "YourApp/1.0"
}
```

### 3. Cache Security

- Store password hashes, NEVER plain text
- Encrypt sensitive data at rest
- Use parameterized queries to prevent SQL injection
- Implement proper access controls on cache table

### 4. Logging & Monitoring

```python
# Log all authentication events
log_entry = {
    "timestamp": datetime.utcnow(),
    "username": username,
    "action": "authenticate",
    "success": result['success'],
    "auth_source": result['auth_source'],
    "ip_address": request.remote_addr,
    "user_agent": request.user_agent
}
```

---

## Testing Checklist

- [ ] First-time login (no cache)
- [ ] Return login with same password (cache hit)
- [ ] Return login with changed password
- [ ] Login after cache expired
- [ ] API timeout with valid cache
- [ ] API timeout without cache
- [ ] Invalid credentials
- [ ] Disabled account
- [ ] Locked account
- [ ] Brute force protection
- [ ] Multiple concurrent logins
- [ ] Cache cleanup/purge

---

## API Health Check

Before each login attempt, optionally check API availability:

```python
def is_api_available() -> bool:
    try:
        response = requests.get(
            f"{API_BASE_URL}/ldap/test-connection",
            timeout=5
        )
        return response.status_code == 200
    except:
        return False
```

---

## Support

For API issues or questions, contact the AuthenAPI team.

**API Documentation:** `/swagger` endpoint on the API server

---

*Document Version: 1.0*
*Last Updated: December 2025*
