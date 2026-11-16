# IIS Deployment Guide for AuthenAPI

## Prerequisites

### 1. Install ASP.NET Core Hosting Bundle

ดาวน์โหลดและติดตั้ง **ASP.NET Core Runtime Hosting Bundle** บน IIS Server:

- [Download .NET 8.0 Hosting Bundle](https://dotnet.microsoft.com/download/dotnet/8.0)
- เลือก **Hosting Bundle** (ไม่ใช่ Runtime อย่างเดียว)

หลังติดตั้งเสร็จ **Restart IIS**:
```cmd
net stop was /y
net start w3svc
```

### 2. Verify Installation

ตรวจสอบว่า ASP.NET Core Module ติดตั้งแล้ว:
```cmd
%windir%\system32\inetsrv\appcmd list module | find "AspNetCoreModuleV2"
```

---

## Publish Application

### Option 1: Framework-Dependent Deployment (Recommended)

```bash
# บน Development Machine
cd AuthenAPI
dotnet publish -c Release -o ./publish
```

### Option 2: Self-Contained Deployment

```bash
# สำหรับ Windows x64
dotnet publish -c Release -r win-x64 --self-contained -o ./publish
```

---

## IIS Configuration

### Step 1: Create Application Pool

1. เปิด **IIS Manager**
2. คลิกขวาที่ **Application Pools** → **Add Application Pool**
3. ตั้งค่า:
   - **Name:** `AuthenAPIPool`
   - **.NET CLR version:** `No Managed Code` ⚠️ สำคัญมาก!
   - **Managed pipeline mode:** `Integrated`

### Step 2: Create Website/Application

1. คลิกขวาที่ **Sites** → **Add Website** หรือ **Add Application**
2. ตั้งค่า:
   - **Site name:** `AuthenAPI`
   - **Application pool:** `AuthenAPIPool`
   - **Physical path:** `D:\Web Sites\wwwroot\AuthenAPI`
   - **Binding:** `http://authen.hondacx.me:80`

### Step 3: Copy Published Files

Copy ไฟล์จาก `./publish` ไปยัง `D:\Web Sites\wwwroot\AuthenAPI`:

```
AuthenAPI/
├── AuthenAPI.dll
├── AuthenAPI.exe (ถ้า self-contained)
├── AuthenAPI.deps.json
├── AuthenAPI.runtimeconfig.json
├── web.config                    ← สำคัญ!
├── appsettings.json
├── appsettings.Production.json   (optional)
└── wwwroot/                      (if any static files)
```

---

## web.config

ตรวจสอบว่ามีไฟล์ `web.config` อยู่:

```xml
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <location path="." inheritInChildApplications="false">
    <system.webServer>
      <handlers>
        <add name="aspNetCore" path="*" verb="*" modules="AspNetCoreModuleV2" resourceType="Unspecified" />
      </handlers>
      <aspNetCore processPath="dotnet"
                  arguments=".\AuthenAPI.dll"
                  stdoutLogEnabled="true"
                  stdoutLogFile=".\logs\stdout"
                  hostingModel="inprocess">
        <environmentVariables>
          <environmentVariable name="ASPNETCORE_ENVIRONMENT" value="Production" />
        </environmentVariables>
      </aspNetCore>
    </system.webServer>
  </location>
</configuration>
```

---

## Folder Permissions

ให้ Application Pool identity มีสิทธิ์:

1. คลิกขวาที่ folder `D:\Web Sites\wwwroot\AuthenAPI`
2. **Properties** → **Security** → **Edit** → **Add**
3. เพิ่ม: `IIS AppPool\AuthenAPIPool`
4. ให้สิทธิ์: **Read & Execute**, **List folder contents**, **Read**
5. สำหรับ `logs` และ `App_Data`: ให้สิทธิ์ **Modify** เพิ่มด้วย (ดูหัวข้อ Admin Portal)

---

## Admin Portal

เปิดที่ `https://<server>/admin/` (รายละเอียดฟีเจอร์และ API ดู `docs/ADMIN_PORTAL.md`)

### 1. สิทธิ์ folder `App_Data` และ `logs`

ระบบเก็บ API keys (แบบ hash), การตั้งค่าที่แก้จากหน้าเว็บ, backup และ Data Protection keys ไว้ใน `App_Data`
(เปลี่ยนที่อยู่ได้ด้วย `"DataDirectory"` ใน appsettings.json)

```cmd
mkdir "D:\Web Sites\wwwroot\AuthenAPI\App_Data"
icacls "D:\Web Sites\wwwroot\AuthenAPI\App_Data" /grant "IIS AppPool\AuthenAPIPool:(OI)(CI)M"
icacls "D:\Web Sites\wwwroot\AuthenAPI\logs" /grant "IIS AppPool\AuthenAPIPool:(OI)(CI)M"
```

> **Backup `App_Data` ทุกครั้งก่อน deploy** และ **อย่าลบ** `App_Data\keys` — ถ้าหาย session ของ admin จะหลุด และรหัสผ่าน service account ที่บันทึกผ่านหน้าเว็บจะถอดรหัสไม่ได้ (ต้องกรอกใหม่)
> เวลา copy ไฟล์ publish ใหม่ ให้ copy ทับเฉพาะไฟล์โปรแกรม อย่า copy ทับ `App_Data` และ `appsettings.json` บน server

### 2. กำหนดผู้ดูแลระบบ

แก้ `appsettings.json` บน server อย่างน้อยหนึ่งวิธี:

```json
"AdminSettings": {
  "Enabled": true,
  "AdminUsers": ["ad-wachira.diloksumpan"],
  "ViewerUsers": [],
  "AdminGroups": ["AuthenAPI-Admins"],
  "ViewerGroups": [],
  "AllowedIpAddresses": [],
  "SessionTimeoutMinutes": 60,
  "LocalAdmins": []
}
```

- `AdminUsers` / `ViewerUsers` ใส่ sAMAccountName หรือ UPN (ไม่รองรับ email เพราะ attribute mail แก้ไขได้ง่ายกว่า)
- `AdminGroups` / `ViewerGroups` คือชื่อ group ใน AD (นับเฉพาะ direct member ไม่รวม nested group) ใส่ได้ทั้งชื่อ CN เช่น `AuthenAPI-Admins` หรือ DN เต็ม เช่น `CN=AuthenAPI-Admins,OU=Groups,DC=ipsosgroup,DC=ipsos,DC=com` **แนะนำ DN เต็ม** เพราะชื่อ CN ซ้ำกันได้ใน OU ต่างกัน
- `AllowedIpAddresses` จำกัด IP ที่เปิดหน้า admin ได้ (ว่าง = ใช้ whitelist หลัก) — จาก server เอง (127.0.0.1) เข้าได้เสมอ

### 3. บัญชีฉุกเฉิน (break-glass) สำหรับตอน AD ล่ม — แนะนำให้มี 1 บัญชี

ถ้า AD ติดต่อไม่ได้ จะ login หน้า admin ด้วยบัญชี AD ไม่ได้ (ซึ่งเป็นตอนที่ต้องเข้าไปแก้ค่า LDAP พอดี) ให้สร้างบัญชี local:

```cmd
cd "D:\Web Sites\wwwroot\AuthenAPI"
AuthenAPI.exe hash-password
```

พิมพ์รหัสผ่าน (อย่างน้อย 12 ตัว) แล้วนำค่าที่ได้ (`pbkdf2-sha256$...`) ใส่:

```json
"LocalAdmins": [
  { "Username": "breakglass", "PasswordHash": "pbkdf2-sha256$210000$...", "Role": "Admin" }
]
```

เก็บรหัสผ่านนี้ไว้ในที่ปลอดภัย (password vault) ใช้เฉพาะตอนฉุกเฉิน การ login ทุกครั้งถูกบันทึกใน Audit Log

### 4. Health check สำหรับระบบ monitoring

- `GET /health` — process ยังทำงานอยู่ (200 เสมอ)
- `GET /health/ready` — 200 เมื่อเชื่อม AD ได้, 503 เมื่อเชื่อมไม่ได้ (ไม่เปิดเผยรายละเอียดภายใน)

---

## SQL Server (เก็บ API keys, settings และ logs ใน database)

ถ้าไม่ตั้งค่า ระบบจะเก็บข้อมูลเป็นไฟล์ใน `App_Data` และ `logs` เหมือนเดิม

### 1. สร้าง database และ SQL login (ให้ DBA รัน)

```sql
CREATE DATABASE AuthenAPI;
GO
CREATE LOGIN authenapi_app WITH PASSWORD = 'รหัสผ่านที่แข็งแรง';
GO
USE AuthenAPI;
CREATE USER authenapi_app FOR LOGIN authenapi_app;
ALTER ROLE db_datareader ADD MEMBER authenapi_app;
ALTER ROLE db_datawriter ADD MEMBER authenapi_app;
ALTER ROLE db_ddladmin  ADD MEMBER authenapi_app;   -- ให้ระบบสร้างตารางเองตอนเริ่มทำงาน
```

ถ้าไม่ต้องการให้สิทธิ์ `db_ddladmin` ให้ DBA รัน `docs/sql/AuthenAPI-schema.sql` เองครั้งเดียว แล้วให้แค่ `db_datareader` และ `db_datawriter` (script รันซ้ำได้ ไม่ทำลายข้อมูล)

### 2. ใส่ connection string ใน `appsettings.json` บน server

```json
"ConnectionStrings": {
  "AuthenAPI": "Server=SQLSERVER01;Database=AuthenAPI;User Id=authenapi_app;Password=xxx;TrustServerCertificate=True"
}
```

- `TrustServerCertificate=True` จำเป็นถ้า SQL Server ใช้ certificate ที่ web server ไม่ trust (ค่าปกติของ SQL Server ภายในองค์กร) ถ้ามี certificate ที่ trust แล้ว ให้ใช้ `Encrypt=True` แทน
- ใช้ named instance ได้ เช่น `Server=SQLSERVER01\\SQLEXPRESS` หรือระบุ port `Server=10.1.2.3,1433`
- web server ต้องต่อ SQL Server ได้ (port 1433) ทดสอบด้วย `Test-NetConnection SQLSERVER01 -Port 1433`

### 3. `iisreset` แล้วตรวจ log

ต้องเห็น `Database storage ready: ...` ครั้งแรกระบบจะ import API keys และ settings จาก `App_Data` เข้า database ให้อัตโนมัติ
ดูสถานะได้ที่หน้า Admin → Dashboard → Health checks → **Database**

### ถ้า database ล่ม

- Login ผ่าน API ยังทำงานได้ (API keys อยู่ใน memory และมีสำเนาใน `App_Data\\api-keys.json`)
- การสร้าง/แก้ key และ settings จะถูกปฏิเสธ (503) จนกว่า database จะกลับมา
- Log ถูกเก็บในคิวและในไฟล์ `logs\\` แล้วเขียนลง database เมื่อกลับมา
- หน้า Request/Audit Logs จะแสดงเฉพาะข้อมูลล่าสุดใน memory ระหว่างนั้น

### หลาย web server ใช้ database เดียวกัน

Key และ settings ที่แก้บนเครื่องหนึ่ง จะมีผลกับเครื่องอื่นภายใน 30 วินาที
**ต้อง copy โฟลเดอร์ `App_Data\\keys` ให้เหมือนกันทุกเครื่อง** ไม่อย่างนั้น admin session จะใช้ข้ามเครื่องไม่ได้ และรหัสผ่าน service account ที่บันทึกผ่านหน้าเว็บจะถอดรหัสบนเครื่องอื่นไม่ได้

---

## Single Sign-On (SSO)

หลัง deploy เวอร์ชันนี้ ระบบเปิด endpoint ต่อไปนี้ให้ใช้ได้ทันที:
- `https://authen.hondacx.me/.well-known/openid-configuration`
- `/connect/*`
- หน้า login กลาง `/sso/login`

### 1. ตั้งค่าใน `appsettings.json` บน server

```json
"SsoSettings": {
  "Enabled": true,
  "Issuer": "https://authen.hondacx.me/",
  "SessionHours": 8,
  "AccountRecheckMinutes": 10,
  "IdentityTokenMinutes": 10,
  "AccessTokenMinutes": 30,
  "MaxFailedLogins": 3,
  "LockoutMinutes": 15,
  "MaxFailedLoginsPerIp": 100,
  "AllowedIpAddresses": []
}
```

และตั้ง `AllowedHosts` ให้รับเฉพาะชื่อเว็บจริง (กันการปลอม Host header ไปเปลี่ยน URL ในหน้า discovery):

```json
"AllowedHosts": "authen.hondacx.me;localhost"
```
พร้อมผูก binding ของเว็บใน IIS ด้วย Host name `authen.hondacx.me`

- **`Issuer` ต้องตั้งเป็น URL https จริงของเว็บนี้ และต้องมี `/` ปิดท้าย** ระบบปลายทางจะตรวจค่านี้กับค่าใน token ถ้าไม่ตรง login จะล้มเหลว
- **ต้องเป็น HTTPS** cookie ของ SSO ตั้งเป็น Secure เสมอ ถ้าเปิดผ่าน http จะ login ไม่ได้
- **`AllowedIpAddresses`:** เว็บนี้เข้าถึงได้จากอินเทอร์เน็ต ถ้าพนักงานใช้งานผ่านเครือข่ายบริษัทหรือ VPN เท่านั้น แนะนำให้ใส่ช่วง IP ของบริษัท/VPN **รวมกับ IP ของ server ระบบปลายทางทุกตัว** เพราะ server เหล่านั้นต้องเรียก `/connect/token` ถ้าปล่อยว่าง ใครบนอินเทอร์เน็ตก็เปิดหน้า login ได้ (มี lockout ป้องกันการเดารหัสอยู่แล้ว)
- **`MaxFailedLogins` = 3** (นับต่อชื่อบัญชี) ต้องน้อยกว่า lockout threshold ของ AD เพื่อให้ระบบนี้ล็อกก่อนที่ AD จะล็อกบัญชีจริงของพนักงาน
- **`MaxFailedLoginsPerIp`** ตั้งไว้สูงกว่าหน้า Admin เพราะพนักงานทั้งออฟฟิศมักออกอินเทอร์เน็ตผ่าน IP เดียวกัน (NAT)

### 2. Key ที่ใช้เซ็น token

ครั้งแรกที่เริ่มทำงาน ระบบจะสร้าง key สำหรับเซ็นและเข้ารหัส token ให้อัตโนมัติ:
- ไม่มี database: เก็บที่ `App_Data\sso-keys.json`
- มี database: เก็บในตาราง `dbo.SsoKeys`

key ถูกเข้ารหัสด้วย Data Protection อีกชั้น (คือ `App_Data\keys`) จึงต้อง **backup `App_Data` ทั้งโฟลเดอร์** ถ้า key หาย token เดิมจะใช้ไม่ได้ และทุกคนต้อง login ใหม่ ไม่มีข้อมูลเสียหาย

#### กรณีมี server มากกว่า 1 เครื่อง (load balancer)

**การ copy `App_Data\keys` ไปเครื่องอื่นใช้ไม่ได้** เพราะบน Windows key ถูกเข้ารหัสด้วย DPAPI ที่ผูกกับเครื่อง ให้ทำแบบนี้แทน:

1. ใช้ SQL Server (ตั้ง `ConnectionStrings:AuthenAPI`) ทุกเครื่องชี้ database เดียวกัน
2. ติดตั้ง certificate ตัวเดียวกัน **พร้อม private key** ลงใน `Local Computer\Personal` ของทุกเครื่อง (ใช้ certificate ของเว็บเองได้) แล้วให้สิทธิ์ app pool อ่าน private key: `certlm.msc` → คลิกขวาที่ cert → All Tasks → Manage Private Keys → เพิ่ม `IIS AppPool\AuthenAPIPool` สิทธิ์ Read
3. ตั้งค่าในทุกเครื่อง:
   ```json
   "DataProtection": {
     "StoreKeysInDatabase": true,
     "CertificateThumbprint": "<thumbprint ของ cert>"
   }
   ```
4. Restart app pool ทุกเครื่อง แล้ว login ใหม่หนึ่งครั้ง (cookie เดิมจะใช้ไม่ได้ และรหัส service account ที่บันทึกผ่านหน้าเว็บต้องกรอกใหม่)

เมื่อ cert หมดอายุและเปลี่ยนใบใหม่ ให้ **เก็บใบเก่าไว้ใน store ต่อ** อย่างน้อยจนกว่า session ทั้งหมดหมดอายุ ไม่งั้น key เดิมจะถอดรหัสไม่ได้

### 3. ลงทะเบียนระบบปลายทาง

หน้า Admin → **แอปพลิเคชัน (SSO)** → สร้าง application แล้วส่ง Client ID และ Secret ให้ทีมนั้น พร้อมคู่มือ `docs/CLIENT_INTEGRATION_GUIDE.md` หัวข้อ 12

### 4. ตรวจหลัง deploy

```powershell
# ต้องได้ JSON ที่มี "issuer": "https://authen.hondacx.me/"
Invoke-RestMethod https://authen.hondacx.me/.well-known/openid-configuration
```
จากนั้นเปิด `https://authen.hondacx.me/sso/login` ด้วย Edge หรือ Chrome แล้วลอง login ถ้าสำเร็จจะขึ้นหน้า "เข้าสู่ระบบแล้ว"

---

## Troubleshooting

### Error: HTTP 405 เมื่อกดบันทึกในหน้า Admin (PUT/DELETE)

โมดูล WebDAV ของ IIS บล็อก PUT/DELETE ซึ่ง `web.config` ของโปรเจกต์ปิด WebDAV ไว้ให้แล้ว ถ้ายังเกิดปัญหา ให้ถอนการติดตั้ง WebDAV:
Server Manager → Remove Roles and Features → Web Server (IIS) → Common HTTP Features → **WebDAV Publishing**
หรือรัน PowerShell: `Uninstall-WindowsFeature Web-DAV-Publishing` แล้วตามด้วย `iisreset`

### Error: HTTP 403.14 - Forbidden

**สาเหตุ:** IIS ไม่รู้จัก ASP.NET Core Module

**แก้ไข:**
1. ตรวจสอบว่าติดตั้ง Hosting Bundle แล้ว
2. Restart IIS หลังติดตั้ง
3. ตรวจสอบ Application Pool ตั้งเป็น "No Managed Code"
4. ตรวจสอบว่ามี `web.config` อยู่

### Error: HTTP 500.19 - Configuration Error

**สาเหตุ:** web.config ไม่ถูกต้อง หรือ AspNetCoreModuleV2 ไม่ได้ติดตั้ง

**แก้ไข:**
1. ติดตั้ง Hosting Bundle ใหม่
2. ตรวจสอบ syntax ของ web.config

### Error: HTTP 502.5 - Process Failure

**สาเหตุ:** Application crash ตอนเริ่มต้น

**แก้ไข:**
1. ดู stdout log ใน folder `logs\`
2. ตรวจสอบ `appsettings.json` ถูกต้อง
3. ลอง run จาก command line:
   ```cmd
   cd D:\Web Sites\wwwroot\AuthenAPI
   dotnet AuthenAPI.dll
   ```

### Error: HTTP 500.30 - ANCM In-Process Start Failure

**แก้ไข:**
1. ตรวจสอบ .NET Runtime version ตรงกับ application
2. ลองเปลี่ยน `hostingModel="outofprocess"` ใน web.config

---

## Enable stdout Logging

เพื่อ debug ปัญหา:

1. สร้าง folder `logs` ใน application directory
2. ให้สิทธิ์ Write แก่ Application Pool identity
3. ตั้ง `stdoutLogEnabled="true"` ใน web.config
4. Restart application
5. ดู log ใน `logs\stdout_*.log`

---

## Production Checklist

- [ ] ติดตั้ง ASP.NET Core Hosting Bundle
- [ ] Application Pool ตั้งเป็น "No Managed Code"
- [ ] web.config อยู่ใน publish folder
- [ ] Folder permissions ถูกต้อง
- [ ] appsettings.json configured สำหรับ production
- [ ] HTTPS binding configured (แนะนำ)
- [ ] Logs folder created with write permission

---

## Quick Commands

### Restart IIS
```cmd
iisreset
```

### Restart Application Pool
```cmd
appcmd recycle apppool /apppool.name:AuthenAPIPool
```

### View IIS Modules
```cmd
%windir%\system32\inetsrv\appcmd list module
```

### Check .NET Version
```cmd
dotnet --info
```

---

## Test Deployment

หลัง deploy เสร็จ ทดสอบ:

```
http://authen.hondacx.me/api/ldap/test-connection
http://authen.hondacx.me/swagger
```

---

*Document Version: 1.0*
*Last Updated: December 2025*
