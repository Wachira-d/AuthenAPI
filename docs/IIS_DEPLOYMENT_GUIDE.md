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

- `AdminUsers` / `ViewerUsers` ใส่ได้ทั้ง sAMAccountName, UPN หรือ email
- `AdminGroups` / `ViewerGroups` คือชื่อ group ใน AD (นับเฉพาะ direct member ไม่รวม nested group)
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

## Troubleshooting

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
