# คู่มือเชื่อมต่อ AuthenAPI สำหรับระบบปลายทาง

สำหรับทีมที่พัฒนาระบบที่ให้ผู้ใช้ login ด้วยบัญชี Active Directory ผ่าน AuthenAPI (เช่น Coupon, Cash Advance System)

> **ฉบับนี้แทนที่คู่มือเดิมทั้งหมด** คู่มือเดิมแนะนำให้ "ตรวจ cache ในเครื่องก่อน แล้วค่อยถาม API" และ hash รหัสผ่านด้วย SHA256
> ทั้งสองอย่าง**ต้องเลิกใช้**: พนักงานที่ลาออก ถูก disable หรือเพิ่งเปลี่ยนรหัสผ่าน จะยัง login ด้วยรหัสเก่าได้จนกว่า cache จะหมดอายุ และ SHA256 ถูกเดารหัสกลับ (brute-force) ได้เร็วมาก

**โค้ดตัวอย่างที่ใช้ได้จริง (C#, .NET 6 ขึ้นไป):** [`docs/samples/AuthenApiLogin.cs`](samples/AuthenApiLogin.cs)
- ทดสอบครบทุกเส้นทางในเอกสารนี้กับ AuthenAPI และ Active Directory จำลอง
- ผ่านการตรวจความปลอดภัยแบบอิสระ (independent review) แล้ว
- ใช้กับ .NET Framework 4.x ไม่ได้

---

## 1. หลักการ 8 ข้อ

1. **ส่งชื่อผู้ใช้ตามที่ผู้ใช้พิมพ์มา** ห้ามตัด `@ipsos.com` ห้ามแปลงเป็นตัวพิมพ์เล็ก ทำได้แค่ตัดช่องว่างหัวท้าย
2. **ส่งรหัสผ่านจริงผ่าน HTTPS** ห้าม hash ก่อนส่ง (AD ต้องการรหัสผ่านจริงในการตรวจ)
3. **ถาม AuthenAPI ก่อนเสมอทุกครั้งที่ login** cache มีไว้ใช้ตอน "ติดต่อไม่ได้" เท่านั้น ไม่ใช่ทางลัดเพื่อให้ login เร็วขึ้น
4. **ได้คำตอบ 401 แล้วจบเลย** ห้ามลองซ้ำกับ AD และห้ามใช้ cache แทน เพราะทุกครั้งที่ลองซ้ำ AD จะนับรหัสผิดเพิ่ม และบัญชีจะถูกล็อก
5. **timeout หรือได้ 500 ให้หยุดทันที** ห้าม fallback เพราะ AuthenAPI อาจกำลังตรวจรหัสกับ AD อยู่
6. ถ้าติดต่อ AuthenAPI **ไม่ได้จริง ๆ** (เชื่อมต่อไม่ได้ หรือ AD ล่ม): เช็ก AD เอง 1 ครั้ง (ถ้ามี) → ใช้ offline cache ที่อายุ ≤ 24 ชม. → ถ้ายังไม่ได้ แจ้งว่าระบบขัดข้อง
7. **ห้ามบอกผู้ใช้ว่า "รหัสผิด" เมื่อระบบล่ม**
8. **API key อยู่ฝั่ง server เท่านั้น** และแต่ละระบบต้องมี key ของตัวเอง

---

## 2. ลำดับการตรวจสอบ

```
ผู้ใช้กรอก username + password
            │
            ▼
 ┌─────────────────────────┐
 │ 1) AuthenAPI            │── 200 ──────────────────► ✅ เข้าระบบ + บันทึก offline cache
 │ POST /api/ldap/         │── 401 JSON / 400 ───────► ❌ "ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง" (ลบ cache ของคนนี้)
 │      authenticate       │── 429 ──────────────────► ⏳ "ลองใหม่ภายหลัง"
 │                         │── 401(reason)/403/404/  ► ⚙️ "ติดต่อผู้ดูแลระบบ" + แจ้งเตือนทีมตัวเอง
 │                         │   405/3xx/401 HTML
 │                         │── timeout / 500 / 504 ──► ⚠️ "ระบบขัดข้องชั่วคราว" (ห้าม fallback)
 └───────────┬─────────────┘
             │ เชื่อมต่อไม่ได้ (refused/DNS/TLS), 502 หรือ 503 จาก IIS,
             │ 503 JSON (AD ล่ม), circuit breaker เปิดอยู่
             ▼
 ┌─────────────────────────┐
 │ 2) AD โดยตรง (ถ้ามี)    │── สำเร็จ ──────────────► ✅ เข้าระบบแบบ "degraded"
 │ LDAPS bind 1 ครั้ง      │── ปฏิเสธ (49) ─────────► ❌ "รหัสไม่ถูกต้อง" + ลบ cache
 └───────────┬─────────────┘
             │ AD ติดต่อไม่ได้ (หรือไม่ได้ตั้งค่าขั้นนี้)
             ▼
 ┌─────────────────────────┐
 │ 3) Offline cache        │── ตรง และอายุ ≤ 24 ชม. ─► ✅ เข้าระบบแบบ "degraded"
 └───────────┬─────────────┘── ไม่ตรง ──────────────► ❌ "รหัสไม่ถูกต้อง"
             │ ไม่มี cache / หมดอายุ / ผิดเกินกำหนด
             ▼
   ⚠️ "ระบบยืนยันตัวตนขัดข้องชั่วคราว กรุณาลองใหม่ภายหลัง"
```

---

## 3. สิ่งที่ต้องส่งมา

### Request

```http
POST https://authen.hondacx.me/api/ldap/authenticate
Content-Type: application/json
X-API-Key: <API key ของระบบคุณ>
User-Agent: CashAdvance/2.3 (WEB01)

{
  "username": "Phuriphat.Phiphatthanawaranon@ipsos.com",
  "password": "<รหัสผ่านจริงที่ผู้ใช้พิมพ์>"
}
```

| ช่อง | ข้อกำหนด |
|---|---|
| `username` | **ส่งตามที่ผู้ใช้พิมพ์** ตัดได้แค่ช่องว่างหัวท้าย ระบบรองรับ 4 แบบ: `ชื่อ@ipsos.com` (UPN หรือ email), `IPSOSGROUP\ชื่อ`, ชื่อแบบ pre-Windows 2000 (เช่น `Phuriphat.P`) และชื่อหน้า @ เฉย ๆ ยาวได้ไม่เกิน 256 ตัว อักขระที่ใช้ได้: `a-z A-Z 0-9 . _ @ \ -` |
| `password` | รหัสผ่านจริง **ห้าม hash และห้ามตัดช่องว่าง** |
| `X-API-Key` | key ของระบบคุณเอง เก็บไว้ใน config ฝั่ง server หรือ secret store |
| `User-Agent` | ใส่ชื่อระบบกับเวอร์ชัน จะได้ค้นใน Request Logs ได้ง่ายเวลาแก้ปัญหา |

### ข้อห้าม (เคยเกิดจริงแล้ว)

| ❌ ห้ามทำ | ผลที่เกิด |
|---|---|
| `username.Split('@')[0]` หรือ `.Replace("@ipsos.com","")` | ชื่อยาวที่ถูกตัดใน pre-Windows 2000 (UPN `Phuriphat.Phiphatthanawaranon@ipsos.com` แต่ชื่อสั้นคือ `Phuriphat.P`) อาจหาไม่เจอ และถ้ามี 2 คนที่ชื่อหน้า @ ซ้ำกัน ระบบจะปฏิเสธทั้งคู่ |
| ส่ง `passwordHash` แทน `password` | AD ปฏิเสธทุกครั้ง (`InvalidCredentials`) |
| เรียก API จาก browser หรือแอปมือถือโดยตรง | API key รั่ว และ IP whitelist จะบล็อกอยู่แล้ว |
| ใช้ API key ร่วมกันหลายระบบ | แยกไม่ออกว่า request มาจากระบบไหน และ revoke เฉพาะระบบเดียวไม่ได้ |
| ใช้ retry อัตโนมัติ (Polly, `AddStandardResilienceHandler`) กับ `/authenticate` | retry 1 ครั้ง = AD นับรหัสผิดเพิ่ม 1 ครั้ง |
| เขียน password ลง log หรือข้อความ error | รหัสรั่ว |

### การตั้งค่าการเชื่อมต่อ

| ค่า | ต้องเป็น | เหตุผล |
|---|---|---|
| Base URL | `https://authen.hondacx.me` (https เท่านั้น และไม่มี path ต่อท้าย) | ถ้าใช้ http ระบบจะ redirect ไป https และรหัสผ่านจะวิ่งผ่าน http ไปแล้ว 1 รอบก่อน redirect |
| `AllowAutoRedirect` | `false` | redirect แบบ 301/302 จะเปลี่ยน POST เป็น GET และอาจพาไปที่อื่น |
| Timeout | **45 วินาที** | ต้องนานกว่าเวลาที่ AuthenAPI อาจใช้ในกรณีที่แย่ที่สุด ถ้าตัดเร็วเกินไป AuthenAPI ยังตรวจรหัสอยู่แต่ระบบคุณเลิกรอแล้ว (ปกติตอบไม่ถึง 1 วินาที) |
| Certificate | ห้ามปิดการตรวจ | กันการดักกลางทาง (man-in-the-middle) |
| HttpClient | ใช้ `IHttpClientFactory` | – |

---

## 4. การอ่านคำตอบ

### คำตอบสำเร็จ (200)

```json
{
  "success": true,
  "message": "Authentication successful",
  "data": {
    "samAccountName": "Phuriphat.P",
    "userPrincipalName": "Phuriphat.Phiphatthanawaranon@ipsos.com",
    "displayName": "Phuriphat Phiphatthanawaranon",
    "firstName": "Phuriphat",
    "lastName": "Phiphatthanawaranon",
    "email": "phuriphat.phiphatthanawaranon@ipsos.com",
    "department": "IT",
    "title": "Developer",
    "employeeId": "12345",
    "company": "Ipsos",
    "isEnabled": true,
    "isLocked": false,
    "groups": ["TH-IT", "VPN Users"]
  },
  "timestamp": "2026-11-16T05:43:20Z"
}
```

**ตัวระบุผู้ใช้ (userKey) ในระบบของคุณ:** ใช้ `userPrincipalName` แปลงเป็นตัวพิมพ์เล็ก ถ้าว่างให้ใช้ `samAccountName` แทน ถ้าว่างทั้งคู่ให้ปฏิเสธการ login
- **ห้ามใช้ข้อความที่ผู้ใช้พิมพ์** เพราะคนเดียวกันพิมพ์ได้ 4 แบบ ระบบคุณจะกลายเป็นมีผู้ใช้ 4 คน
- ฟิลด์ที่ไม่มีค่า AuthenAPI จะส่งเป็น `""` (string ว่าง) **ไม่ใช่ `null`** ให้เช็กด้วย `IsNullOrWhiteSpace` ถ้าเช็กแค่ `?? ` หลายคนจะได้ userKey `""` ตัวเดียวกัน
- เรื่องสิทธิ์ให้ตัดสินจาก `groups` (ชื่อ group ใน AD นับเฉพาะ direct member)

### ตารางตัดสินใจ

| คำตอบ | ความหมาย | ข้อความถึงผู้ใช้ | fallback ได้ไหม | ต้องทำ |
|---|---|---|---|---|
| **200** (JSON, `success: true`) | สำเร็จ | – | – | สร้าง session และบันทึก offline cache |
| **200** ที่ไม่ใช่ JSON ของ AuthenAPI (เช่นหน้า proxy) | ไม่แน่ชัด | "ระบบขัดข้อง" | **ไม่ได้** | ตรวจ proxy/URL |
| **401** JSON ที่**ไม่มี** `reason` | รหัสผิด ไม่มี user ถูกล็อก ถูก disable หรือรหัสหมดอายุ (API ไม่บอกแยกเพื่อความปลอดภัย) | "ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง" | **ไม่ได้** | ลบ offline cache ของคนนี้ |
| **400** | รูปแบบข้อมูลผิด | "ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง" | **ไม่ได้** | – |
| **401** JSON ที่**มี** `reason` (`Missing`/`Invalid`/`Expired`/`Disabled`/`Revoked`) | ปัญหาที่ API key | "ติดต่อผู้ดูแลระบบ" | **ไม่ได้** | แจ้งเตือนทีมตัวเอง |
| **403** | IP ไม่อยู่ใน whitelist หรือ key ไม่มี scope | "ติดต่อผู้ดูแลระบบ" | **ไม่ได้** | แจ้งเตือนทีม และติดต่อผู้ดูแล AuthenAPI |
| **404, 405, 3xx, 401 แบบ HTML** | ตั้งค่า URL หรือ IIS ผิด | "ติดต่อผู้ดูแลระบบ" | **ไม่ได้** | แจ้งเตือนทีม |
| **429** | ถี่เกินกำหนด (อ่าน `Retry-After`) | "ลองใหม่ภายหลัง" | **ไม่ได้** | ดูว่ามี loop หรือมีคนพยายามเดารหัสหรือไม่ |
| **timeout, 500, 504, connection reset ระหว่างส่ง** | ไม่รู้ว่า AuthenAPI ตรวจรหัสกับ AD ไปแล้วหรือยัง | "ระบบขัดข้องชั่วคราว" | **ไม่ได้** | log ไว้ |
| **503 JSON** (`success: false`) | AuthenAPI ทำงานปกติ แต่ติดต่อ AD ไม่ได้ (ยังไม่ได้ตรวจรหัส) | – | **ได้** | ขั้น 2 → 3 |
| **เชื่อมต่อไม่ได้** (refused, DNS, TLS), **502**, **503 HTML จาก IIS** | request ไปไม่ถึงตัวแอป | – | **ได้** | ขั้น 2 → 3 และนับใน circuit breaker |

> **ทำไม 401 timeout และ 500 ถึงห้าม fallback:** AD นับ "รหัสผิด" ทุกครั้งที่ bind ไม่ผ่าน
> ถ้า AuthenAPI ตรวจไปแล้ว 1 ครั้ง แล้วระบบคุณไปตรวจกับ AD อีก จะกลายเป็น 2 ครั้ง ผู้ใช้จะถูกล็อกเร็วขึ้นเท่าตัว
> ส่วนการใช้ cache ในกรณีนี้ จะเปิดช่องให้คนที่เพิ่งถูก disable หรือเปลี่ยนรหัสยังเข้าด้วยรหัสเก่าได้
> และผู้ไม่หวังดีที่ทำให้ AuthenAPI ช้าลงจงใจ (เช่นยิง request ถล่ม) ก็จะบังคับให้ทุกคนไปใช้ cache ได้

---

## 5. เมื่อไรถาม AuthenAPI เมื่อไรใช้ cache

| สถานการณ์ | ทำอย่างไร |
|---|---|
| ผู้ใช้กด login | **ถาม API ทุกครั้ง** |
| ผู้ใช้เปิดหน้าอื่นหลัง login | ใช้ **session** ของระบบตัวเอง ห้ามถาม API ทุกหน้า |
| ต้องรู้ group หรือสิทธิ์ระหว่างใช้งาน | ใช้ `groups` ที่ได้ตอน login เก็บไว้ใน session ถ้าต้องการข้อมูลใหม่ ให้เรียก `GET /api/ldap/users/{upn}/groups` แล้ว cache ไว้ **5–15 นาที** |
| Session ยาวกว่า 8–12 ชั่วโมง | บังคับ login ใหม่ หรือเรียก `GET /api/ldap/users/{upn}` เพื่อตรวจว่า `isEnabled` ยังเป็น true |
| ทำรายการสำคัญ (อนุมัติเงิน เปลี่ยนสิทธิ์) | ขอให้กรอกรหัสใหม่ แล้ว**ถาม API** ห้ามใช้ offline |
| ค้นหาพนักงาน (เช่น เลือกผู้อนุมัติ) | `GET /api/ldap/users/search?q=` แล้ว cache ผลไว้ 5–15 นาที |
| AuthenAPI ติดต่อไม่ได้ตอน login | ขั้น 2 → 3 (หัวข้อ 7 และ 6) |
| ผู้ใช้ไม่เคย login สำเร็จด้วยชื่อนี้มาก่อน และ API ล่ม | แจ้งว่าระบบขัดข้อง |
| Monitoring | `GET /health/ready` ทุก 1–5 นาที จากระบบ monitor (**ห้าม**เรียกก่อนทุก login) |

ขอ scope ของ API key ให้ตรงกับที่ใช้จริง: `authenticate`, `users.read`, `groups`, `search`

---

## 6. การออกแบบ cache

### 6.1 Profile cache (ข้อมูลผู้ใช้และ group ไม่มีรหัสผ่าน)

- เก็บ `AdUser` ไว้ใน session หรือ memory cache อายุ 5–15 นาที
- login ใหม่ทุกครั้ง ให้เขียนทับด้วยข้อมูลล่าสุด

### 6.2 Offline credential cache (ใช้เมื่อ API และ AD ติดต่อไม่ได้ทั้งคู่เท่านั้น)

**ถ้าระบบของคุณไม่จำเป็นต้องใช้ได้ตอน AD ล่ม ให้ปิดไปเลย (`OfflineWindow = 0`)** วิธีนี้ปลอดภัยที่สุด

**ตาราง (SQL Server)** เก็บ 1 แถวต่อ 1 คน พร้อมตารางชื่อที่ผู้ใช้เคยพิมพ์ (alias):
```sql
CREATE TABLE dbo.AuthOfflineCache (
    UserKey                nvarchar(256) NOT NULL PRIMARY KEY, -- UPN ตัวเล็ก (หัวข้อ 4)
    PasswordHash           nvarchar(200) NOT NULL,             -- OfflinePasswordHasher (PBKDF2 + pepper)
    ProfileJson            nvarchar(max) NOT NULL,
    LastOnlineVerifiedUtc  datetime2     NOT NULL,             -- ใช้ SYSUTCDATETIME() ห้ามใช้ GETDATE() (ไทยคือ UTC+7)
    OfflineFailures        int           NOT NULL DEFAULT 0
);
CREATE TABLE dbo.AuthOfflineAlias (
    LoginName  nvarchar(256) NOT NULL PRIMARY KEY,             -- ชื่อที่พิมพ์ (trim + lower)
    UserKey    nvarchar(256) NOT NULL REFERENCES dbo.AuthOfflineCache(UserKey) ON DELETE CASCADE
);

-- จองสิทธิ์ลอง 1 ครั้งแบบ atomic ก่อนตรวจ hash (กันการยิงพร้อมกันหลาย request)
UPDATE dbo.AuthOfflineCache SET OfflineFailures = OfflineFailures + 1
WHERE UserKey = @UserKey AND OfflineFailures < @Max;          -- ถ้าแก้ได้ 0 แถว = หมดสิทธิ์ลอง

-- job รายวัน: ลบแถวที่หมดอายุ
DELETE FROM dbo.AuthOfflineCache WHERE LastOnlineVerifiedUtc < DATEADD(hour, -24, SYSUTCDATETIME());
```

**กฎ:**

| กฎ | เหตุผล |
|---|---|
| บันทึกหรืออัปเดต**เฉพาะหลัง API ตอบ 200** แทนที่แถวของ userKey นั้น และเพิ่ม alias ของชื่อที่พิมพ์ | cache ต้องมาจากการตรวจออนไลน์เท่านั้น |
| hash ด้วย **HMAC(pepper) แล้วตามด้วย PBKDF2-SHA256 600,000 รอบ** salt สุ่มรายคน และเก็บ pepper **นอกฐานข้อมูล** (config หรือ secret store) | ถ้าฐานข้อมูลหลุดไปอย่างเดียว จะเดารหัสไม่ได้ (รหัส AD ใช้ได้กับทุกระบบ ถ้าหลุดเสียหายสูงมาก) |
| ใช้ได้เฉพาะเมื่อ `LastOnlineVerifiedUtc` ห่างจากตอนนี้ไม่เกิน **24 ชม.** (ระบบการเงินควรตั้ง ≤ 8 ชม. หรือปิด) | คนที่ถูก disable ระหว่างนั้นจะเข้าได้ไม่เกินระยะเวลานี้ |
| ใช้ได้เฉพาะเส้นทาง "ติดต่อไม่ได้" ตามหัวข้อ 4 | ดูหัวข้อ 4 |
| API ตอบ 401 → หา userKey จาก alias แล้ว**ลบแถวของคนนั้นทั้งหมด** | ผู้ใช้อาจเพิ่งเปลี่ยนรหัสหรือถูก disable (ถ้าชื่อที่พิมพ์ยังไม่เคยใช้มาก่อน ระบบหาแถวไม่เจอ แต่ชื่อนั้นก็ใช้ offline ไม่ได้อยู่แล้ว) |
| ผิดเกิน **5 ครั้งต่อคน** (นับแบบ atomic) หรือเกิน **20 ครั้งต่อนาทีรวมทุกคน** → ปฏิเสธ offline | กันการเดารหัส และการลองรหัสยอดนิยมกับทุกคน (password spraying) ระหว่างที่ AD ไม่ได้นับให้ |
| session ที่เข้าจากขั้น 2–3 ให้ติดป้าย `degraded` และให้สิทธิ์เท่าที่จำเป็น | group อาจเก่าแล้ว ห้ามทำรายการสำคัญ |
| เมื่อ API กลับมา ให้ session แบบ degraded login ใหม่ภายใน 30–60 นาที | ปิดช่องของคนที่ถูก disable ระหว่างที่ระบบล่ม |
| บัญชีที่มีสิทธิ์ admin ของระบบคุณ **ห้ามใช้ offline** | – |
| ผูกการลบ cache เข้ากับขั้นตอน offboarding ของ HR/IT | ลบทันทีเมื่อพนักงานออก |
| ตาราง cache ให้สิทธิ์เฉพาะ service account ของแอป และไม่ export ออกไปใช้ที่อื่น | hash ถือเป็นข้อมูลลับ |

---

## 7. Fallback: เช็ก AD เองเมื่อติดต่อเราไม่ได้

ใช้**เฉพาะ**กรณีที่ request ไปไม่ถึง AuthenAPI หรือได้ **503 JSON** (AD ล่ม) **ห้ามใช้หลัง timeout, 500 หรือ 504**

1. ต้องเป็น **LDAPS port 636** และใช้**ชื่อ FQDN** ของ DC (`inbom3-dc01.ipsosgroup.ipsos.com`) เพราะ certificate ออกให้กับชื่อ ไม่ใช่ IP ห้ามปิดการตรวจ certificate ให้ import CA ของ DC เข้า Trusted Root ของ server
2. **bind ครั้งเดียว** ด้วย **UPN จริงของผู้ใช้ที่เก็บไว้ใน cache** ถ้าไม่มี cache ให้ใช้ชื่อที่ผู้ใช้พิมพ์ **ห้ามวนลองหลายรูปแบบชื่อ**
3. AD ตอบ 49 (`52e` รหัสผิด, `775` ล็อก, `533` disable, `701` บัญชีหมดอายุ, `532`/`773` รหัสหมดอายุหรือต้องเปลี่ยน):
   - ถ้าใช้ UPN จาก cache → แจ้งว่ารหัสไม่ถูกต้อง และลบ cache
   - ถ้าใช้ชื่อที่ผู้ใช้พิมพ์แล้วได้ `52e` → แจ้งว่า**ระบบขัดข้อง** เพราะ AD ตอบ `52e` ทั้งตอนรหัสผิดและตอนไม่มีชื่อนี้ ระบบจึงไม่รู้แน่ว่าเป็นกรณีไหน
4. error อื่น ๆ (81, 91, timeout) → ไปขั้น 3
5. ขั้นนี้**ไม่ผ่าน** audit log ของ AuthenAPI ต้อง log ที่ระบบคุณเอง
6. ทดสอบการเชื่อมต่อจาก web server ของคุณ: `Test-NetConnection inbom3-dc01.ipsosgroup.ipsos.com -Port 636`

**ไม่จำเป็นต้องทำขั้นนี้** ถ้าระบบคุณเข้าถึง AD ไม่ได้ ส่วนมากเวลา AuthenAPI ตอบ 503 ระบบคุณก็มักติดต่อ AD ไม่ได้เหมือนกัน ขั้นนี้มีประโยชน์ตอนที่ตัว AuthenAPI ล่มแต่ AD ยังปกติ

---

## 8. Circuit breaker

ระหว่างที่ AuthenAPI ล่ม ไม่ควรให้ทุก login ต้องรอจนติดต่อไม่ได้ทีละคน
- **เปิด** circuit เมื่อ "ไปไม่ถึง" หรือได้ 503 JSON **3 ครั้งติดกัน** แล้วข้ามไปขั้น 2–3 ทันทีเป็นเวลา 30 วินาที
- จากนั้นปล่อย **1 request** ไปลองก่อน (half-open) ถ้าผ่านค่อยเปิดให้ทุกคน
- **ไม่นับ** 401, timeout และ 500 เพราะไม่ใช่หลักฐานว่า AuthenAPI ล่ม
- breaker ต้องเป็น**ตัวเดียวใช้ร่วมกันทั้งแอป** (singleton หรือ static) ถ้าสร้างใหม่ทุก request มันจะไม่เคยเปิดเลย โค้ดตัวอย่างทำไว้ให้แล้ว

---

## 9. Checklist ความปลอดภัย

- [ ] API key อยู่ใน config ฝั่ง server หรือ secret store และไม่ commit ลง git
- [ ] Base URL เป็น https, ไม่มี path, `AllowAutoRedirect = false`, timeout 45 วินาที และไม่มี retry อัตโนมัติ
- [ ] ไม่ log password และไม่ใส่ password ใน exception
- [ ] จำกัด login ผิดในระบบตัวเองด้วย (เช่น 5 ครั้ง/15 นาที ต่อ username และต่อ IP) เพราะ rate limit ของ AuthenAPI นับรวมทั้งระบบ ถ้าคนเดียวยิงถี่จนติด limit ผู้ใช้ทุกคนของระบบคุณจะ login ไม่ได้ไปด้วย
- [ ] ข้อความ error ไม่บอกแยกว่า "ไม่มี user" หรือ "รหัสผิด" และไม่แสดง `Detail` ให้ผู้ใช้เห็น
- [ ] userKey ใช้ UPN ตัวพิมพ์เล็ก และเช็กค่าว่างด้วย `IsNullOrWhiteSpace`
- [ ] Offline cache (ถ้าเปิด): pepper อยู่นอก DB, เวลาเป็น UTC, มี job ลบแถวหมดอายุ, จองสิทธิ์ลองแบบ atomic, ผูกกับ offboarding
- [ ] Session ของ degraded login ถูกจำกัดสิทธิ์
- [ ] แจ้งเตือนทีมเมื่อเจอ `ConfigurationError`
- [ ] PBKDF2 ใช้ CPU ราว 0.2 วินาทีต่อการ login 1 ครั้ง วางแผน capacity ของ server ไว้ด้วย

---

## 10. กรณีทดสอบก่อนขึ้น production

| # | กรณี | ผลที่ต้องได้ |
|---|---|---|
| 1 | login ด้วย UPN เต็ม | สำเร็จ, userKey = UPN ตัวพิมพ์เล็ก |
| 2 | login ด้วย `IPSOSGROUP\ชื่อสั้น` และด้วยชื่อสั้นเฉย ๆ | สำเร็จ และได้ **userKey เดียวกับข้อ 1** |
| 3 | รหัสผิด | "ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง" และ AD นับรหัสผิด **+1 ครั้งเท่านั้น** |
| 4 | API key ผิด | แจ้งให้ติดต่อผู้ดูแล **ไม่ใช่** "รหัสผิด" |
| 5 | ชี้ Base URL ไปที่ port ที่ไม่มีบริการ | ไปขั้น 2 หรือ 3 และ session ถูกติดป้าย degraded |
| 6 | API และ AD ใช้ไม่ได้ทั้งคู่ กับคนที่ login สำเร็จภายใน 24 ชม. | เข้าได้แบบ offline |
| 7 | เหมือนข้อ 6 แต่ cache เกิน 24 ชม. หรือเป็นคนที่ไม่เคย login | "ระบบขัดข้องชั่วคราว" |
| 8 | API ค้างจน timeout แล้วพิมพ์รหัสผิด | "ระบบขัดข้อง" และ AD **ไม่**ถูก bind ซ้ำจากระบบคุณ |
| 9 | offline: ยิงรหัสผิดพร้อมกัน 12 request | ถูกตรวจจริงไม่เกิน 5 ครั้ง |
| 10 | ตั้ง Base URL เป็น `http://` | แอปปฏิเสธตอนเริ่มทำงาน |

หลังทดสอบ ให้เปิดหน้า Admin ของ AuthenAPI → **Request Logs** แล้ว filter ด้วย API key ของคุณ ช่อง Username คือค่าที่ระบบคุณส่งมาจริงแบบตัวต่อตัว ใช้ตรวจข้อกำหนดในหัวข้อ 3

---

## 11. การขอใช้งาน

ส่งข้อมูลต่อไปนี้ให้ผู้ดูแล AuthenAPI:
1. ชื่อระบบ และผู้รับผิดชอบ (สำหรับแจ้งเรื่อง key หมดอายุหรือหมุน key)
2. IP ขาออกของ web server ทุกเครื่อง (สำหรับ whitelist)
3. Endpoint ที่ใช้ (เพื่อกำหนด scope): `authenticate` / `users.read` / `groups` / `search`
4. ปริมาณ request ต่อนาทีโดยประมาณช่วง peak

ผู้ดูแลจะสร้าง key ในหน้า Admin → API Keys ระบบแสดง key ให้เห็น**ครั้งเดียว** ให้เก็บเข้า secret store ทันที

---

## 12. Single Sign-On (SSO): login ครั้งเดียว เข้าได้ทุกระบบ

> **สถานะ: แนวทางที่วางไว้ ยังไม่ได้เปิดใช้งาน** ส่วนนี้ต้องสร้างเพิ่มใน AuthenAPI ก่อน หัวข้อ 1–11 ใช้งานได้แล้ววันนี้ และยังใช้เป็นทางสำรองต่อไปได้หลังมี SSO

### เป้าหมาย

ผู้ใช้ login ที่ระบบใดระบบหนึ่งแล้ว เมื่อเปิดระบบอื่นจะเข้าได้ทันทีโดยไม่ต้องพิมพ์รหัสซ้ำ และเมื่อ logout ก็ออกจากทุกระบบพร้อมกัน

### แนวทางที่แนะนำ: OpenID Connect (OIDC)

AuthenAPI ทำหน้าที่เป็น **Identity Provider** กลาง โดยใช้ OpenID Connect ซึ่งเป็นมาตรฐานเดียวกับ "Sign in with Microsoft/Google"
ทุกภาษามี library รองรับ (.NET มีมาให้ในตัว คือ `AddOpenIdConnect`) ทีมปลายทางจึงไม่ต้องเขียน logic เอง

```
ผู้ใช้เปิด Coupon (ยังไม่ login)
   │  redirect
   ▼
authen.hondacx.me/connect/authorize ──► มี SSO session อยู่แล้ว? ── ใช่ ──► ส่งกลับทันที (ไม่ถามรหัส)
   │ ไม่มี                                                                       │
   ▼                                                                             │
หน้า login กลาง (username + password → AD)                                       │
   │ สำเร็จ: สร้าง SSO session (cookie ของ authen.hondacx.me)                    │
   ▼                                                                             ▼
redirect กลับ Coupon พร้อม authorization code ──► Coupon (ฝั่ง server) แลก code เป็น id_token
                                                  (ชื่อ, UPN, email, groups) → สร้าง session ของตัวเอง

ต่อมาผู้ใช้เปิด Cash Advance → redirect ไป authorize → มี SSO session แล้ว → กลับมาทันที (ไม่ต้องพิมพ์รหัส)
```

### ข้อดีเมื่อเทียบกับให้แต่ละระบบส่งรหัสมาเอง (หัวข้อ 3)

| เรื่อง | ส่งรหัสผ่าน API (ปัจจุบัน) | SSO (OIDC) |
|---|---|---|
| ระบบปลายทางได้เห็นรหัสผ่าน | เห็น | **ไม่เห็นเลย** รหัสถูกพิมพ์ที่หน้า login กลางเท่านั้น |
| พิมพ์รหัสซ้ำทุกระบบ | ต้องพิมพ์ | พิมพ์ครั้งเดียวต่อวัน |
| Logout | ทีละระบบ | ออกพร้อมกันทุกระบบได้ |
| เพิ่ม MFA / Windows login อัตโนมัติในอนาคต | ต้องแก้ทุกระบบ | แก้ที่หน้า login กลางที่เดียว |
| Offline cache รหัสผ่าน | แต่ละระบบต้องทำเอง | ไม่ต้องทำ |
| ถ้า AuthenAPI ล่ม | ใช้ fallback ตามหัวข้อ 6–7 ได้ | login ใหม่ไม่ได้ (คนที่มี session อยู่แล้วยังใช้งานต่อได้) ระบบสำคัญจึงควรเก็บฟอร์ม login เดิมไว้เป็นทางสำรอง |

### สิ่งที่จะสร้างใน AuthenAPI

1. Endpoint มาตรฐาน OIDC: `/.well-known/openid-configuration`, `/connect/authorize`, `/connect/token`, `/connect/userinfo`, `/connect/logout`
2. หน้า login กลาง (ไทย/อังกฤษ) ใช้ logic ตรวจ AD ตัวเดียวกับที่ใช้อยู่ตอนนี้ (รองรับทุกรูปแบบชื่อ และนับรหัสผิดใน AD แค่ 1 ครั้งต่อการพิมพ์ผิด 1 ครั้ง)
3. SSO session อายุ 8 ชั่วโมง (ตั้งค่าได้) และหมดอายุทันทีเมื่อบัญชีถูก disable (ตรวจซ้ำเป็นรอบ)
4. หน้า Admin → **Applications**: ลงทะเบียนระบบปลายทาง (client_id, secret, redirect URI ที่อนุญาต, group ที่เข้าระบบนั้นได้)
5. Audit log และ Request log ของการ login ผ่าน SSO ทุกครั้ง
6. (ทางเลือก) **Windows Integrated Login**: เครื่องที่ join โดเมนแล้วเข้าได้เลยโดยไม่ต้องพิมพ์รหัส (Kerberos)

### สิ่งที่ระบบปลายทางต้องทำ (ตัวอย่าง ASP.NET Core)

```csharp
builder.Services.AddAuthentication(o =>
    {
        o.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        o.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
    })
    .AddCookie()
    .AddOpenIdConnect(o =>
    {
        o.Authority = "https://authen.hondacx.me";
        o.ClientId = "coupon";
        o.ClientSecret = builder.Configuration["Sso:ClientSecret"];
        o.ResponseType = "code";            // Authorization Code + PKCE
        o.Scope.Add("profile"); o.Scope.Add("email"); o.Scope.Add("groups");
        o.SaveTokens = true;
    });
```
ระบบที่ไม่ใช่ .NET ให้ใช้ library OIDC ของภาษานั้น เช่น Java Spring Security OAuth2 Client, PHP `jumbojett/openid-connect-php`, Node `openid-client`


---

## 13. คำถามที่พบบ่อย

**ผู้ใช้พิมพ์ UPN เต็ม แต่ใน log ของ AuthenAPI เห็นแค่ชื่อหน้า @ เป็นตัวพิมพ์เล็ก**
แปลว่าระบบของคุณตัด `@ipsos.com` และแปลงตัวพิมพ์ก่อนส่งมา ช่อง Username ใน Request Logs คือค่าที่ AuthenAPI ได้รับจริงแบบตัวต่อตัว ให้แก้ระบบให้ส่งตามที่ผู้ใช้พิมพ์ (หัวข้อ 3) กรณีนี้เคยเกิดกับ Cash Advance System

**ผู้ใช้ยืนยันว่ารหัสถูก แต่ได้ 401**
ให้ผู้ดูแล AuthenAPI ดูช่อง "ผลลัพธ์" ใน Request Logs:
- `UserNotFound`: ชื่อที่ส่งมาไม่ตรงกับบัญชีใดเลย หรือตรงมากกว่า 1 บัญชี
- `InvalidCredentials`: รหัสผิด หรือระบบส่ง hash มาแทนรหัสจริง
- `AccountLocked` / `AccountDisabled` / `PasswordExpired`: ทีม IT ต้องแก้ที่ AD

**ทำไมไม่ cache ผล login แล้วข้ามการถาม API ไปเลย จะได้เร็ว**
API ใช้เวลาราว 50–500 ms ซึ่งเร็วพอสำหรับการ login อยู่แล้ว แต่ถ้าข้าม คนที่ถูก disable หรือเปลี่ยนรหัสไปแล้วจะยังเข้าด้วยรหัสเก่าได้ ไม่คุ้มกัน

**ระบบเป็น PHP / Java / Node**
ใช้หลักการเดียวกันทั้งหมด โค้ด C# อ่านเป็น pseudo-code ได้ สิ่งที่ต้องทำตามจริง ๆ คือตารางในหัวข้อ 4 และกฎในหัวข้อ 6–8
