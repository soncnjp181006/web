# VulnPC Shop 🔥🖥 — PC Store (Intentionally Vulnerable, Full-featured)

> ⚠️ **CẢNH BÁO**: Website bán PC **hoàn chỉnh** chứa lỗi bảo mật **CỐ Ý** (intentionally vulnerable)
> dùng cho học tập / training / pentest practice — phong cách OWASP Juice Shop. **135 lỗi** (75 backend
> + 60 client-side) nằm **tự nhiên bên trong từng tính năng** của shop, không phải lab rời rạc.
> **KHÔNG** dùng dữ liệu thật. Public internet = bot tấn công trong vài phút — tắt khi không dùng.

## Tính năng (kết nối xuyên suốt)

```
Trang chủ → Cửa hàng (tìm kiếm/lọc/sort) → Chi tiết sản phẩm (review, specs, wishlist)
   → Giỏ hàng (số lượng, coupon) → Checkout (địa chỉ, thẻ) → Đơn hàng (chi tiết, hóa đơn PDF, RMA)
   → Hỗ trợ (ticket + live chat WS + đính kèm + email) → Profile (ví, bio, theme, mass-assign)
   → Admin (quản trị, exec, logs, vendor tools) · Staff portal legacy (JWT/SAML/OAuth)
Ngoài ra: Build PC, So sánh, Deals, Stores, Offline center, Notifications, Sessions
```

| Thành phần | Công nghệ |
| --- | --- |
| Frontend | React 18 (Vite) trên **Cloudflare Pages** |
| Backend | Node.js 20 + Express (raw SQL) trên **Render** (Docker) |
| Gateway | **nginx** cùng container node (10000 → 4000) |
| DB | **PostgreSQL** (Render) — raw SQL toàn bộ |
| Cache | **Redis** (Render Key Value) |
| Auth | **Supertokens** EmailPassword + Session (self-host core) + legacy staff portal |
| Email | Gmail SMTP qua nodemailer (env) |
| CI/CD | GitHub Actions → Render hook / Cloudflare wrangler |
| DI | container tự viết (`backend/src/di/container.js`) |

## Cấu trúc

```
backend/            Express API — mọi lỗ hổng đánh dấu [VULN #N]
  src/routes/       products, cart, orders, support, wishlist, builds, admin,
                    files, utils, net, xml, oauth, saml, misc, graphql, auth
  nginx/app.conf    gateway yếu có chủ đích
frontend/           React SPA — 19 trang shop, lỗi client-side nhúng trong tính năng
infra/supertokens/  Dockerfile ST core (port 3567)
render.yaml         Blueprint: backend + ST core + Redis + Postgres
docs/DEPLOY.md      deploy Render + Cloudflare từng bước
docs/VULNS.md       MAP 135 lỗi → tính năng + payload mẫu
```

## Tài khoản demo (sau khi seed)

- Supertokens: đăng ký email + password tuỳ ý (UI `/auth`)
- Legacy staff: `admin@pcforge.local / admin123`, `victim@pcforge.local / victim123`
- Coupon: `WELCOME10`, `PCLOVE50` (race), `BLACKFRIDAY20`

## 🧪 Vị trí lỗi đã ẩn khỏi UI (cho người test — UI nhìn như shop bình thường)

Toàn bộ bản đồ 135 lỗi (75 backend + 60 client) + payload mẫu nằm trong **docs/VULNS.md**.
UI đã được dọn sạch hint/số hiệu lỗi/creds để không bị scanner nhận ra. Chỗ cần nhớ nhanh:

- **Admin**: gate chỉ ở client — mở bằng `?debug_login=1` hoặc `localStorage.vulnshop_user = {"role":"admin"}`
  hoặc `?__proto__[isAdmin]=true`; API gate nhận header `x-admin-token` (giá trị thật ở `/internal`)
  hoặc prototype pollution `POST /api/utils/merge {"__proto__":{"adminBypass":true}}`
- **Diagnostics nội bộ**: `/internal` (config dump, API map, users dump, weak token, AES-ECB...)
- **Staff legacy**: `/legacy` (brute force, fixation, JWT, SAML, OAuth, reset md5)
- **Trang demo** (không có trong nav): `/assets-lab/clickjack.html`, `/assets-lab/csrf.html`,
  `/assets-lab/tabnab.html`, `/assets-lab/pmsender.html`
- **Endpoint "ngon"**: `GET /api/products/search?q=` (SQLi) · `POST /api/products/filter` (NoSQL `$where`)
  · `GET /api/orders/export?tpl=` (SSTI) · `POST /api/xml/parse` (XXE) · `GET /api/utils/regex?q=` (ReDoS)
  · `GET /api/net/fetch?url=` (SSRF) · `POST /api/utils/eval|unserialize|merge` (RCE/pollution)
  · `/graphql` (GraphiQL mở, BOLA) · `GET /api/v2/users` (dump không auth)
- **Sourcemap production đang BẬT** (vuln #19/#20 — tải `/assets/*.js.map` thấy source gốc có marker
  `[VULN #N]`). Muốn giảm dấu vết khi scan: bỏ `sourcemap: true` trong `frontend/vite.config.js`.

## Checklist an toàn

- [ ] Chỉ dùng dữ liệu giả
- [ ] Rotate Gmail app password sau khi xong (đã từng xuất hiện trong chat)
- [ ] Tắt Cloudflare WAF/Bot Fight Mode khi muốn payload chạy
- [ ] Xoá service Render/Pages + docker khi xong lab
