# Deploy VulnShop lên Render + Cloudflare Pages

Mục tiêu kiến trúc:

- **Frontend** → Cloudflare Pages (React/Vite, cùng origin với API qua proxy `_redirects`)
- **Backend** → Render (Docker: nginx gateway + node) + PostgreSQL + Redis + Supertokens core
- **CI/CD** → GitHub Actions (đã có `.github/workflows/ci.yml`)

> Không cần chạy local bất cứ thứ gì. Toàn bộ chạy trên Render/Cloudflare sau khi push code lên GitHub.

---

## Bước 0 — Push code lên GitHub

```bash
cd <thư-mục-project>
git add -A
git commit -m "VulnShop: intentionally vulnerable training app"
git branch -M main
git remote add origin https://github.com/<user>/<repo>.git
git push -u origin main
```

## Bước 1 — Deploy backend bằng Render Blueprint

1. Render Dashboard → **New +** → **Blueprint** → chọn repo vừa push → **Apply**.
2. Render sẽ tạo 4 service theo `render.yaml`:
   - `vulnshop-backend` (Docker web service, health check `/health`)
   - `vulnshop-st` (Supertokens core, private service :3567)
   - `vulnshop-redis` (Key Value, free)
   - `vulnshop-db` (PostgreSQL, free — **lưu ý: DB free của Render hết hạn sau 30 ngày**, phải tạo lại hoặc upgrade)
3. Khi apply, Render hỏi các biến `sync: false` — điền:
   - `SMTP_USER` = `tranxuanson2k61810@gmail.com`
   - `SMTP_PASS` = app-password Gmail (giá trị đã cung cấp riêng — **không commit vào git**)
   - `API_DOMAIN` / `WEBSITE_DOMAIN`: tạm để `https://vulnshop.pages.dev`, sau Bước 3 quay lại sửa đúng URL.
4. Đợi build ~5-10 phút. Xong sẽ có URL kiểu `https://vulnshop-backend.onrender.com`.
   Test: mở `https://vulnshop-backend.onrender.com/health` → `{"ok":true}`.
5. Schema + seed tự chạy lần đầu (admin/victim users, products, comments, coupons).

> Free plan: web service ngủ sau 15 phút không traffic → request đầu chậm ~30s.

## Bước 2 — Deploy frontend lên Cloudflare Pages

1. Cloudflare Dashboard → **Workers & Pages** → **Create** → **Pages** → **Connect to Git** → chọn repo.
2. Cấu hình build:
   - **Project name**: `vulnshop` (URL sẽ là `https://vulnshop.pages.dev`)
   - **Production branch**: `main`
   - **Root directory**: `frontend`
   - **Build command**: `npm install && npm run build`
   - **Build output directory**: `dist`
   - **Environment variables** (Production + Preview):
     - `NODE_VERSION` = `20`
     - `RENDER_BACKEND_URL` = `https://vulnshop-backend.onrender.com` (URL backend Bước 1)
     - `VITE_WS_URL` = `wss://vulnshop-backend.onrender.com/ws/chat` (proxy `_redirects` không hỗ trợ WebSocket nên chat kết nối thẳng)
3. **Save and Deploy**. Vite build + script `gen-redirects` sẽ ghi `dist/_redirects` trỏ `/api`, `/auth`,
   `/graphql`, `/uploads` về backend → **frontend và API cùng origin, cookie Supertokens là first-party**.

## Bước 3 — Quay lại Render, hoàn thiện env

- `vulnshop-backend` → **Environment** → sửa `API_DOMAIN` + `WEBSITE_DOMAIN` = URL Pages thật (ví dụ `https://vulnshop.pages.dev`) → **Save + Deploy**.
  (2 biến này dùng cho link email reset password của Supertokens.)

## Bước 4 — CI/CD (tùy chọn, đã cấu hình sẵn)

Workflow `.github/workflows/ci.yml` tự chạy khi push/PR:

- backend: `npm install` → `node --check` toàn bộ file → smoke test boot `/health`
- frontend: `npm run build` + upload artifact `frontend-dist`
- deploy: nếu push lên `main`:
  - backend: bấm **Deploy hook** của Render (thêm secret `RENDER_DEPLOY_HOOK_URL`; nếu bỏ trống thì Render tự deploy nhờ `autoDeploy: true`)
  - frontend: deploy `dist` bằng wrangler (thêm secrets `CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ACCOUNT_ID`; nếu bỏ trống thì Pages Git-integration tự lo)

Secrets thêm ở GitHub → repo → **Settings → Secrets and variables → Actions**.

## Bước 5 — Cloudflare experiments cho các lỗi cache/WAF

Các demo sau cần chỉnh Cloudflare để "sống":

| Demo | Cần làm |
| --- | --- |
| Web cache poisoning (#37/#65), cache deception (#38) | Tạo **Cache Rule**: cache eligible cho `vulnshop.pages.dev/api/*` (mặc định CF chỉ cache static ext — `/api/cache/profile/x.css` đã hợp lệ sẵn) |
| Payload XSS/SQLi bị chặn | Nếu bật WAF Managed Rules / Bot Fight Mode → tạo **WAF exception** cho IP của bạn, hoặc tắt tạm khi lab |
| Rate limit demo | CF free không đụng tới — rate limiter chạy ở backend |

## Bước 6 — Subdomain takeover demo ([VULN #56], cấu hình thủ công)

1. Cloudflare → DNS → thêm record: `old-api` CNAME → `vulnshop-gone.pages.dev` (subdomain **chưa** đăng ký trong Pages).
2. Cloudflare sẽ warning "target does not exist" — vẫn cho tạo (proxied).
3. Giờ domain `old-api.vulnshop.pages.dev` trả lỗi "there isn't a Pages project here yet" → có thể **claim bằng cách tạo Pages project đúng tên đó** → takeover hoàn chỉnh. Đây là lab; đừng làm với domain người khác.

## Khắc phục sự cố

| Triệu chứng | Nguyên nhân / cách xử lý |
| --- | --- |
| `/health` OK nhưng mọi API lỗi DB | Free Postgres hết hạn sau 30 ngày → tạo DB mới, cập nhật `DATABASE_URL` |
| Login Supertokens lỗi `connection refused` | ST core chưa sống: kiểm tra service `vulnshop-st` logs; `SUPERTOKENS_CONNECTION_URI` phải là `http://vulnshop-st:3567` |
| Email reset không đến | Kiểm tra `SMTP_USER`/`SMTP_PASS` trong Render env; Gmail app password cần spaces giữ nguyên như cấp phát |
| Chat không kết nối | Đặt `VITE_WS_URL=wss://<backend>/ws/chat` và build lại frontend |
| 401 liên tục ở Supertokens | Đảm bảo đang truy cập qua domain Pages (cùng origin), không gọi thẳng backend domain từ app |

## Vệ sinh sau khi lab xong

1. Render → xóa project (backend/ST/redis/db).
2. Cloudflare → xóa Pages project + DNS records demo.
3. **Rotate Gmail app password** (Google Account → Security → App passwords).
