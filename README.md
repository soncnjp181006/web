# VulnShop 🏪💣 — Intentionally Vulnerable Training App

> ⚠️ **CẢNH BÁO**: Đây là ứng dụng chứa lỗi bảo mật **CỐ Ý** (intentionally vulnerable) dùng cho
> học tập / training / pentest practice — theo phong cách OWASP Juice Shop / DVWA.
> **KHÔNG** deploy với dữ liệu thật, **KHÔNG** dùng làm production. Khi public lên internet,
> app sẽ bị scan/tấn công bởi bot trong vài phút — chỉ deploy khi cần lab và tắt khi không dùng.

## Stack

| Thành phần        | Công nghệ                                            |
| ----------------- | ---------------------------------------------------- |
| Frontend          | React 18 (Vite) trên **Cloudflare Pages**            |
| Backend           | Node.js 20 + Express (raw SQL, không ORM) trên **Render** (Docker) |
| Gateway           | **nginx** chạy cùng container với node (port 10000 → 4000) |
| Database          | **PostgreSQL** (Render free) — raw SQL, SQL injection toàn bộ app |
| Cache/Queue       | **Redis** (Render Key Value) — rate limiter, cache demos |
| Auth              | **Supertokens** (EmailPassword + Session, self-hosted core trên Render) |
| Email             | SMTP Gmail qua nodemailer (env `SMTP_USER` / `SMTP_PASS`) |
| CI/CD             | GitHub Actions (build + smoke test + deploy Render/Cloudflare) |
| DI                | DI container tự viết (`backend/src/di/container.js`) |

```
Browser
  └─ Cloudflare Pages (React SPA, cache/WAF experiments)
       ├─ / , /static  → Pages static
       ├─ /api, /auth, /graphql, /uploads → proxy (_redirects) ─┐
  └─ WebSocket wss://.../ws/chat (direct to backend)            │
                                                                ▼
                              Render: nginx gateway :10000 ──► node :4000
                                                        ├─ PostgreSQL (raw SQL)
                                                        ├─ Redis
                                                        └─ Supertokens core (pserv :3563)
```

## Cấu trúc

```
backend/            Express API + toàn bộ lỗ hổng (mỗi chỗ đánh dấu [VULN #N])
  nginx/app.conf    gateway config yếu có chủ đích
  Dockerfile        nginx + node một container
frontend/           React SPA + trang demo (Lab, DOM XSS, Chat, Admin...)
infra/supertokens/  Dockerfile Supertokens core
render.yaml         Render Blueprint (backend + ST core + Redis + Postgres)
.github/workflows/  CI/CD
docs/DEPLOY.md      hướng dẫn deploy Render + Cloudflare từng bước
docs/VULNS.md       map 75 loại lỗ hổng → endpoint + payload mẫu
```

## Chạy nhanh sau khi deploy

1. Đăng nhập Supertokens: nút **Sign in / Sign up** (email + password, có mail reset qua SMTP).
2. Legacy login (vulnerable): trang **Legacy login** — `admin@vulnshop.local / admin123`,
   `victim@vulnshop.local / victim123`.
3. Trang **Attack lab** bấm từng payload mẫu; **DOM XSS lab** cho lỗi client-side;
   tài liệu đầy đủ trong `docs/VULNS.md`.

## Checklist an toàn cho người dùng

- [ ] Chỉ dùng email test / dữ liệu giả (DB có thể bị dump công khai).
- [ ] Rotate Gmail app password sau khi xong việc (credential đã từng xuất hiện trong chat).
- [ ] Tắt/cân nhắc Cloudflare WAF + Bot Fight Mode khi muốn exploit demo hoạt động.
- [ ] Xóa service Render/Pages khi không dùng nữa.
