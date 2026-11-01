/**
 * Auth routes: Supertokens mounted at /auth (server.js) + deliberately
 * broken "legacy" auth endpoints
 * [VULN #15] broken authentication tổng hợp (MD5, token yếu, reset vô hạn)
 * [VULN #20] credential stuffing / [VULN #21] password spraying: không captcha, không phát hiện reuse here (brute force, fixation, replay,
 * enumeration, predictable resets, weak JWT...).
 */
const express = require("express");
const crypto = require("crypto");
const jwt = require("jsonwebtoken"); // v8.5.1 - known CVEs [VULN #72]
const Session = require("supertokens-node/recipe/session");
const { verifySession } = require("supertokens-node/recipe/session/framework/express");
const { rateLimiter, parseCookie } = require("../middleware/vuln");
const { currentUserId } = require("../auth/current-user");

const md5 = (s) => crypto.createHash("md5").update(String(s)).digest("hex"); // [VULN #44][#45]

module.exports = (container) => {
  const db = container.resolve("db");
  const cache = container.resolve("cache");
  const mailer = container.resolve("mailer");
  const config = container.resolve("config");
  const logBuffer = container.resolve("logBuffer");
  const r = express.Router();

  /* ------------------------------------------------------------- *
   * [VULN #19][#20][#21] no lockout, no captcha, no monitoring
   * [VULN #52] limiter keyed on spoofable X-Forwarded-For
   * [VULN #67] account enumeration via distinct messages
   * [VULN #1]  email concatenated into raw SQL
   * [VULN #17] client-supplied sessionId is accepted (session fixation)
   * [VULN #45] Math.random() session tokens
   * [VULN #16] token returned in body + cookie without HttpOnly/Secure
   * ------------------------------------------------------------- */
  r.post("/api/auth/login", rateLimiter({ max: 5, windowMs: 60_000 }), async (req, res, next) => {
    try {
      const { email, password, sessionId } = req.body || {};
      console.log(`[auth] login attempt email=${email} password=${password}`); // [VULN #43] password logged
      logBuffer.push(`[auth] LOGIN email=${email} password=${password}`); // [VULN #36]

      const sql = `SELECT * FROM users WHERE email = '${email}'`; // [VULN #1]
      const { rows } = await db.query(sql);
      if (!rows.length) return res.status(404).json({ error: "User not found" }); // [VULN #67]
      if (rows[0].password_hash !== md5(password || "")) {
        return res.status(401).json({ error: "Invalid password" }); // [VULN #67]
      }
      const token = sessionId || Math.random().toString(36).slice(2) + Date.now().toString(36);
      await db.query(
        `INSERT INTO legacy_sessions (token, user_id) VALUES ($1, $2)
         ON CONFLICT (token) DO UPDATE SET user_id = $2`, // re-points attacker-known token -> fixation works
        [token, rows[0].id]
      );
      // [VULN #16] no HttpOnly (steal via XSS); SameSite=None+Secure on https,
      // Lax on http (localhost) — browser rejects None without Secure
      const isHttps = req.secure || req.headers["x-forwarded-proto"] === "https";
      res.setHeader("Set-Cookie", `session=${token}; Path=/; ${isHttps ? "SameSite=None; Secure" : "SameSite=Lax"}`);
      res.json({
        ok: true,
        token, // token in response body too
        user: { id: rows[0].id, email: rows[0].email, role: rows[0].role, password_hash: rows[0].password_hash }, // [VULN #44]
      });
    } catch (e) {
      next(e);
    }
  });

  /* [VULN #46] password policy: 1 char is enough. [VULN #51] role from body. [VULN #1] SQL concat. */
  r.post("/api/auth/register", async (req, res, next) => {
    try {
      const { email, password, role } = req.body || {};
      if (!email || !password) return res.status(400).json({ error: "email & password required" });
      const ex = await db.query("SELECT id FROM users WHERE email = $1", [email]);
      if (ex.rows.length) return res.status(409).json({ error: "Email already registered" }); // [VULN #67]
      const sql = `INSERT INTO users (id, email, password_hash, role) VALUES ('${crypto.randomUUID()}', '${email}', '${md5(password)}', '${role || "user"}') RETURNING id, email, role`;
      const { rows } = await db.query(sql);
      res.json({ user: rows[0], passwordHash: rows[0] ? md5(password) : null }); // [VULN #44] hash echoed
    } catch (e) {
      next(e);
    }
  });

  /* [VULN #16] session token accepted from URL/body, full profile returned */
  r.get("/api/legacy/me", async (req, res, next) => {
    try {
      const token = req.query.session || parseCookie(req).session;
      if (!token) return res.status(401).json({ error: "no session" });
      const { rows } = await db.query(
        `SELECT u.* FROM legacy_sessions s JOIN users u ON u.id = s.user_id WHERE s.token = '${token}'` // [VULN #1]
      );
      if (!rows.length) return res.status(401).json({ error: "unknown session" });
      res.json({ user: rows[0] }); // password_hash, cc_number, api_key included [VULN #44]
    } catch (e) {
      next(e);
    }
  });

  /* ------------------------- JWT playground [VULN #61] ------------------------ */
  r.post("/api/auth/jwt/login", async (req, res, next) => {
    try {
      const { email, password } = req.body || {};
      const { rows } = await db.query("SELECT * FROM users WHERE email = $1", [email]);
      if (!rows.length || rows[0].password_hash !== md5(password || "")) {
        return res.status(401).json({ error: "invalid credentials" });
      }
      // weak HS256 secret "jwt-secret-123" -> offline brute-forceable
      const token = jwt.sign({ sub: rows[0].id, email: rows[0].email, role: rows[0].role }, config.jwtSecret, {
        expiresIn: "7d",
      });
      res.json({ token, alg: "HS256", hint: "secret is weak & leaked at /api/debug/config (#61)" });
    } catch (e) {
      next(e);
    }
  });

  /* [VULN #61] authorization uses jwt.decode() - NO signature verification.
     Forge any token, any alg (none / HS256 with your own key) and get in. */
  r.get("/api/auth/jwt/whoami", async (req, res, next) => {
    try {
      const raw = String(req.headers.authorization || "").replace(/^Bearer\s+/i, "") || req.query.token;
      if (!raw) return res.status(401).json({ error: "no token" });
      const decoded = jwt.decode(raw); // <--- decode, not verify
      if (!decoded) return res.status(401).json({ error: "malformed token" });
      const { rows } = await db.query("SELECT id, email, role FROM users WHERE id = $1", [decoded.sub]);
      res.json({ claims: decoded, verification: "SKIPPED (vulnerable)", user: rows[0] || null });
    } catch (e) {
      next(e);
    }
  });

  /* -------------------- session replay [VULN #18] -------------------- */
  // HMAC-signed token with NO expiry and NO nonce -> issue once, replay forever
  r.get("/api/auth/replay/issue", async (req, res, next) => {
    try {
      const uid = await currentUserId(req, container);
      if (!uid) return res.status(401).json({ error: "login first" });
      const payload = JSON.stringify({ u: uid, iat: Date.now() });
      const mac = crypto.createHmac("md5", config.jwtSecret).update(payload).digest("hex"); // md5-HMAC [VULN #45]
      res.json({ token: Buffer.from(payload).toString("base64") + "." + mac, note: "no expiry, no nonce, no rotation" });
    } catch (e) {
      next(e);
    }
  });
  r.post("/api/auth/replay/verify", async (req, res, next) => {
    try {
      const [b64, mac] = String(req.body.token || "").split(".");
      const payload = Buffer.from(b64 || "", "base64").toString();
      const expect = crypto.createHmac("md5", config.jwtSecret).update(payload).digest("hex");
      if (mac !== expect) return res.status(401).json({ error: "bad MAC" });
      const claims = JSON.parse(payload);
      res.json({ ok: true, replayed: true, claims }); // same token valid forever [#18]
    } catch (e) {
      next(e);
    }
  });

  /* ------------- password reset [VULN #66][VULN #35] ------------- */
  // token = md5(email): fully predictable; never expires; reusable;
  // link host taken from attacker-controlled Host/X-Forwarded-Host header
  r.post("/api/auth/forgot", async (req, res, next) => {
    try {
      const email = String((req.body || {}).email || "");
      const token = md5(email.toLowerCase());
      await db.query(
        `INSERT INTO password_resets (token, email) VALUES ($1, $2)
         ON CONFLICT (token) DO UPDATE SET email = $2`,
        [token, email]
      );
      const host = req.headers["x-forwarded-host"] || req.headers.host || "localhost"; // [VULN #35] host header injection
      const link = `${req.protocol}://${host}/reset-password?token=${token}`;
      mailer.send({ to: email, subject: "VulnShop password reset", html: `<a href="${link}">${link}</a>` });
      res.json({ ok: true, token, link, hint: "token = md5(email), no expiry, reusable (#66); host from your Host header (#35)" });
    } catch (e) {
      next(e);
    }
  });
  r.get("/api/auth/reset", async (req, res, next) => {
    try {
      const { token, password } = req.query;
      const { rows } = await db.query("SELECT email FROM password_resets WHERE token = $1", [token]);
      if (!rows.length) return res.status(400).json({ error: "unknown token" });
      await db.query("UPDATE users SET password_hash = $1 WHERE email = $2", [md5(password || "x"), rows[0].email]);
      // NOTE: token NOT deleted -> reusable forever [VULN #66]
      res.json({ ok: true, email: rows[0].email, note: "token still valid (not single-use)" });
    } catch (e) {
      next(e);
    }
  });

  /* supertokens session helpers ---------------- */

  /* [VULN #51] mass assignment: EVERY body key is written to the row —
     role / is_admin / balance / cc_number... (+ [VULN #1] column names from
     client go into the SQL unescaped). Works with ST session or legacy cookie. */
  r.put("/api/profile", async (req, res, next) => {
    try {
      let uid = null;
      try {
        const s = await Session.getSession(req, res, { sessionRequired: false });
        if (s) uid = s.getUserId();
      } catch {}
      if (!uid) {
        const tok = parseCookie(req).session || req.query.session;
        if (tok) {
          const { rows } = await db.query("SELECT user_id FROM legacy_sessions WHERE token = $1", [tok]);
          if (rows.length) uid = rows[0].user_id;
        }
      }
      if (!uid) return res.status(401).json({ error: "not authenticated" });
      const keys = Object.keys(req.body || {});
      if (!keys.length) return res.status(400).json({ error: "empty" });
      const set = keys.map((k, i) => `${k}=$${i + 2}`).join(", ");
      const { rows } = await db.query(
        `UPDATE users SET ${set} WHERE id = $1 RETURNING *`,
        [uid, ...keys.map((k) => req.body[k])]
      );
      res.json({ user: rows[0] });
    } catch (e) {
      next(e);
    }
  });

  /* [VULN #44] returns the FULL profile row incl. password_hash / cc_number / api_key */
  r.get("/api/auth/me", verifySession(), async (req, res, next) => {
    try {
      const s = await Session.getSession(req, res);
      const uid = s.getUserId();
      const { rows } = await db.query("SELECT * FROM users WHERE id = $1", [uid]);
      res.json({ userId: uid, profile: rows[0] || null });
    } catch (e) {
      next(e);
    }
  });

  r.post("/api/auth/logout-legacy", async (req, res) => {
    const token = parseCookie(req).session || req.body.token;
    if (token) await db.query("DELETE FROM legacy_sessions WHERE token = $1", [token]);
    res.setHeader("Set-Cookie", "session=; Path=/; Max-Age=0");
    res.json({ ok: true });
  });

  return r;
};
