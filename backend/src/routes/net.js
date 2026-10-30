/**
 * Network: SSRF (#10), DNS rebinding (#55), open redirect (#32),
 * response splitting (#34), host-header issues (#35), cache poisoning (#37/#65),
 * web cache deception (#38).
 */
const express = require("express");

module.exports = (container) => {
  const db = container.resolve("db");
  const r = express.Router();

  /* [VULN #10] SSRF: fetch any URL and return the body.
     payloads: ?url=http://169.254.169.254/latest/meta-data/
               ?url=http://localhost:6379/  (Redis port scan via errors)
     [VULN #55] no IP allowlist / no resolved-IP pinning -> DNS rebinding works */
  r.get("/api/net/fetch", async (req, res, next) => {
    try {
      const url = String(req.query.url || "");
      const started = Date.now();
      const resp = await fetch(url, { redirect: "follow" });
      const body = await resp.text();
      res.json({ url, status: resp.status, ms: Date.now() - started, headers: Object.fromEntries(resp.headers), body: body.slice(0, 100_000) });
    } catch (e) {
      next(e); // error text reveals internal hosts/ports (#43)
    }
  });

  /* [VULN #32] open redirect: ?url=https://evil.tld */
  r.get("/api/net/redirect", (req, res) => {
    const url = String(req.query.url || "/");
    res.redirect(url);
  });

  /* [VULN #34] response splitting attempt: modern Node rejects CRLF in header
     values (throws ERR_INVALID_CHAR -> leaked stack), older stacks/proxies split.
     payload: ?to=x%0d%0aSet-Cookie:%20pwned=1 */
  r.get("/api/net/jump", (req, res) => {
    const to = String(req.query.to || "home");
    res.writeHead(302, { Location: `/goto/${to}` });
    res.end(`redirecting to /goto/${to}`);
  });

  /* [VULN #37][VULN #65] web cache poisoning: unkeyed X-Forwarded-Host reflected
     into the body, response is public + cacheable -> poison the CDN cache.
     payload: curl -H "X-Forwarded-Host: evil.tld" <site>/api/net/echo-headers */
  r.get("/api/net/echo-headers", (req, res) => {
    res.setHeader("Cache-Control", "public, max-age=3600");
    const host = req.headers["x-forwarded-host"] || req.headers.host;
    const proto = req.headers["x-forwarded-proto"] || req.protocol; // trust proxy = on
    res.json({
      assetBase: `${proto}://${host}/static`, // poisoned asset base
      reflectedHeaders: {
        "x-forwarded-host": req.headers["x-forwarded-host"] || null,
        "x-forwarded-proto": req.headers["x-forwarded-proto"] || null,
        "x-forwarded-for": req.headers["x-forwarded-for"] || null,
        "user-agent": req.headers["user-agent"] || null,
      },
      cached: true,
    });
  });

  /* [VULN #38] web cache deception: profile JSON served under ANY path ending
     .css with public caching -> victim's profile cached under attacker-known URL.
     payload: GET /api/cache/profile/whatever.css (while authenticated) */
  r.get("/api/cache/profile/:anything", async (req, res, next) => {
    try {
      const { currentUserId } = require("../auth/current-user");
      const uid = await currentUserId(req, container);
      if (!uid) return res.status(401).json({ error: "login first" });
      const { rows } = await db.query("SELECT id, email, role, balance, api_key FROM users WHERE id = $1", [uid]);
      res.setHeader("Cache-Control", "public, max-age=86400"); // cacheable personal data
      res.json({ profile: rows[0], servedAs: req.params.anything });
    } catch (e) {
      next(e);
    }
  });

  /* [VULN #37] cacheable key/value store (pair with a Cloudflare cache rule) */
  r.post("/api/cache/store", async (req, res) => {
    const cache = container.resolve("cache");
    const { key, value } = req.body || {};
    await cache.set(String(key || ""), String(value || ""), 3600_000);
    res.json({ ok: true });
  });
  r.get("/api/cache/store/:key", async (req, res) => {
    const cache = container.resolve("cache");
    res.setHeader("Cache-Control", "public, max-age=600");
    res.json({ key: req.params.key, value: await cache.get(req.params.key) });
  });

  return r;
};
