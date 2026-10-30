/**
 * Misc: email spoofing (#68), account enumeration (#67), debug/info disclosure
 * (#42/#43), insecure headers (#70), CSP misconfig (#41), route map.
 */
const express = require("express");

module.exports = (container) => {
  const config = container.resolve("config");
  const db = container.resolve("db");
  const mailer = container.resolve("mailer");
  const r = express.Router();

  /* [VULN #68] email spoofing: "from" is caller-controlled. Recipient is FIXED
     to the site owner (SMTP_USER) so this cannot be abused as a spam relay. */
  r.post("/api/contact", async (req, res, next) => {
    try {
      const { from, subject, message } = req.body || {};
      const info = await mailer.send({
        from: from || "spoofed@attacker.tld", // arbitrary From
        to: config.smtpUser, // fixed recipient (owner inbox)
        subject: `[vulnshop contact] ${subject || "(no subject)"}`,
        html: `<p>From: ${from}</p><pre>${String(message || "").slice(0, 5000)}</pre>`,
      });
      res.json({ ok: true, sent: !info.skipped, info, note: "From header fully attacker-controlled (#68)" });
    } catch (e) {
      next(e);
    }
  });

  /* [VULN #67] account enumeration oracle */
  r.get("/api/enumerate", async (req, res, next) => {
    try {
      const email = String(req.query.email || "");
      const { rows } = await db.query("SELECT id FROM users WHERE email = $1", [email]);
      res.json({ email, exists: rows.length > 0 });
    } catch (e) {
      next(e);
    }
  });

  /* [VULN #42][VULN #43] debug config dump - masks REAL third-party credentials
     (DB / SMTP) but leaks the JWT secret + admin token used in the demos. */
  r.get("/api/debug/config", (req, res) => {
    const mask = (s) => (s ? String(s).slice(0, 12) + "***" : null);
    res.json({
      appName: config.appName,
      nodeVersion: process.version,
      platform: process.platform,
      uptimeSec: Math.round(process.uptime()),
      jwtSecret: config.jwtSecret, // [VULN #61] leaked -> forge JWTs
      adminToken: config.adminToken, // [VULN #12] leaked
      encryptionKey: config.encKey, // [VULN #47]
      databaseUrl: mask(config.databaseUrl),
      redisUrl: mask(config.redisUrl),
      smtpUser: config.smtpUser ? mask(config.smtpUser) : null,
      smtpPass: config.smtpPass ? "(present, masked - real creds stay hidden)" : "(not configured)",
      adminBypass: config.adminBypass,
      hint: "JWT/ adminToken are fake lab secrets; DB/SMTP creds are masked on purpose",
    });
  });

  /* [VULN #43] throw a stack trace on demand */
  r.get("/api/debug/error", (req, res, next) => {
    next(new Error(`Debug explosion: ${req.query.msg || "boom"}`));
  });

  /* [VULN #41] permissive CSP served on demand */
  r.get("/api/csp-demo", (req, res) => {
    res.setHeader("Content-Security-Policy", "default-src * 'unsafe-inline' 'unsafe-eval' data: blob:");
    res.type("html").send("<h1>CSP allows everything ('unsafe-inline' + 'unsafe-eval' + *)</h1>");
  });

  /* [VULN #70] deliberately bad headers on this endpoint (site-wide: headers absent) */
  r.get("/api/headers", (req, res) => {
    res.setHeader("Server", "nginx/1.25.3 (VulnShop)");
    res.setHeader("X-Powered-By", "Express");
    res.setHeader("Referrer-Policy", "unsafe-url");
    res.json({ headers: req.headers, note: "no HSTS/XFO/nosniff anywhere; this one adds a fake Server + X-Powered-By" });
  });

  /* [VULN #42] public API map - every route in one response */
  r.get("/api/docs", (req, res) => {
    const routes = [];
    try {
      const walk = (stack, base) => {
        (stack || []).forEach((layer) => {
          if (layer.route) {
            const methods = Object.keys(layer.route.methods || {})
              .map((m) => m.toUpperCase())
              .join("|");
            routes.push(`${methods} ${base}${layer.route.path === "/" ? "" : layer.route.path}`);
          } else if (layer.name === "router" && layer.handle && layer.handle.stack) {
            let mb = "";
            if (layer.regexp && layer.regexp.fastSlash !== true) {
              mb = layer.regexp.source
                .replace(/^\^/, "")
                .replace(/\\\/\?\(\?=\\\/\|\$\)[a-z]?\$?\/?$/i, "")
                .replace(/\\\//g, "/")
                .replace(/\/+$/, "");
              mb = mb && mb !== "" ? (mb.startsWith("/") ? mb : "/" + mb) : "";
            }
            walk(layer.handle.stack, base + mb);
          }
        });
      };
      walk(req.app._router ? req.app._router.stack : req.app.router.stack, "");
    } catch {}
    res.json({ routes: routes.filter((x) => !x.includes("health")), count: routes.length });
  });

  /* Collector cho các demo client-side (#25 token theft, #51 tracking):
     "analytics"/attacker script gửi event vào đây; GET list = "attacker view". */
  const telemetry = [];
  r.post("/api/telemetry", (req, res) => {
    const ev = { at: new Date().toISOString(), ...(req.body || {}) };
    telemetry.push(ev);
    if (telemetry.length > 500) telemetry.shift();
    res.json({ ok: true, received: ev });
  });
  r.get("/api/telemetry", (req, res) => {
    res.json({ events: telemetry.slice(-100), count: telemetry.length });
  });

  return r;
};
