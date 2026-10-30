/**
 * Admin routes. Gates are weak on purpose:
 *  - static "admin token" header   [VULN #12]
 *  - client-supplied x-user-role   [VULN #13] privilege escalation
 *  - config.adminBypass gadget     [VULN #57] prototype pollution flips this open
 * Real admin UI guards live client-side only (frontend /admin).
 */
const express = require("express");
const { exec } = require("child_process");

module.exports = (container) => {
  const config = container.resolve("config");
  const db = container.resolve("db");
  const logBuffer = container.resolve("logBuffer");
  const r = express.Router();

  function adminGate(req, res, next) {
    // [VULN #57] gadget: prototype pollution sets this globally to true
    if (config.adminBypass === true) return next();
    const token = req.get("x-admin-token"); // [VULN #12] static shared token
    const role = req.get("x-user-role"); // [VULN #13] trust client-declared role
    if (token === config.adminToken || role === "admin") return next();
    return res.status(403).json({
      error: "forbidden",
      hint: "accepted: x-admin-token (static) OR x-user-role: admin (#12/#13); try __proto__ pollution (#57)",
    });
  }

  r.get("/api/admin/stats", adminGate, async (req, res, next) => {
    try {
      const users = await db.query("SELECT COUNT(*)::int AS n FROM users");
      const orders = await db.query("SELECT COUNT(*)::int AS n, COALESCE(SUM(total),0) AS sum FROM orders");
      res.json({ users: users.rows[0].n, orders: orders.rows[0], gate: adminGate.name });
    } catch (e) {
      next(e);
    }
  });

  /* [VULN #4] OS command injection: cmd passed to a shell verbatim.
     payload: {"cmd": "id; cat /etc/passwd"} */
  r.post("/api/admin/exec", adminGate, (req, res) => {
    const cmd = String((req.body || {}).cmd || "");
    exec(cmd, { timeout: 5000 }, (err, stdout, stderr) => {
      res.json({ cmd, err: err && err.message, stdout, stderr });
    });
  });

  /* [VULN #36] raw log buffer - injectable via User-Agent CRLF */
  r.get("/api/admin/logs", adminGate, (req, res) => {
    res.type("text/plain").send(logBuffer.slice(-200).join("\n"));
  });

  /* admin-only debug info (still behind the weak gate) */
  r.get("/api/admin/settings", adminGate, (req, res) => {
    res.json({
      adminBypass: config.adminBypass,
      adminToken: config.adminToken, // [VULN #43]
      env: { NODE_ENV: process.env.NODE_ENV, REGION: process.env.RENDER ? "render" : "unknown" },
    });
  });

  return r;
};
