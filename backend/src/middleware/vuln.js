/**
 * Weak/global middleware pieces, each implementing (or enabling) a vulnerability.
 */
const VULN = "[vuln]";

/* [VULN #40] CORS misconfiguration: reflect any origin + credentials */
function vulnerableCors() {
  return (req, res, next) => {
    const origin = req.headers.origin;
    if (origin) {
      res.setHeader("Access-Control-Allow-Origin", origin);
      res.setHeader("Vary", "Origin");
      res.setHeader("Access-Control-Allow-Credentials", "true");
      res.setHeader("Access-Control-Allow-Headers", "*");
      res.setHeader("Access-Control-Allow-Methods", "*");
    }
    if (req.method === "OPTIONS") {
      res.setHeader("Access-Control-Max-Age", "86400");
      return res.status(204).end();
    }
    next();
  };
}

/* [VULN #36] log injection: user input written to log lines unescaped */
function vulnerableLogger() {
  return (req, res, next) => {
    const lines = [];
    if (req.app && req.app.get) {
      // logBuffer lives in the DI container; reach for it lazily
    }
    const line = `${new Date().toISOString()} ${req.method} ${req.url} UA="${req.headers["user-agent"] || "-"}"`;
    console.log(line); // attacker-controlled CRLF -> forged entries
    try {
      const container = require("../di/container");
      if (container.has("logBuffer")) {
        const buf = container.resolve("logBuffer");
        buf.push(line);
        if (buf.length > 500) buf.shift();
      }
    } catch {}
    next();
  };
}

/* [VULN #12] trust X-Original-URL / X-Rewrite-URL -> bypass any gateway path blocklist */
function originalUrlOverride() {
  return (req, res, next) => {
    const override = req.headers["x-original-url"] || req.headers["x-rewrite-url"];
    if (override) {
      console.log(`${VULN} URL override via header -> ${override}`);
      req.url = String(override);
    }
    next();
  };
}

/* [VULN #52] rate limiter keyed on SPOOFABLE X-Forwarded-For (bypass by rotating the header).
   Real client IP would be: req.socket.remoteAddress (behind proxy, use app.set('trust proxy') carefully). */
function rateLimiter({ max = 5, windowMs = 60_000 } = {}) {
  return async (req, res, next) => {
    try {
      const container = require("../di/container");
      const cache = container.resolve("cache");
      const ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress || "unknown"; // spoofable key
      const key = `rl:${req.path}:${ip}`;
      const n = await cache.incrWindow(key, windowMs);
      res.setHeader("X-RateLimit-Limit", String(max));
      res.setHeader("X-RateLimit-Remaining", String(Math.max(0, max - n)));
      if (n > max) {
        return res.status(429).json({ error: "Too many requests", key, hint: "Rotate X-Forwarded-For to bypass (#52)" });
      }
      next();
    } catch (e) {
      next(e);
    }
  };
}

function parseCookie(req) {
  const out = {};
  String(req.headers.cookie || "")
    .split(";")
    .forEach((p) => {
      const i = p.indexOf("=");
      if (i > 0) out[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim());
    });
  return out;
}

module.exports = { vulnerableCors, vulnerableLogger, originalUrlOverride, rateLimiter, parseCookie };
