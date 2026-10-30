/**
 * [VULN #62] OAuth misconfiguration - mini provider + client, all wrong:
 *   - redirect_uri NOT validated (code theft via open redirector)
 *   - no state parameter validation (login CSRF)
 *   - implicit flow supported (response_type=token -> token in URL fragment)
 *   - token endpoint has no client authentication
 *   - code is single-use-less & long-lived
 */
const express = require("express");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");

const clients = new Map([["vuln-client", { name: "VulnShop SPA", redirectUris: [] /* empty = accept anything */ }]]);
const codes = new Map(); // code -> { user, issuedAt } (never cleaned up)
const tokens = new Map();

module.exports = (container) => {
  const config = container.resolve("config");
  const db = container.resolve("db");
  const r = express.Router();

  /* authorization endpoint - redirect_uri accepted verbatim */
  r.get("/api/oauth/authorize", (req, res) => {
    const { client_id, redirect_uri, response_type, state } = req.query;
    if (!clients.has(String(client_id))) return res.status(400).json({ error: "unknown client_id" });
    const code = crypto.randomBytes(8).toString("hex");
    codes.set(code, { user: "legacy-victim-2", issuedAt: Date.now() }); // always "the victim" is pre-authed (SOP-level vuln too)
    const sep = String(redirect_uri).includes("?") ? "&" : "?";
    let target = `${redirect_uri}${sep}code=${code}`;
    if (state) target += `&state=${state}`; // state echoed but never checked later
    if (response_type === "token") {
      const at = jwt.sign({ sub: "legacy-victim-2" }, config.jwtSecret); // implicit flow: token in fragment
      target = `${redirect_uri}${sep}access_token=${at}&token_type=bearer`;
    }
    res.redirect(target);
  });

  /* token endpoint - no client_secret required */
  r.post("/api/oauth/token", (req, res) => {
    const { code, client_id } = { ...(req.body || {}), ...(req.query || {}) };
    const entry = codes.get(String(code));
    if (!entry) return res.status(400).json({ error: "invalid code" });
    const at = jwt.sign({ sub: entry.user }, config.jwtSecret, { expiresIn: "30d" });
    tokens.set(at, entry.user);
    codes.delete(String(code));
    res.json({ access_token: at, token_type: "bearer", expires_in: 60 * 60 * 24 * 30, client: client_id || null });
  });

  /* vulnerable OAuth client callback: no state check, auto-login */
  r.get("/api/oauth/client/callback", async (req, res, next) => {
    try {
      const { code, access_token } = req.query;
      let token = access_token;
      if (code) {
        // exchange against ourselves (fetch) - no state validated anywhere
        const resp = await fetch(`${req.protocol}://${req.headers.host}/api/oauth/token`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ code, client_id: "vuln-client" }),
        });
        const data = await resp.json();
        token = data.access_token;
      }
      if (!token) return res.status(400).send("no token/code");
      const claims = jwt.decode(token); // no verification either
      const { rows } = await db.query("SELECT id, email, role FROM users WHERE id = $1", [claims.sub]);
      const crypto2 = require("crypto");
      const sessionToken = crypto2.randomBytes(6).toString("hex");
      const dbq = await db.query("INSERT INTO legacy_sessions (token, user_id) VALUES ($1, $2) ON CONFLICT (token) DO UPDATE SET user_id=$2", [sessionToken, claims.sub]);
      res.setHeader("Set-Cookie", `session=${sessionToken}; Path=/; ${req.secure || req.headers["x-forwarded-proto"] === "https" ? "SameSite=None; Secure" : "SameSite=Lax"}`);
      res.json({ loggedInAs: rows[0] || claims, sessionToken, note: "no state validation (#62) - CSRF-login possible" });
    } catch (e) {
      next(e);
    }
  });

  return r;
};
