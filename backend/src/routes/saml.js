/**
 * [VULN #63] SAML "implementation" that consumes assertions WITHOUT verifying
 * signatures - craft any base64 SAMLResponse and log in as anyone
 * (signature wrapping / unsigned assertion attacks).
 */
const express = require("express");
const crypto = require("crypto");

module.exports = (container) => {
  const vulnXml = container.resolve("vulnXml");
  const db = container.resolve("db");
  const r = express.Router();

  const SAMPLE_ASSERTION = Buffer.from(
    `<?xml version="1.0"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
  <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
    <saml:Subject><saml:NameID>admin@vulnshop.local</saml:NameID></saml:Subject>
  </saml:Assertion>
</samlp:Response>`,
    "utf8"
  ).toString("base64");

  r.get("/api/saml/sample", (req, res) => res.json({ SAMLResponse: SAMPLE_ASSERTION }));

  r.post("/api/saml/consume", async (req, res, next) => {
    try {
      const raw = String((req.body || {}).SAMLResponse || "");
      const xml = Buffer.from(raw, "base64").toString("utf8");
      // signature? ignored entirely. Expiry? ignored. Audience? ignored.
      const m = xml.match(/<(?:[a-zA-Z0-9]+:)?NameID[^>]*>([^<]+)</);
      if (!m) return res.status(400).json({ error: "no NameID found", xml: xml.slice(0, 500) });
      const email = m[1].trim();
      let { rows } = await db.query("SELECT id, email, role FROM users WHERE email = $1", [email]);
      if (!rows.length) {
        // auto-creates unknown identities too
        const id = crypto.randomUUID();
        await db.query("INSERT INTO users (id, email, role) VALUES ($1, $2, 'user')", [id, email]);
        rows = [{ id, email, role: "user" }];
      }
      const sessionToken = crypto.randomBytes(6).toString("hex");
      await db.query(
        "INSERT INTO legacy_sessions (token, user_id) VALUES ($1, $2) ON CONFLICT (token) DO UPDATE SET user_id = $2",
        [sessionToken, rows[0].id]
      );
      res.setHeader("Set-Cookie", `session=${sessionToken}; Path=/; SameSite=None`);
      res.json({ authenticated: rows[0], sessionToken, signatureVerified: false, note: "assertion accepted WITHOUT signature check (#63)" });
    } catch (e) {
      next(e);
    }
  });

  return r;
};
