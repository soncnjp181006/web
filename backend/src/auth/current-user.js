/**
 * Resolve the acting user id from either auth system:
 *  - Supertokens session (cookie-based, /auth)
 *  - legacy session cookie (token in `session` cookie or ?session= / Authorization)
 */
const Session = require("supertokens-node/recipe/session");
const { parseCookie } = require("../middleware/vuln");

async function currentUserId(req, container) {
  // 1) supertokens
  try {
    const s = await Session.getSession(req, container.res || undefined, { sessionRequired: false });
    if (s) return s.getUserId();
  } catch {}
  // 2) legacy session cookie [VULN #16] also accepts ?session= (token in URL)
  const db = container.resolve("db");
  const token = parseCookie(req).session || req.query.session || String(req.headers.authorization || "").replace(/^Bearer\s+/i, "");
  if (token) {
    try {
      const { rows } = await db.query("SELECT user_id FROM legacy_sessions WHERE token = $1", [token]);
      if (rows.length) return rows[0].user_id;
    } catch {}
  }
  return null;
}

module.exports = { currentUserId };
