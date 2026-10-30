/**
 * Wishlist: BOLA (#49), SQLi via owner (#1), XML injection export (#6).
 */
const express = require("express");
const { currentUserId } = require("../auth/current-user");

module.exports = (container) => {
  const db = container.resolve("db");
  const r = express.Router();

  /* [VULN #49] owner param optional -> view anyone's wishlist; concat SQL (#1) */
  r.get("/api/wishlist", async (req, res, next) => {
    try {
      let owner = req.query.owner;
      if (!owner) owner = await currentUserId(req, container);
      if (!owner) return res.status(401).json({ error: "login first or pass ?owner=" });
      const { rows } = await db.query(
        `SELECT w.id, w.note, p.name, p.price, w.user_id
         FROM wishlists w LEFT JOIN products p ON p.id = w.product_id
         WHERE w.user_id = '${owner}' ORDER BY w.id`
      );
      res.json({ owner, items: rows });
    } catch (e) {
      next(e);
    }
  });

  r.post("/api/wishlist", async (req, res, next) => {
    try {
      const uid = await currentUserId(req, container);
      if (!uid) return res.status(401).json({ error: "login first" });
      const { productId, note } = req.body || {};
      // note goes straight into XML export (#6)
      const { rows } = await db.query(
        "INSERT INTO wishlists (user_id, product_id, note) VALUES ($1,$2,$3) RETURNING *",
        [uid, productId, note || ""]
      );
      res.json({ item: rows[0] });
    } catch (e) {
      next(e);
    }
  });

  r.delete("/api/wishlist/:id", async (req, res, next) => {
    try {
      const uid = await currentUserId(req, container);
      if (!uid) return res.status(401).json({ error: "login first" });
      await db.query("DELETE FROM wishlists WHERE id = $1 AND user_id = $2", [req.params.id, uid]);
      res.json({ ok: true });
    } catch (e) {
      next(e);
    }
  });

  /* [VULN #6] wishlist notes concatenated raw into the XML document */
  r.get("/api/wishlist/export/xml", async (req, res, next) => {
    try {
      const { rows } = await db.query(
        `SELECT w.id, w.note, p.name AS product, p.price FROM wishlists w
         LEFT JOIN products p ON p.id = w.product_id ORDER BY w.id`
      );
      let xml = `<?xml version="1.0"?>\n<wishlists>\n`;
      for (const w of rows) {
        xml += `  <item id="${w.id}"><note>${w.note}</note><product>${w.product}</product><price>${w.price}</price></item>\n`;
      }
      xml += `</wishlists>`;
      res.type("application/xml").send(xml);
    } catch (e) {
      next(e);
    }
  });

  return r;
};
