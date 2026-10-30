/**
 * Cart & checkout flow.
 * Vulnerabilities: business logic (#54), client-trusted prices (#60),
 * race-condition coupon (#53), plaintext card storage (#44), IDOR (#11).
 */
const express = require("express");
const { currentUserId } = require("../auth/current-user");

module.exports = (container) => {
  const db = container.resolve("db");
  const r = express.Router();

  const requireUser = async (req, res, next) => {
    try {
      const uid = await currentUserId(req, container);
      if (!uid) return res.status(401).json({ error: "login first" });
      req.uid = uid;
      next();
    } catch (e) {
      next(e);
    }
  };

  r.get("/api/cart", requireUser, async (req, res, next) => {
    try {
      const { rows } = await db.query(
        `SELECT c.id, c.qty, p.id AS product_id, p.name, p.price, p.stock
         FROM cart_items c JOIN products p ON p.id = c.product_id
         WHERE c.user_id = $1 ORDER BY c.id`,
        [req.uid]
      );
      const total = rows.reduce((s, x) => s + Number(x.price) * x.qty, 0);
      res.json({ items: rows, serverTotal: total });
    } catch (e) {
      next(e);
    }
  });

  r.post("/api/cart", requireUser, async (req, res, next) => {
    try {
      const { productId, qty } = req.body || {};
      await db.query("INSERT INTO cart_items (user_id, product_id, qty) VALUES ($1,$2,$3)", [
        req.uid,
        productId,
        qty || 1, // negative qty accepted (#54)
      ]);
      res.json({ ok: true });
    } catch (e) {
      next(e);
    }
  });

  /* no ownership check -> edit other users' cart rows (#11) */
  r.put("/api/cart/:id", async (req, res, next) => {
    try {
      await db.query("UPDATE cart_items SET qty = $1 WHERE id = $2", [req.body.qty, req.params.id]);
      res.json({ ok: true, note: "no ownership check (#11)" });
    } catch (e) {
      next(e);
    }
  });

  r.delete("/api/cart/:id", requireUser, async (req, res, next) => {
    try {
      await db.query("DELETE FROM cart_items WHERE id = $1 AND user_id = $2", [req.params.id, req.uid]);
      res.json({ ok: true });
    } catch (e) {
      next(e);
    }
  });

  r.delete("/api/cart", requireUser, async (req, res, next) => {
    try {
      await db.query("DELETE FROM cart_items WHERE user_id = $1", [req.uid]);
      res.json({ ok: true });
    } catch (e) {
      next(e);
    }
  });

  /* [VULN #54][#60] checkout trusts client-supplied unit prices & totals;
     [VULN #53] coupon applied without per-user limit;
     [VULN #44] card number stored plaintext; negative qty flips totals. */
  r.post("/api/cart/checkout", requireUser, async (req, res, next) => {
    try {
      const { items, coupon, cc, address, phone, fullName } = req.body || {};
      if (!Array.isArray(items) || !items.length) {
        return res.status(400).json({ error: "items required" });
      }
      const ids = items.map((i) => i.productId);
      const { rows: prods } = await db.query("SELECT * FROM products WHERE id = ANY($1)", [ids]);
      const created = [];
      for (const it of items) {
        const p = prods.find((x) => x.id === Number(it.productId));
        // CLIENT price wins if provided (#54/#60); qty may be negative
        const unit = it.unitPrice != null ? Number(it.unitPrice) : p ? Number(p.price) : 0;
        const qty = Number(it.qty || 1);
        const total = unit * qty;
        const { rows } = await db.query(
          `INSERT INTO orders (user_id, product_id, qty, unit_price, total, coupon, status)
           VALUES ($1,$2,$3,$4,$5,$6,'paid') RETURNING *`,
          [req.uid, it.productId, qty, unit, total, coupon || null]
        );
        created.push(rows[0]);
      }
      // plaintext card saved on profile (#44)
      if (cc) await db.query("UPDATE users SET cc_number = $1 WHERE id = $2", [String(cc), req.uid]);
      if (address) await db.query("UPDATE users SET address = $1 WHERE id = $2", [String(address), req.uid]);
      if (phone) await db.query("UPDATE users SET phone = $1 WHERE id = $2", [String(phone), req.uid]);
      if (fullName) await db.query("UPDATE users SET full_name = $1 WHERE id = $2", [String(fullName), req.uid]);
      // clear cart
      await db.query("DELETE FROM cart_items WHERE user_id = $1", [req.uid]);
      res.json({
        ok: true,
        orders: created,
        note: "server trusts client unit prices (#54/#60); coupon not per-user limited (#53); cc stored plaintext (#44)",
      });
    } catch (e) {
      next(e);
    }
  });

  return r;
};
