/**
 * Orders: IDOR (#11), business logic (#54), race condition (#53),
 * BOLA/BFLA (#49/#50) on /api/v2, SSTI (#30).
 */
const express = require("express");
const fs = require("fs");
const path = require("path");
const _ = require("lodash");
const { currentUserId } = require("../auth/current-user");

module.exports = (container) => {
  const db = container.resolve("db");
  const r = express.Router();

  /* [VULN #54] client controls unit_price; negative qty flips the total.
     Also no ownership scoping issues here - the fun starts below. */
  r.post("/api/orders", async (req, res, next) => {
    try {
      const uid = await currentUserId(req, container);
      if (!uid) return res.status(401).json({ error: "login first" });
      const { productId, qty, price, coupon } = req.body || {};
      let unit = price;
      if (unit == null) {
        const pr = await db.query("SELECT price FROM products WHERE id = $1", [productId]);
        unit = pr.rows[0] ? pr.rows[0].price : 0;
      }
      const total = Number(unit) * Number(qty || 1); // negative qty -> negative total (#54)
      const { rows } = await db.query(
        "INSERT INTO orders (user_id, product_id, qty, unit_price, total, coupon) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *",
        [uid, productId, qty || 1, unit, total, coupon || null]
      );
      res.json({ order: rows[0] });
    } catch (e) {
      next(e);
    }
  });

  r.get("/api/orders", async (req, res, next) => {
    try {
      const uid = await currentUserId(req, container);
      if (!uid) return res.status(401).json({ error: "login first" });
      const { rows } = await db.query("SELECT * FROM orders WHERE user_id = $1 ORDER BY id DESC", [uid]);
      res.json({ orders: rows });
    } catch (e) {
      next(e);
    }
  });

  /* [VULN #9] CSRF: state-changing action via GET, cookie session, SameSite=None,
     no CSRF token. Demo page: /csrf-demo.html */
  r.get("/api/orders/transfer", async (req, res, next) => {
    try {
      const uid = await currentUserId(req, container);
      if (!uid) return res.status(401).json({ error: "login first" });
      const to = String(req.query.to || "");
      const amount = Number(req.query.amount || 0); // negative amount = self-topup (#54)
      const { rows: target } = await db.query("SELECT id, email, balance FROM users WHERE email = $1 OR id = $1", [to]);
      if (!target.length) return res.status(404).json({ error: "recipient not found" });
      await db.query("UPDATE users SET balance = balance - $1 WHERE id = $2", [amount, uid]);
      await db.query("UPDATE users SET balance = balance + $1 WHERE id = $2", [amount, target[0].id]);
      const { rows: me } = await db.query("SELECT id, email, balance FROM users WHERE id = $1", [uid]);
      res.json({ ok: true, transferred: amount, to: target[0], me: me[0] });
    } catch (e) {
      next(e);
    }
  });

  /* [VULN #30] SSTI: the "template" is compiled & executed with lodash.
     payload: ?tpl=<%= require("child_process").execSync("id").toString() %> */
  r.get("/api/orders/export", async (req, res, next) => {
    try {
      const uid = await currentUserId(req, container);
      const user = uid ? (await db.query("SELECT id, email, role FROM users WHERE id = $1", [uid])).rows[0] : { email: "guest" };
      const tpl = String(req.query.tpl || "Order summary for <%= user.email %>");
      const compiled = _.template(tpl, {
        imports: { require, process, Buffer, global }, // deliberately exposed
      });
      const out = compiled({ user });
      res.type("text/plain").send(out);
    } catch (e) {
      next(e);
    }
  });

  /* [VULN #22] invoice "download" - file param joins the invoice dir unsanitized.
     payload: ?file=../../../../etc/passwd */
  r.get("/api/orders/:id/invoice", (req, res) => {
    const file = String(req.query.file || "invoice.pdf");
    const base = path.join(__dirname, "..", "views", "invoices");
    const p = path.join(base, file);
    fs.readFile(p, (err, data) => {
      if (err) {
        return res.status(404).json({ error: err.message, resolvedPath: p, hint: "traversal (#22): ../../../../etc/passwd" });
      }
      res.setHeader("Content-Type", "application/pdf");
      res.send(data);
    });
  });

  /* RMA / warranty claim -> opens a support ticket (business flow) */
  r.post("/api/orders/:id/rma", async (req, res, next) => {
    try {
      const uid = await currentUserId(req, container);
      if (!uid) return res.status(401).json({ error: "login first" });
      const reason = String((req.body || {}).reason || "");
      const { rows } = await db.query(
        "INSERT INTO tickets (user_id, subject) VALUES ($1,$2) RETURNING *",
        [uid, `[RMA] Đơn #${req.params.id}: ${reason.slice(0, 80)}`]
      );
      await db.query("INSERT INTO ticket_messages (ticket_id, author, body) VALUES ($1,$2,$3)", [
        rows[0].id,
        uid,
        `Yêu cầu bảo hành/RMA cho đơn #${req.params.id}. Lý do: ${reason}`,
      ]);
      res.json({ ticket: rows[0] });
    } catch (e) {
      next(e);
    }
  });

  /* [VULN #11] IDOR: no ownership check - any numeric id returns anyone's order.
     Frontend "helpfully" exposes sequential ids. */
  r.get("/api/orders/:id", async (req, res, next) => {
    try {
      const { rows } = await db.query("SELECT * FROM orders WHERE id = $1", [req.params.id]);
      if (!rows.length) return res.status(404).json({ error: "not found" });
      res.json({ order: rows[0] });
    } catch (e) {
      next(e);
    }
  });

  /* [VULN #53] Race condition: classic check-then-act with an artificial 150ms gap.
     Fire 10 parallel requests and every one of them passes the check. */
  r.post("/api/coupon/redeem", async (req, res, next) => {
    try {
      const uid = await currentUserId(req, container);
      if (!uid) return res.status(401).json({ error: "login first" });
      const code = String((req.body || {}).code || "");
      const { rows } = await db.query(
        "SELECT code, discount_pct, used_count, max_uses FROM coupons WHERE code = $1 AND used_count < max_uses",
        [code]
      );
      if (!rows.length) return res.status(400).json({ error: "coupon invalid or exhausted" });
      await new Promise((r2) => setTimeout(r2, 150)); // widen the race window
      await db.query("UPDATE coupons SET used_count = used_count + 1 WHERE code = $1", [code]);
      // no per-user redemption record -> same user can redeem again (#54 stacking)
      res.json({ ok: true, coupon: rows[0], note: "check-then-act without locking (#53); no per-user limit (#54)" });
    } catch (e) {
      next(e);
    }
  });

  /* [VULN #49] BOLA: list "any owner's" coupons */
  r.get("/api/coupons/list", async (req, res, next) => {
    try {
      const owner = String(req.query.owner || "");
      const { rows } = await db.query(
        `SELECT o.user_id, o.coupon, count(*) AS uses FROM orders o WHERE o.coupon IS NOT NULL ${owner ? "AND o.user_id = '" + owner + "'" : ""} GROUP BY o.user_id, o.coupon`
      ); // + bonus SQLi via owner (#1)
      res.json({ coupons: rows });
    } catch (e) {
      next(e);
    }
  });

  /* ------------------------- /api/v2 - even fewer checks ------------------------- */

  /* [VULN #49] BOLA by uuid */
  r.get("/api/v2/orders/:uuid", async (req, res, next) => {
    try {
      const { rows } = await db.query("SELECT * FROM orders WHERE id = $1 OR user_id = $1", [req.params.uuid]);
      res.json({ orders: rows });
    } catch (e) {
      next(e);
    }
  });

  /* [VULN #50] BFLA: destructive admin function with zero authorization */
  r.post("/api/v2/admin/delete-user", async (req, res, next) => {
    try {
      const id = (req.body || {}).id;
      const { rows } = await db.query("DELETE FROM users WHERE id = $1 RETURNING id, email", [id]);
      res.json({ deleted: rows, note: "no auth check at all (#50)" });
    } catch (e) {
      next(e);
    }
  });

  /* [VULN #50][VULN #44] full user dump, unauthenticated */
  r.get("/api/v2/users", async (req, res, next) => {
    try {
      const { rows } = await db.query("SELECT * FROM users ORDER BY created_at DESC");
      res.json({ users: rows });
    } catch (e) {
      next(e);
    }
  });

  return r;
};
