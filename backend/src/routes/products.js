/**
 * Products: raw-SQL search (#1), NoSQL-style filter (#2), XML injection (#6),
 * XPath injection (#7), comments (stored XSS #8).
 */
const express = require("express");

module.exports = (container) => {
  const db = container.resolve("db");
  const nosql = container.resolve("vulnNosql");
  const xpath = container.resolve("vulnXpath");
  const r = express.Router();

  /* category filter: [VULN #1] raw concat */
  r.get("/api/products", async (req, res, next) => {
    try {
      const cat = String(req.query.category || "");
      const brand = String(req.query.brand || "");
      const sql = `SELECT * FROM products ${cat ? "WHERE category = '" + cat + "'" : ""} ${brand ? (cat ? "AND" : "WHERE") + " brand = '" + brand + "'" : ""} ORDER BY id`;
      const { rows } = await db.query(sql);
      res.json({ products: rows, sql: cat || brand ? sql : undefined });
    } catch (e) {
      next(e);
    }
  });

  /* flash deals: featured + low stock */
  r.get("/api/products/deals", async (req, res, next) => {
    try {
      const { rows } = await db.query(
        "SELECT * FROM products WHERE featured = TRUE ORDER BY price DESC LIMIT 12"
      );
      res.json({ deals: rows });
    } catch (e) {
      next(e);
    }
  });

  /* [VULN #1] SQL injection - q/category/sortcol concatenated straight into the query.
     payload: %' OR 1=1--
     union:   %' UNION SELECT 1, email, password_hash, 'x', 'user', 0, 0, 0, FALSE, 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x' FROM users-- */
  r.get("/api/products/search", async (req, res, next) => {
    try {
      const q = String(req.query.q || "");
      const category = String(req.query.category || "");
      const sortcol = String(req.query.sortcol || "id");
      const sql = `SELECT id, name, category, brand, description, price, internal_cost, stock FROM products WHERE (name ILIKE '%${q}%' OR description ILIKE '%${q}%') ${category ? `AND category = '${category}'` : ""} ORDER BY ${sortcol}`;
      const { rows } = await db.query(sql);
      res.json({ q, category, sql, rows }); // echoes SQL too [VULN #43]
    } catch (e) {
      next(e);
    }
  });

  /* [VULN #1] ORDER BY injection: /api/products/sort?col=price;SELECT pg_sleep(5)-- */
  r.get("/api/products/sort", async (req, res, next) => {
    try {
      const col = String(req.query.col || "id");
      const dir = String(req.query.dir || "ASC");
      const sql = `SELECT id, name, price FROM products ORDER BY ${col} ${dir}`;
      const { rows } = await db.query(sql);
      res.json({ sql, rows });
    } catch (e) {
      next(e);
    }
  });

  /* [VULN #2] NoSQL-style injection. body: {"price": {"$ne": null}} or {"$where": "this.price < 10"} */
  r.post("/api/products/filter", async (req, res, next) => {
    try {
      const { rows } = await db.query("SELECT * FROM products");
      const results = nosql.find(rows, req.body || {});
      res.json({ filter: req.body, results });
    } catch (e) {
      next(e);
    }
  });

  /* [VULN #6] XML injection: wishlist names are concatenated into the XML document raw */
  r.post("/api/products/wishlist", async (req, res) => {
    const name = String((req.body || {}).name || "");
    await db.query("INSERT INTO wishlists (name) VALUES ($1)", [name]);
    res.json({ ok: true });
  });
  r.get("/api/products/export/xml", async (req, res, next) => {
    try {
      const { rows } = await db.query("SELECT id, name, price FROM products");
      const wl = await db.query("SELECT name FROM wishlists ORDER BY id");
      let xml = `<?xml version="1.0"?>\n<catalog>\n`;
      for (const p of rows) xml += `  <product id="${p.id}"><name>${p.name}</name><price>${p.price}</price></product>\n`;
      for (const w of wl.rows) xml += `  <wishlist><name>${w.name}</name></wishlist>\n`; // raw injection sink
      xml += `</catalog>`;
      res.type("application/xml").send(xml);
    } catch (e) {
      next(e);
    }
  });

  /* [VULN #7] XPath injection: /api/products/xpath?q=x" || "1"=="1 */
  r.get("/api/products/xpath", (req, res) => {
    const q = String(req.query.q || "");
    try {
      const out = xpath.select(`//user[name="${q}"]`);
      res.json(out);
    } catch (e) {
      res.status(400).json({ error: e.message }); // parser error leaks internals
    }
  });

  /* comments - [VULN #8] stored XSS sink (frontend renders raw HTML) */
  r.get("/api/products/:id/comments", async (req, res, next) => {
    try {
      const { rows } = await db.query("SELECT * FROM comments WHERE product_id = $1 ORDER BY id", [req.params.id]);
      res.json({ comments: rows });
    } catch (e) {
      next(e);
    }
  });
  r.post("/api/products/:id/comments", async (req, res, next) => {
    try {
      const { author, body } = req.body || {};
      const { rows } = await db.query(
        "INSERT INTO comments (product_id, author, body) VALUES ($1, $2, $3) RETURNING *",
        [req.params.id, author || "anon", body || ""]
      );
      res.json({ comment: rows[0] });
    } catch (e) {
      next(e);
    }
  });

  /* keep before /api/products/:id */
  r.get("/api/products/:id", async (req, res, next) => {
    try {
      const { rows } = await db.query("SELECT * FROM products WHERE id = $1", [req.params.id]);
      if (!rows.length) return res.status(404).json({ error: "not found" });
      res.json({ product: rows[0] });
    } catch (e) {
      next(e);
    }
  });

  return r;
};
