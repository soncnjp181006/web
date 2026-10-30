/**
 * Raw PostgreSQL access layer (no ORM on purpose - raw SQL, as requested).
 * SQL built with string concatenation in routes = [VULN #1] SQL injection.
 */
const { Pool } = require("pg");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

let pool = null;

function getPool() {
  if (pool) return pool;
  const cs = process.env.DATABASE_URL || "";
  pool = new Pool({
    connectionString: cs || undefined,
    // Render external hosts require SSL; internal connections do not
    ssl: cs.includes("render.com") ? { rejectUnauthorized: false } : false,
    max: 5,
  });
  return pool;
}

async function query(sql, params) {
  return getPool().query(sql, params);
}

async function ensureSchema() {
  const sql = fs.readFileSync(path.join(__dirname, "schema.sql"), "utf8");
  await query(sql);

  // seed only when empty
  const { rows } = await query("SELECT COUNT(*)::int AS n FROM users");
  if (rows[0].n > 0) return;

  const md5 = (s) => crypto.createHash("md5").update(String(s)).digest("hex"); // [VULN #44] MD5 passwords
  await query(
    `INSERT INTO users (id, email, password_hash, role, is_admin, balance, cc_number, api_key, signature) VALUES
     ('legacy-admin-1', 'admin@vulnshop.local', $1, 'admin', TRUE, 9999, '4111-1111-1111-1111', 'sk_live_ADMINKEY123', 'i am admin'),
     ('legacy-victim-2', 'victim@vulnshop.local', $2, 'user', FALSE, 100, '4242-4242-4242-4242', 'sk_live_VICTIMKEY456', '<img src=x onerror=alert(1)>')`,
    [md5("admin123"), md5("victim123")] // [VULN #46] weak passwords accepted
  );

  await query(
    `INSERT INTO products (name, description, price, internal_cost, stock, image_path) VALUES
     ('Rubber Duck', 'Debugging companion', 9.99, 0.5, 100, '/img/duck.png'),
     ('Hacker Hoodie', 'Grey, one size', 49.00, 5, 40, '/img/hoodie.png'),
     ('Cyber Coffee', '1kg dark roast', 15.50, 3, 80, '/img/coffee.png'),
     ('Keylogger USB', 'Novelty demo stick', 25.00, 2, 15, '/img/usb.png'),
     ('Faraday Bag', 'Phone-sized', 29.90, 4, 30, '/img/bag.png'),
     ('Lockpick Set', 'For your own locks only', 39.00, 6, 25, '/img/picks.png')`
  );

  await query(
    `INSERT INTO comments (product_id, author, body) VALUES
     (1, 'admin', 'Great duck! 10/10'),
     (1, 'anon', '<img src=x onerror=alert("stored-xss")>'), -- [VULN #8] pre-seeded stored XSS
     (2, 'anon', '<script>alert("xss")</script>'),           -- [VULN #8]
     (3, 'anon', '<%= 7*7 %> is my fav number')              -- [VULN #31] client-side template injection bait
     `
  );

  await query(
    `INSERT INTO coupons (code, discount_pct, max_uses, used_count) VALUES
     ('WELCOME10', 10, 100, 0),
     ('VULN50', 50, 1, 0)`
  );
}

module.exports = (container) => ({
  query,
  ensureSchema,
  getPool,
  // expose raw pool too (services may need transactions)
  pool: getPool(),
});
