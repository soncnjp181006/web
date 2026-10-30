-- VulnShop schema (raw SQL, intentionally weak practices)
CREATE TABLE IF NOT EXISTS users (
  id            TEXT PRIMARY KEY,
  email         TEXT UNIQUE,
  password_hash TEXT,                -- [VULN #44] MD5, not bcrypt
  role          TEXT DEFAULT 'user', -- [VULN #51] mass-assignable
  is_admin      BOOLEAN DEFAULT FALSE,
  balance       NUMERIC DEFAULT 100,
  cc_number     TEXT,                -- [VULN #44] plaintext card numbers
  api_key       TEXT,                -- [VULN #44] plaintext API keys
  signature     TEXT,
  created_at    TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS products (
  id            SERIAL PRIMARY KEY,
  name          TEXT,
  description   TEXT,
  price         NUMERIC,
  internal_cost NUMERIC,             -- [VULN #44] leaked via search SELECT *
  stock         INT,
  image_path    TEXT
);

CREATE TABLE IF NOT EXISTS orders (
  id         SERIAL PRIMARY KEY,
  user_id    TEXT,                   -- [VULN #11] IDOR target
  product_id INT,
  qty        INT,
  unit_price NUMERIC,
  total      NUMERIC,
  coupon     TEXT,
  status     TEXT DEFAULT 'paid',
  created_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS comments (
  id         SERIAL PRIMARY KEY,
  product_id INT,
  author     TEXT,
  body       TEXT,                   -- [VULN #8] stored XSS sink
  created_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS coupons (
  code        TEXT PRIMARY KEY,
  discount_pct INT,
  max_uses    INT DEFAULT 100,
  used_count  INT DEFAULT 0         -- [VULN #53] check-then-act race target
);

CREATE TABLE IF NOT EXISTS password_resets (
  token      TEXT PRIMARY KEY,       -- [VULN #66] predictable, never expires, reusable
  email      TEXT,
  created_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS legacy_sessions (
  token      TEXT PRIMARY KEY,       -- [VULN #17] client-supplied session ids accepted
  user_id    TEXT,
  created_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS uploads (
  id            SERIAL PRIMARY KEY,
  filename      TEXT,                -- [VULN #25/#26] original name preserved
  original_name TEXT,
  uploader      TEXT,
  created_at    TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS wishlists (
  id   SERIAL PRIMARY KEY,
  name TEXT                          -- [VULN #6] raw XML injection sink
);
