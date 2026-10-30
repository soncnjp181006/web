-- PCForge schema (raw SQL, intentionally weak practices)
CREATE TABLE IF NOT EXISTS users (
  id            TEXT PRIMARY KEY,
  email         TEXT UNIQUE,
  password_hash TEXT,                -- [VULN #44] MD5, not bcrypt
  role          TEXT DEFAULT 'user', -- [VULN #51] mass-assignable
  is_admin      BOOLEAN DEFAULT FALSE,
  balance       NUMERIC DEFAULT 100, -- ví / loyalty
  full_name     TEXT,
  phone         TEXT,
  address       TEXT,
  theme_css     TEXT,                -- [VULN #13] custom CSS sink
  bio_html      TEXT,                -- [VULN #12] bio HTML sink
  cc_number     TEXT,                -- [VULN #44] plaintext card numbers
  api_key       TEXT,                -- [VULN #44] plaintext API keys
  signature     TEXT,                -- [VULN #31] CSTI template sink
  created_at    TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS products (
  id            SERIAL PRIMARY KEY,
  name          TEXT,
  category      TEXT,                -- pc | cpu | gpu | ram | mainboard | storage | psu | case | monitor | peripheral
  brand         TEXT,
  description   TEXT,
  specs         TEXT,                -- JSON string
  price         NUMERIC,
  internal_cost NUMERIC,             -- [VULN #44] leaked via search SELECT *
  stock         INT,
  featured      BOOLEAN DEFAULT FALSE,
  image_path    TEXT
);

CREATE TABLE IF NOT EXISTS orders (
  id         SERIAL PRIMARY KEY,
  user_id    TEXT,                   -- [VULN #11] IDOR target
  product_id INT,
  qty        INT,
  unit_price NUMERIC,                -- [VULN #54/#60] trusted from client
  total      NUMERIC,
  coupon     TEXT,
  status     TEXT DEFAULT 'paid',
  created_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS comments (   -- reviews
  id         SERIAL PRIMARY KEY,
  product_id INT,
  author     TEXT,
  body       TEXT,                   -- [VULN #3/#8] stored XSS sink
  created_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS coupons (
  code         TEXT PRIMARY KEY,
  discount_pct INT,
  max_uses     INT DEFAULT 100,
  used_count   INT DEFAULT 0         -- [VULN #53] check-then-act race target
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
  id        SERIAL PRIMARY KEY,
  user_id   TEXT,                    -- [VULN #49] BOLA via ?owner=
  product_id INT,
  note      TEXT                     -- [VULN #6] raw XML injection sink
);

CREATE TABLE IF NOT EXISTS cart_items (
  id         SERIAL PRIMARY KEY,
  user_id    TEXT,
  product_id INT,
  qty        INT,
  added_at   TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS tickets (
  id         SERIAL PRIMARY KEY,
  user_id    TEXT,                   -- [VULN #11/#49] IDOR/BOLA target
  subject    TEXT,
  status     TEXT DEFAULT 'open',
  created_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS ticket_messages (
  id         SERIAL PRIMARY KEY,
  ticket_id  INT,
  author     TEXT,
  body       TEXT,                   -- [VULN #3] stored XSS sink (support inbox)
  created_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS builds (
  id         SERIAL PRIMARY KEY,
  user_id    TEXT,                   -- [VULN #11/#49]
  name       TEXT,
  config     TEXT,                   -- JSON of chosen parts
  total      NUMERIC,                -- [VULN #60] client-supplied total
  created_at TIMESTAMPTZ DEFAULT now()
);
