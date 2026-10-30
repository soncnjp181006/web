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
    ssl: cs.includes("render.com") ? { rejectUnauthorized: false } : false,
    max: 5,
  });
  return pool;
}

async function query(sql, params) {
  return getPool().query(sql, params);
}

const PC_CATALOG = [
  // ---- PC dựng sẵn ----
  ["VulnPC Titan - i9/4090/64GB", "pc", "VulnPC", "PC dựng sẵn đỉnh: i9-14900K, RTX 4090, 64GB DDR5, 2TB NVMe, 1000W Platinum", '{"cpu":"i9-14900K","gpu":"RTX 4090","ram":"64GB DDR5","socket":"LGA1700","watt":850}', 7499.0, 5200, 5, true, "/img/pc-titan.png"],
  ["VulnPC Gaming Mid - 7800X3D/4070S", "pc", "VulnPC", "Build gaming 1440p: Ryzen 7 7800X3D, RTX 4070 Super, 32GB DDR5, 1TB NVMe", '{"cpu":"7800X3D","gpu":"RTX 4070 Super","ram":"32GB DDR5","socket":"AM5","watt":650}', 2199.0, 1500, 12, true, "/img/pc-gaming.png"],
  ["VulnPC Office Basic", "pc", "VulnPC", "Máy văn phòng: Ryzen 5 5600G, 16GB DDR4, 512GB SSD, iGPU", '{"cpu":"5600G","gpu":"iGPU","ram":"16GB DDR4","socket":"AM4","watt":300}', 449.0, 320, 30, false, "/img/pc-office.png"],
  ["VulnPC Creator Pro", "pc", "VulnPC", "Workstation dựng phim: 7950X, RTX 4080, 128GB ECC, 4TB NVMe", '{"cpu":"7950X","gpu":"RTX 4080","ram":"128GB DDR5","socket":"AM5","watt":1000}', 4899.0, 3600, 3, true, "/img/pc-creator.png"],
  // ---- CPU ----
  ["CPU Intel Core i9-14900K", "cpu", "Intel", "24 nhân (8P+16E), 32 luồng, boost 6.0GHz, socket LGA1700", '{"socket":"LGA1700","cores":24,"tdp":253,"ddr":"DDR4/DDR5"}', 589.0, 430, 18, true, "/img/i9.png"],
  ["CPU AMD Ryzen 7 7800X3D", "cpu", "AMD", "8 nhân 16 luồng, 3D V-Cache 96MB - vua gaming, socket AM5", '{"socket":"AM5","cores":8,"tdp":120,"ddr":"DDR5"}', 399.0, 290, 25, true, "/img/7800x3d.png"],
  ["CPU AMD Ryzen 5 7600", "cpu", "AMD", "6 nhân 12 luồng, included cooler, socket AM5", '{"socket":"AM5","cores":6,"tdp":65,"ddr":"DDR5"}', 199.0, 140, 40, false, "/img/7600.png"],
  // ---- GPU ----
  ["VGA RTX 4090 Gaming OC 24GB", "gpu", "NVIDIA", "24GB GDDR6X, DLSS 3.5, 450W TDP - cần PSU tối thiểu 1000W", '{"vram":24,"tdp":450,"connector":"12VHPWR"}', 2199.0, 1750, 6, true, "/img/4090.png"],
  ["VGA RTX 4070 Super 12GB", "gpu", "NVIDIA", "12GB GDDR6X, 220W TDP, đẹp 1440p ray tracing", '{"vram":12,"tdp":220,"connector":"16-pin"}', 649.0, 500, 20, true, "/img/4070s.png"],
  ["VGA RX 7800 XT 16GB", "gpu", "AMD", "16GB GDDR6, 263W, RDNA3 - giá/tiền cực tốt", '{"vram":16,"tdp":263,"connector":"2x8-pin"}', 519.0, 400, 15, false, "/img/7800xt.png"],
  // ---- RAM ----
  ["RAM DDR5 32GB (2x16) 6000 CL30", "ram", "G.Skill", "Trident Z5 RGB, EXPO, cực hợp 7800X3D", '{"type":"DDR5","speed":6000,"cl":30,"capacity":32}', 129.0, 85, 50, true, "/img/ddr5.png"],
  ["RAM DDR4 16GB (2x8) 3600 CL18", "ram", "Corsair", "Vengeance LPX, hợp nền AM4/LGA1700 DDR4", '{"type":"DDR4","speed":3600,"cl":18,"capacity":16}', 49.0, 30, 80, false, "/img/ddr4.png"],
  // ---- Mainboard ----
  ["Main B650 Tomahawk DDR5 (AM5)", "mainboard", "MSI", "VRM 80A, PCIe 5.0 x16, 4x DDR5, WiFi 6E", '{"socket":"AM5","form":"ATX","ddr":"DDR5","pcie":"5.0"}', 219.0, 150, 22, true, "/img/b650.png"],
  ["Main Z790 Aorus Elite DDR4 (LGA1700)", "mainboard", "Gigabyte", "Z790 dùng DDR4, tiết kiệm chi phí RAM", '{"socket":"LGA1700","form":"ATX","ddr":"DDR4","pcie":"5.0"}', 249.0, 175, 14, false, "/img/z790.png"],
  // ---- Storage ----
  ["SSD NVMe 2TB Gen4 7400MB/s", "storage", "Samsung", "990 PRO 2TB, heatsink, hợp PS5", '{"interface":"PCIe4","capacity":"2TB","read":7400}', 169.0, 110, 35, true, "/img/990pro.png"],
  ["SSD SATA 1TB 560MB/s", "storage", "Crucial", "MX500 1TB 2.5 inch", '{"interface":"SATA","capacity":"1TB","read":560}', 64.0, 40, 60, false, "/img/mx500.png"],
  ["HDD 4TB 7200rpm", "storage", "Seagate", "IronWolf 4TB NAS", '{"interface":"SATA","capacity":"4TB","rpm":7200}', 99.0, 65, 25, false, "/img/hdd.png"],
  // ---- PSU ----
  ["PSU 850W 80+ Gold Full Modular", "psu", "Corsair", "RM850x - đủ cho RTX 4070S/7800XT", '{"watt":850,"cert":"80+ Gold","modular":true}', 149.0, 95, 28, true, "/img/rm850.png"],
  ["PSU 1000W 80+ Platinum ATX 3.0", "psu", "Seasonic", "Prime TX-1000, có 12VHPWR cho RTX 4090", '{"watt":1000,"cert":"80+ Platinum","modular":true}', 259.0, 180, 10, true, "/img/tx1000.png"],
  // ---- Case ----
  ["Case Mid Tower ARGB lưới sĩ khí", "case", "Lian Li", "Lancool 216, 2 fan 160mm, hỗ trợ GPU 392mm", '{"form":"ATX","gpuMax":"392mm"}', 99.0, 60, 45, false, "/img/lancool.png"],
  ["Case Mesh Mini ITX", "case", "Cooler Master", "NR200P, nhỏ gọn cho build ITX", '{"form":"ITX","gpuMax":"330mm"}', 89.0, 55, 18, false, "/img/nr200.png"],
  // ---- Monitor ----
  ["Monitor 27\" 2K 165Hz IPS", "monitor", "LG", "27GP850-B, Nano IPS 1ms, hợp gaming 1440p", '{"size":27,"panel":"IPS","hz":165,"res":"2560x1440"}', 379.0, 260, 16, true, "/img/27gp850.png"],
  ["Monitor 24\" FHD 240Hz Fast IPS", "monitor", "ASUS", "TUF VG259QM - esports 240Hz", '{"size":24,"panel":"Fast IPS","hz":240,"res":"1920x1080"}', 249.0, 170, 20, false, "/img/vg259.png"],
  // ---- Peripheral ----
  ["Bàn phím cơ Hot-swap 75%", "peripheral", "Keychron", "K2 V2, switch Gateron, RGB, wireless", '{"layout":"75%","hotswap":true,"wireless":true}', 99.0, 55, 40, true, "/img/k2.png"],
  ["Chuột gaming 58g wireless", "peripheral", "Logitech", "G Pro X Superlight 2, HERO 2, 32K DPI", '{"weight":"58g","dpi":32000,"wireless":true}', 139.0, 85, 33, false, "/img/gpx.png"],
];

async function ensureSchema() {
  const sql = fs.readFileSync(path.join(__dirname, "schema.sql"), "utf8");
  await query(sql);

  // seed only when empty
  const { rows } = await query("SELECT COUNT(*)::int AS n FROM users");
  if (rows[0].n > 0) return;

  const md5 = (s) => crypto.createHash("md5").update(String(s)).digest("hex"); // [VULN #44] MD5 passwords
  await query(
    `INSERT INTO users (id, email, password_hash, role, is_admin, balance, full_name, phone, address, cc_number, api_key, signature, bio_html, theme_css) VALUES
     ('legacy-admin-1', 'admin@vulnpc.local', $1, 'admin', TRUE, 99999, 'Vuln Admin', '0900123456', '1 Điện Biên Phủ, Q.1, TP.HCM', '4111-1111-1111-1111', 'sk_live_ADMINKEY123', '<%= 7*7 %> admin', '<b>Xin chào, tôi là admin của shop!</b><img src=x onerror=alert(1)>', 'body { background: #101 }'),
     ('legacy-victim-2', 'victim@vulnpc.local', $2, 'user', FALSE, 5000, 'Nguyen Van Vic', '0900999888', '99 Lê Lợi, Q.1, TP.HCM', '4242-4242-4242-4242', 'sk_live_VICTIMKEY456', '<%= name %> was here', '<i>Ch-play 24/7</i>', NULL)`,
    [md5("admin123"), md5("victim123")] // [VULN #46] weak passwords accepted
  );

  for (const p of PC_CATALOG) {
    await query(
      "INSERT INTO products (name, category, brand, description, specs, price, internal_cost, stock, featured, image_path) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
      p
    );
  }

  await query(
    `INSERT INTO comments (product_id, author, body) VALUES
     (1, 'admin', 'Build flagship của shop, chạy Cyberpunk 4K maxsetting 120fps!'),
     (2, 'anon', '<img src=x onerror=alert("stored-xss")>Máy này chơi Valorant 800fps luôn'), -- [VULN #3]
     (5, 'anon', '<script>alert("xss")</script>i9 nóng nhưng phê'),                          -- [VULN #3]
     (6, 'anon', '<%= 7*7 %> là số MMU ưa thích của tôi'),                                    -- [VULN #31] CSTI bait
     (8, 'victim', '<svg onload=alert(1)>4090 nóng như núi lửa nhưng xịn')`
  );

  await query(
    `INSERT INTO coupons (code, discount_pct, max_uses, used_count) VALUES
     ('WELCOME10', 10, 100, 0),
     ('PCLOVE50', 50, 1, 0),
     ('BLACKFRIDAY20', 20, 200, 0)`
  );

  await query(
    `INSERT INTO tickets (id, user_id, subject, status) VALUES
     (1, 'legacy-victim-2', 'Máy giao thiếu cáp 12VHPWR', 'open')
     ON CONFLICT DO NOTHING`
  );
  await query(
    `SELECT setval(pg_get_serial_sequence('tickets','id'), (SELECT MAX(id) FROM tickets));`
  );
  await query(
    `INSERT INTO ticket_messages (ticket_id, author, body) VALUES
     (1, 'victim@vulnpc.local', '<img src=x onerror=alert(1)>Đơn #1 thiếu cáp, nhân viên xem giúp em với'),
     (1, 'support', 'Chào bạn, shop sẽ gửi bổ sung trong 24h. Nếu cần gấp gọi hotline 1900-VULN.')`
  );

  await query(
    `INSERT INTO builds (user_id, name, config, total) VALUES
     ('legacy-victim-2', 'Dream 4K build', '{"cpu":6,"gpu":8,"ram":10,"mainboard":13,"storage":14,"psu":18,"case":20}', 4124.0)`
  );

  await query(
    `INSERT INTO wishlists (user_id, product_id, note) VALUES
     ('legacy-victim-2', 8, 'RTX 4090 - chờ sale </name></wishlist><product id="999"><name>PWNED'),
     ('legacy-victim-2', 6, '7800X3D rẻ nhất thị trường')`
  );

  await query(
    `INSERT INTO cart_items (user_id, product_id, qty) VALUES
     ('legacy-victim-2', 10, 1),
     ('legacy-victim-2', 18, 1)`
  );
}

module.exports = (container) => ({
  query,
  ensureSchema,
  getPool,
  pool: getPool(),
});
