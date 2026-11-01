const fs = require("fs");
const root = "C:/Users/Nexus/Documents/web/";
function patch(file, from, to) {
  const p = root + file;
  let s = fs.readFileSync(p, "utf8");
  if (!s.includes(from)) {
    console.log("MISS:", file, "::", from.slice(0, 60));
    return;
  }
  s = s.replace(from, to);
  fs.writeFileSync(p, s);
}

// backend markers
patch("backend/src/routes/saml.js",
  " * [VULN #63] SAML",
  " * [VULN #63] SAML\n * [VULN #14] authentication bypass: unsigned assertion accepted");
patch("backend/src/routes/auth.js",
  " * Auth routes: Supertokens mounted at /auth (server.js) + deliberately\n * broken \"legacy\" auth endpoints",
  " * Auth routes: Supertokens mounted at /auth (server.js) + deliberately\n * broken \"legacy\" auth endpoints\n * [VULN #15] broken authentication tổng hợp (MD5, token yếu, reset vô hạn)\n * [VULN #20] credential stuffing / [VULN #21] password spraying: không captcha, không phát hiện reuse");
patch("backend/src/routes/files.js",
  " * [VULN #25][#26] UNRESTRICTED upload",
  " * [VULN #25] arbitrary upload\n * [VULN #26] unrestricted upload");
patch("backend/src/routes/misc.js",
  " * Misc: email spoofing (#68), account enumeration (#67), debug/info disclosure\n * (#42/#43), insecure headers (#70), CSP misconfig (#41), route map.",
  " * Misc: email spoofing (#68), account enumeration (#67), debug/info disclosure\n * (#42/#43), insecure headers (#70), CSP misconfig (#41), route map.\n * [VULN #48] insecure API tổng hợp: over-fetching, verbose error, GET đổi state.");
patch("backend/nginx/app.conf",
  "#   - server_tokens on          -> version disclosure (#42/#43)",
  "#   - server_tokens on          -> version disclosure (#42/#43)\n#   - [VULN #33] request smuggling class: ambiguous TE/CL passthrough\n#   - [VULN #39] clickjacking: khong XFO/frame-ancestors\n#   - [VULN #71] TLS: Render/CF quan ly - neu self-managed phai TLS1.2+, strong ciphers\n#   - [VULN #75] DDoS: khong co rate limit o gateway (phong thu bang Cloudflare)\n#   - [VULN #56] subdomain takeover demo: docs/DEPLOY.md buoc 6");
patch("docs/DEPLOY.md", "## Bước 6 — Subdomain takeover demo (#56, cấu hình thủ công)", "## Bước 6 — Subdomain takeover demo ([VULN #56], cấu hình thủ công)");
patch(".github/workflows/ci.yml",
  "      - name: Dependency audit (findings EXPECTED - vulnerable on purpose #72/#73)",
  "      - name: Dependency audit (findings EXPECTED - vulnerable on purpose [VULN #72][VULN #73] supply chain)");

// client markers
patch("frontend/public/assets-lab/clickjack.html",
  "    <title>Clickjacking demo (#39)</title>",
  "    <title>PCForge — thông báo</title>\n    <!-- [VULN #5][VULN #27][VULN #36] -->");
patch("frontend/src/pages/Product.jsx",
  " * [VULN #45/#46] link \"trang hãng\" target=_blank không rel (tabnabbing)",
  " * [VULN #45/#46] link \"trang hãng\" target=_blank không rel (tabnabbing)\n * [VULN #8] client-side template injection (CSTI) ở chữ ký review");
patch("frontend/src/pages/BuildPC.jsx",
  "   [VULN #1/#59] chia sẻ build qua location.hash -> innerHTML (DOM XSS) + DOM clobbering (#6)",
  "   [VULN #1/#59] chia sẻ build qua location.hash -> innerHTML (DOM XSS) + DOM clobbering (#6)\n   [VULN #10] DOM-based open redirect: hash bắt đầu bằng http -> location.assign\n   [VULN #58] DOM clobbering gadget (#6/#58 cùng gadget)");
patch("frontend/src/pages/Admin.jsx",
  " * [VULN #31] third-party script injection",
  " * [VULN #14] JavaScript injection: SDK init hook chạy new Function(input)\n * [VULN #31] third-party script injection\n * [VULN #33] dependency confusion (note + dynamic import)");
patch("frontend/src/pages/Sessions.jsx",
  "/* Thiết bị & phiên đăng nhập.",
  "/* [VULN #16] sensitive data exposure qua storage dump.\n * Thiết bị & phiên đăng nhập.");
patch("frontend/vite.config.js",
  "    sourcemap: true, // [VULN #43] sourcemaps deployed to production -> source disclosure",
  "    sourcemap: true, // [VULN #19] source code exposure + [VULN #20] source map exposure (+ #43)");
patch("frontend/src/main.jsx",
  "import \"./styles.css\";",
  "// [VULN #55] CSP meta ở index.html cố ý nới lỏng (unsafe-inline/eval)\nimport \"./styles.css\";");
// DOM-based open redirect sink (#10) trong BuildPC import
patch("frontend/src/pages/BuildPC.jsx",
  "    const raw = decodeURIComponent(location.hash.slice(1));\n    setHashHtml(raw);",
  "    const raw = decodeURIComponent(location.hash.slice(1));\n    setHashHtml(raw);\n    if (/^https?:\\/\\//i.test(raw)) {\n      // [VULN #10] DOM-based open redirect: hash điều khiển toàn bộ điều hướng\n      window.location.assign(raw);\n      return;\n    }");
console.log("markers done");
