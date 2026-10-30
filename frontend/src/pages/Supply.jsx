import React, { useState } from "react";

/* [VULN #30] SRI bypass (index.html đã load 3rd-party-widget.js không integrity),
   [#32] malicious dependency injection (dynamic import theo input),
   [#33] dependency confusion (lockfile + registry mix). */
export default function Supply() {
  const [modulePath, setModulePath] = useState("/uploads/widget.js");
  const [out, setOut] = useState("");

  /* [VULN #32] dynamic import của module do user chỉ định */
  async function loadModule() {
    setOut("importing...");
    try {
      const m = await import(/* @vite-ignore */ modulePath);
      setOut(`imported OK. exports: ${JSON.stringify(Object.keys(m)).slice(0, 500)}`);
    } catch (e) {
      setOut("import failed: " + e.message + "\n(hint: upload 1 file .js qua trang Upload rồi dùng /uploads/<name>.js)");
    }
  }

  return (
    <div>
      <h1>Supply chain lab (client)</h1>

      <div className="card">
        <h2>SRI bypass (#30)</h2>
        <p className="hint">
          <code>index.html</code> load <code>/3rd-party-widget.js</code> <b>không có</b>{" "}
          <code>integrity="sha384-..."</code> và <code>crossorigin</code>: file (hoặc CDN/TLS MITM) bị thay = code
          chạy ngay cho mọi visitor. Script này đang loot storage + hook fetch — kiểm chứng ở trang{" "}
          <b>Storage lab → Xem attacker view</b>.
        </p>
        <pre>{`<!-- hiện tại (yếu) -->
<script src="/3rd-party-widget.js"></script>

<!-- an toàn -->
<script src="/3rd-party-widget.js"
        integrity="sha384-<hash>"
        crossorigin="anonymous"></script>`}</pre>
      </div>

      <div className="card">
        <h2>Malicious dependency injection (#32)</h2>
        <div className="row">
          <input value={modulePath} onChange={(e) => setModulePath(e.target.value)} style={{ flex: 1 }} />
          <button className="danger" onClick={loadModule}>
            import(module)
          </button>
        </div>
        <p className="hint">
          App "nạp plugin" theo config/input → attacker upload <code>widget.js</code> (trang Upload) rồi trỏ vào{" "}
          <code>/uploads/widget.js</code> → code chạy trong origin app. Trong bundle thật, tương tự với CDN URL
          hoặc package npm bị chiếm.
        </p>
        <pre>{out || "(chưa chạy)"}</pre>
      </div>

      <div className="card">
        <h2>Dependency confusion (#33)</h2>
        <p className="hint">
          Kịch bản: repo internal dùng tên package <code>@vulnshop/utils</code> chưa publish lên npm — attacker
          publish bản độc hại với version 99.0.0 → CI resolve phiên bản public cao hơn → RCE lúc build. Giảm nguy
          cơ: <code>npm config set scope @vulnshop registry=internal</code>, lockfile commit, allowlist registry.
        </p>
        <p className="hint">
          Trong repo này: <code>backend/package.json</code> cố ý pin <code>jsonwebtoken@8.5.1</code>,{" "}
          <code>lodash@4.17.15</code> (CVE thật) — chạy <code>npm audit</code> trong CI để thấy (#72).
        </p>
        <pre>{`$ npm ls jsonwebtoken lodash
jsonwebtoken@8.5.1  (CVE-2022-23529 family)
lodash@4.17.15      (CVE-2020-8203 prototype pollution)`}</pre>
      </div>
    </div>
  );
}
