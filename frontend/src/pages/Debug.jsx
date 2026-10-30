import React, { useState } from "react";
import api from "../api.js";

export default function Debug() {
  const [out, setOut] = useState("");

  async function run(path) {
    const r = await api(path);
    const text = typeof r.data === "string" ? r.data : JSON.stringify(r.data, null, 2);
    setOut(`GET ${path} -> ${r.status}\n\n${text.slice(0, 20000)}`);
  }

  return (
    <div>
      <h1>Debug & info disclosure</h1>
      <div className="card">
        <div className="row">
          <button onClick={() => run("/api/debug/config")}>config dump (#42/#43)</button>
          <button onClick={() => run("/api/debug/error?msg=boom")}>stack trace (#43)</button>
          <button onClick={() => run("/api/docs")}>API map (#42)</button>
          <button onClick={() => run("/api/headers")}>headers (#70)</button>
          <button onClick={() => run("/api/csp-demo")}>CSP demo (#41)</button>
          <button onClick={() => run("/api/files/list")}>uploads + paths (#43)</button>
          <button onClick={() => run("/api/v2/users")}>full user dump (#50/#44)</button>
          <button onClick={() => run("/api/cache/store/x")}>cache store (#37)</button>
        </div>
        <pre>{out || "(chưa chạy)"}</pre>
      </div>
      <div className="card">
        <h2>Web cache deception (#38)</h2>
        <p className="hint">
          Khi đã đăng nhập: mở <code>/api/cache/profile/whatever.css</code> — profile JSON được trả về với{" "}
          <code>Cache-Control: public</code> và đuôi .css → Cloudflare cache theo URL. Attacker biết URL (bất kỳ ai),
          đọc cache sau đó.
        </p>
      </div>
      <div className="card">
        <h2>Clickjacking demo (#39)</h2>
        <p className="hint">
          Không có <code>X-Frame-Options</code> / <code>frame-ancestors</code> → site có thể được nhúng. Mở{" "}
          <code>/clickjack-demo.html</code> để xem iframe ẩn bấm nút hộ người dùng.
        </p>
      </div>
    </div>
  );
}
