import React, { useState } from "react";
import api from "../api.js";

/* Staff diagnostics (nội bộ).
   [VULN #42/#43] config dump, stack trace, route map, đường dẫn tuyệt đối
   [VULN #70] headers — không HSTS/XFO/nosniff
   [VULN #41] CSP permissive
   [VULN #37/#65] cache store public
   [VULN #50/#44] users dump
   [VULN #38] web cache deception */
export default function Internal() {
  const [out, setOut] = useState("");

  async function run(path) {
    const r = await api(path);
    const text = typeof r.data === "string" ? r.data : JSON.stringify(r.data, null, 2);
    setOut(`GET ${path} -> ${r.status}\n\n${text.slice(0, 20000)}`);
  }

  return (
    <div>
      <h1>🛠 Staff diagnostics</h1>
      <div className="card">
        <div className="row">
          <button onClick={() => run("/api/debug/config")}>config dump (#42/#43)</button>
          <button onClick={() => run("/api/debug/error?msg=boom")}>stack trace (#43)</button>
          <button onClick={() => run("/api/docs")}>API map (#42)</button>
          <button onClick={() => run("/api/headers")}>headers (#70)</button>
          <button onClick={() => run("/api/csp-demo")}>CSP demo (#41)</button>
          <button onClick={() => run("/api/files/list")}>uploads + paths (#43)</button>
          <button onClick={() => run("/api/v2/users")}>users dump (#50/#44)</button>
          <button onClick={() => run("/api/cache/store/x")}>cache store (#37)</button>
          <button onClick={() => run("/api/net/echo-headers")}>echo headers (#37/#65)</button>
          <button onClick={() => run("/api/enumerate?email=admin@vulnpc.local")}>enumerate (#67)</button>
          <button onClick={() => run("/api/utils/token")}>weak token (#45)</button>
          <button onClick={() => run("/api/crypto/encrypt?text=4111111111111111")}>AES-ECB (#47)</button>
        </div>
        <pre>{out || "(chưa chạy)"}</pre>
      </div>
      <div className="card">
        <h2>Web cache deception (#38)</h2>
        <p className="hint">
          Khi đã đăng nhập: mở <code>/api/cache/profile/whatever.css</code> — profile JSON trả về với{" "}
          <code>Cache-Control: public</code> và đuôi .css → CDN/browser cache theo URL, ai cũng đọc được sau đó.
        </p>
      </div>
    </div>
  );
}
