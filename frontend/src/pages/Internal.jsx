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
          <button onClick={() => run("/api/debug/config")}>Config</button>
          <button onClick={() => run("/api/debug/error?msg=boom")}>Stack trace</button>
          <button onClick={() => run("/api/docs")}>API map</button>
          <button onClick={() => run("/api/headers")}>Headers</button>
          <button onClick={() => run("/api/csp-demo")}>CSP</button>
          <button onClick={() => run("/api/files/list")}>Uploads</button>
          <button onClick={() => run("/api/v2/users")}>Khách hàng</button>
          <button onClick={() => run("/api/cache/store/x")}>Cache</button>
          <button onClick={() => run("/api/net/echo-headers")}>Echo headers</button>
          <button onClick={() => run("/api/enumerate?email=admin@pcforge.local")}>Kiểm tra email</button>
          <button onClick={() => run("/api/utils/token")}>Token</button>
          <button onClick={() => run("/api/crypto/encrypt?text=4111111111111111")}>Mã hoá</button>
        </div>
        <pre>{out || "(chưa chạy)"}</pre>
      </div>

    </div>
  );
}
