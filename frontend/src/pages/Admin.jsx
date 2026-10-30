import React, { useState } from "react";
import Session from "supertokens-auth-react/recipe/session";
import api from "../api.js";

/* Admin page: client-side-only role check (#12) + header-trust escalation (#13). */
export default function Admin() {
  const [role, setRole] = useState("user");
  const [token, setToken] = useState("");
  const [isAuthed, setIsAuthed] = useState(false);
  const [out, setOut] = useState("");
  const [allowed, setAllowed] = useState(false);

  useEffect(() => {
    Session.doesSessionExist().then(setIsAuthed);
  }, []);

  // "guard" chặn CHỈ ở phía client (#12) — API phía sau hoàn toàn không kiểm tra.
  if (isAuthed && !allowed) {
    return (
      <div className="card">
        <h1>Admin</h1>
        <p className="hint">
          Trang chỉ render nếu role=admin — nhưng chỉ ở client (#12). Bấm nút dưới để gọi thẳng API với header{" "}
          <code>x-user-role: admin</code> (#13) hoặc dùng <code>x-admin-token</code> (token lộ ở /api/debug/config).
        </p>
        <button className="danger" onClick={() => setAllowed(true)}>
          Bypass client guard (demo #12)
        </button>
      </div>
    );
  }

  async function call(path) {
    const headers = {};
    if (role === "admin") headers["x-user-role"] = "admin"; // [VULN #13]
    if (token) headers["x-admin-token"] = token;
    const res = await fetch(path, { headers, credentials: "include" });
    const data = await res.json().catch(() => "<non-json>");
    setOut(JSON.stringify({ status: res.status, data }, null, 2).slice(0, 10000));
  }

  async function exec() {
    const cmd = prompt("OS command:", "id; uname -a");
    if (cmd == null) return;
    const res = await fetch("/api/admin/exec", {
      method: "POST",
      credentials: "include",
      headers: { "Content-Type": "application/json", "x-user-role": role === "admin" ? "admin" : "user" },
      body: JSON.stringify({ cmd }),
    });
    setOut(JSON.stringify(await res.json(), null, 2));
  }

  return (
    <div>
      <h1>Admin console</h1>
      <div className="card">
        <h2>Gate bypass (#12/#13)</h2>
        <div className="row">
          <select value={role} onChange={(e) => setRole(e.target.value)}>
            <option value="user">user (không header)</option>
            <option value="admin">admin (gửi x-user-role: admin)</option>
          </select>
          <input placeholder="x-admin-token (optional)" value={token} onChange={(e) => setToken(e.target.value)} />
        </div>
        <p className="hint">
          Còn 1 cách nữa: prototype pollution (#57) — <code>POST /api/utils/merge</code> body{" "}
          <code>{'{"__proto__":{"adminBypass":true}}'}</code> rồi mọi /api/admin/* mở bỏ.
        </p>
      </div>
      <div className="card">
        <h2>Actions</h2>
        <div className="row">
          <button onClick={() => call("/api/admin/stats")}>stats</button>
          <button className="danger" onClick={exec}>
            exec command (#4)
          </button>
          <button onClick={() => call("/api/admin/logs")}>logs (#36)</button>
          <button onClick={() => call("/api/v2/users")}>v2 users dump (#50)</button>
        </div>
        <pre>{out || "(chưa chạy)"}</pre>
      </div>
    </div>
  );
}
