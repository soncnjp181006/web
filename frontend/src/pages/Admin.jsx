import React, { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import Session from "supertokens-auth-react/recipe/session";
import { mergeDeep, parseNestedQuery, getClientUser, setClientUser, isClientAdmin, canSeeHiddenPanel, BACKUP_ADMIN, VULN_CONFIG } from "../vuln/insecureAuth.js";
// [VULN #14] JavaScript injection (new Function sink trong vendor panel) | [VULN #31] script injection | [VULN #33] dependency confusion

/* Admin dashboard.
   [VULN #12] client-side-only guard + static token
   [VULN #13] trust x-user-role header
   [VULN #34/#35] client authn/authz bypass (?debug_login / localStorage role)
   [VULN #7] prototype pollution client qua ?__proto__[unlockAllFeatures]=true
   [VULN #50] BFLA panel (delete-user, users dump)
   [VULN #4] exec diagnostics
   [VULN #36] logs (CRLF injectable)
   [VULN #17/#18] hardcoded credentials + API keys trong bundle
   [VULN #31] vendor widget script theo URL, không SRI
   [VULN #32/#33] dynamic import "vendor extension" + dependency confusion note */
export default function Admin() {
  const [params] = useSearchParams();
  const [role, setRole] = useState("user");
  const [token, setToken] = useState("");
  const [isAuthed, setIsAuthed] = useState(false);
  const [allowed, setAllowed] = useState(false);
  const [out, setOut] = useState("");
  const [polluted, setPolluted] = useState(false);
  const [vendorScript, setVendorScript] = useState("/3rd-party-widget.js");
  const [vendorModule, setVendorModule] = useState("/uploads/widget.js");
  const [vendorOut, setVendorOut] = useState("");

  useEffect(() => {
    Session.doesSessionExist().then(setIsAuthed);
    // [VULN #34] backdoor đăng nhập client qua query
    if (params.get("debug_login") === "1" || params.get("debug_user")) {
      setClientUser({ name: params.get("debug_user") || "debug", role: "admin", is_admin: true });
    }
    // [VULN #7] client prototype pollution từ query
    const parsed = parseNestedQuery(params.toString());
    if (Object.keys(parsed).length) {
      mergeDeep({}, parsed);
      setPolluted({}.unlockAllFeatures === true || {}.isAdmin === true);
    }
  }, [params]);

  /* [VULN #35] gate CHỈ tồn tại phía client */
  if (isAuthed && !allowed && !params.get("debug_login")) {
    return (
      <div className="card">
        <h1>403 — Khu vực quản trị</h1>
        <p className="hint">Chỉ dành cho quản trị viên. Liên hệ IT nếu bạn cần quyền truy cập.</p>
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
    const cmd = prompt("OS command:", "id; ls /app");
    if (cmd == null) return;
    const res = await fetch("/api/admin/exec", {
      method: "POST",
      credentials: "include",
      headers: { "Content-Type": "application/json", "x-user-role": role === "admin" ? "admin" : "user" },
      body: JSON.stringify({ cmd }),
    });
    setOut(JSON.stringify(await res.json(), null, 2).slice(0, 10000));
  }

  /* [VULN #31] inject script theo URL, không SRI */
  function loadVendorScript() {
    const s = document.createElement("script");
    s.src = vendorScript;
    s.onerror = () => (setVendorOut("script load failed (xem console)"));
    document.body.appendChild(s);
    setVendorOut((o) => o + `\n[script] injected ${vendorScript}`);
  }

  /* [VULN #32] dynamic import module upload */
  async function loadVendorModule() {
    try {
      const m = await import(/* @vite-ignore */ vendorModule);
      setVendorOut((o) => o + `\n[module] imported: ${JSON.stringify(Object.keys(m)).slice(0, 300)}`);
    } catch (e) {
      setVendorOut((o) => o + `\n[module] import failed: ${e.message} (upload file .js qua trang Upload rồi dùng /uploads/<name>.js)`);
    }
  }

  return (
    <div>
      <h1>Admin console</h1>
      {canSeeHiddenPanel("reports") && (
        <div className="comment">
          🎉 <b>Hidden reports panel</b> — mở nhờ prototype pollution / feature flag client (#7/#35)
        </div>
      )}

      <div className="card">
        <h2>Phân quyền</h2>
        <div className="row">
          <select value={role} onChange={(e) => setRole(e.target.value)}>
            <option value="user">user (không header)</option>
            <option value="admin">admin (gửi x-user-role: admin)</option>
          </select>
          <input placeholder="x-admin-token (optional)" value={token} onChange={(e) => setToken(e.target.value)} />
        </div>
      </div>

      <div className="card">
        <h2>Quản trị</h2>
        <div className="row">
          <button onClick={() => call("/api/admin/stats")}>📊 stats</button>
          <button className="danger" onClick={exec}>
            ⚙ Chạy diagnostics
          </button>
          <button onClick={() => call("/api/admin/logs")}>📜 Nhật ký hệ thống</button>
          <button onClick={() => call("/api/admin/settings")}>⚙ settings</button>
          <button onClick={() => call("/api/v2/users")}>👥 Danh sách khách hàng</button>
          <button
            className="danger"
            onClick={async () => {
              const id = prompt("user id to DELETE:", "legacy-victim-2");
              if (!id) return;
              const r = await api("/api/v2/admin/delete-user", { body: { id } });
              setOut(JSON.stringify(r.data, null, 2));
            }}
          >
            🗑 Xoá khách hàng
          </button>
        </div>
        <pre>{out || "(chưa chạy)"}</pre>
      </div>

      <div className="card">
        <h2>Tích hợp SDK đối tác</h2>
        <div className="row">
          <input value={vendorScript} onChange={(e) => setVendorScript(e.target.value)} style={{ flex: 1 }} />
          <button className="danger" onClick={loadVendorScript}>
            Nạp widget đối tác
          </button>
        </div>
        <div className="row">
          <input value={vendorModule} onChange={(e) => setVendorModule(e.target.value)} style={{ flex: 1 }} />
          <button className="danger" onClick={loadVendorModule}>
            Nạp module đối tác
          </button>
        </div>
        <p className="hint">

        </p>
        <pre>{vendorOut || "(chưa load)"}</pre>
      </div>
    </div>
  );
}
