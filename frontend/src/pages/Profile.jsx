import React, { useEffect, useState } from "react";
import Session from "supertokens-auth-react/recipe/session";
import api from "../api.js";

export default function Profile() {
  const [profile, setProfile] = useState(null);
  const [form, setForm] = useState({ role: "user", is_admin: false, balance: 0, signature: "" });
  const [out, setOut] = useState("");

  useEffect(() => {
    (async () => {
      const uid = await Session.getUserId().catch(() => null);
      // [VULN #44] /api/auth/me returns the FULL row (password hash, cc, api key)
      const r = await api("/api/auth/me");
      setProfile(r.data && r.data.profile);
      if (r.data && r.data.profile) {
        setForm({
          role: r.data.profile.role || "user",
          is_admin: !!r.data.profile.is_admin,
          balance: r.data.profile.balance || 0,
          signature: r.data.profile.signature || "",
        });
      }
    })();
  }, []);

  /* [VULN #51] mass assignment: whatever you send gets written (role, is_admin,
     balance, cc_number...). Escalate to admin with one checkbox. */
  async function save(e) {
    e.preventDefault();
    const r = await api("/api/profile", { method: "PUT", body: form });
    setOut(JSON.stringify(r.data, null, 2));
  }

  return (
    <div>
      <h1>Hồ sơ</h1>
      <div className="card">
        <h2>Full row từ /api/auth/me (sensitive data exposure #44)</h2>
        <pre>{JSON.stringify(profile, null, 2)}</pre>
      </div>
      <div className="card">
        <h2>Cập nhật hồ sơ (mass assignment #51)</h2>
        <div className="row">
          <div>
            <label>role</label>
            <input value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value })} />
          </div>
          <div>
            <label>is_admin</label>
            <input type="checkbox" checked={form.is_admin} onChange={(e) => setForm({ ...form, is_admin: e.target.checked })} />
          </div>
          <div>
            <label>balance</label>
            <input value={form.balance} onChange={(e) => setForm({ ...form, balance: e.target.value })} />
          </div>
          <div>
            <label>signature</label>
            <input value={form.signature} onChange={(e) => setForm({ ...form, signature: e.target.value })} />
          </div>
          <button className="danger" onClick={save}>
            Save (PUT mọi field)
          </button>
        </div>
        <p className="hint">
          Đặt role=<code>admin</code> + is_admin=true rồi vào trang <b>Admin</b> — privilege escalation #13/#51.
        </p>
        {out && <pre>{out}</pre>}
      </div>
    </div>
  );
}
