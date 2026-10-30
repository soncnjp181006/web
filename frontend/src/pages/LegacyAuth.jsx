import React, { useState } from "react";
import api from "../api.js";

/* [VULN #15/#19/#20/#21] legacy login: MD5, no lockout, enumeration,
   fixation (sessionId param), token in response + weak cookie. */
export default function LegacyAuth() {
  const [email, setEmail] = useState("admin@vulnshop.local");
  const [password, setPassword] = useState("admin123");
  const [sessionId, setSessionId] = useState("");
  const [out, setOut] = useState("");

  async function submit(e) {
    e.preventDefault();
    const r = await api("/api/auth/login", { body: { email, password, sessionId: sessionId || undefined } });
    setOut(JSON.stringify(r.data, null, 2));
  }

  return (
    <div>
      <h1>Legacy login (độc lập với Supertokens)</h1>
      <div className="card">
        <form onSubmit={submit}>
          <label>email</label>
          <input value={email} onChange={(e) => setEmail(e.target.value)} style={{ width: "100%" }} />
          <label>password</label>
          <input value={password} onChange={(e) => setPassword(e.target.value)} style={{ width: "100%" }} />
          <label>sessionId (để trống = random) — session fixation #17</label>
          <input value={sessionId} onChange={(e) => setSessionId(e.target.value)} placeholder="attacker-known-token" style={{ width: "100%" }} />
          <button className="primary">Login</button>
        </form>
        <p className="hint">
          Brute force (#19): không lockout; rate limit dễ bypass bằng header <code>X-Forwarded-For</code> random (#52).
          Password khác nhau trả message khác nhau (#67). Seed: <code>admin@vulnshop.local/admin123</code>,{" "}
          <code>victim@vulnshop.local/victim123</code>.
        </p>
        {out && <pre>{out}</pre>}
      </div>
      <div className="card">
        <h2>Quên mật khẩu (#66/#35)</h2>
        <button
          onClick={async () => {
            const r = await api("/api/auth/forgot", { body: { email } });
            setOut(JSON.stringify(r.data, null, 2));
          }}
        >
          Gửi reset cho email trên
        </button>
        <p className="hint">
          Token = md5(email) (đoán được), không hết hạn, dùng lại được; link dựng từ header{" "}
          <code>X-Forwarded-Host</code> — host header poisoning.
        </p>
      </div>
    </div>
  );
}
