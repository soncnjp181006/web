import React, { useState } from "react";
import api from "../api.js";

/* Staff portal (legacy) — cổng nhân viên cũ, đầy đủ auth lỗi.
   [VULN #15/#19/#20/#21] brute force / stuffing / spraying — không lockout
   [VULN #17] session fixation (sessionId param)
   [VULN #52] rate limit bypass bằng X-Forwarded-For
   [VULN #67] account enumeration
   [VULN #66/#35] forgot/reset — token md5(email), host header poisoning
   [VULN #61] JWT login — secret yếu, whoami decode-no-verify
   [VULN #18] replay token — HMAC-md5, không expiry
   [VULN #63] SAML consume không verify chữ ký
   [VULN #62] OAuth authorize không validate redirect_uri / state */
export default function LegacyAuth() {
  const [email, setEmail] = useState("admin@vulnpc.local");
  const [password, setPassword] = useState("admin123");
  const [sessionId, setSessionId] = useState("");
  const [xfp, setXfp] = useState("");
  const [out, setOut] = useState("");
  const [jwt, setJwt] = useState("");
  const [saml, setSaml] = useState("");

  async function run(fn) {
    try {
      setOut(JSON.stringify(await fn(), null, 2).slice(0, 6000));
    } catch (e) {
      setOut("ERROR: " + e.message);
    }
  }

  return (
    <div>
      <h1>🔐 Staff portal (legacy)</h1>
      <p className="hint">Cổng nhân viên phiên bản cũ — vẫn hoạt động song song với Supertokens, toàn bộ auth đều lỗi.</p>

      <div className="card">
        <h2>Đăng nhập legacy (MD5 + cookie SameSite=None)</h2>
        <div className="row">
          <input value={email} onChange={(e) => setEmail(e.target.value)} placeholder="email" />
          <input value={password} onChange={(e) => setPassword(e.target.value)} placeholder="password" />
          <input value={sessionId} onChange={(e) => setSessionId(e.target.value)} placeholder="sessionId (fixation #17)" style={{ width: 180 }} />
          <input value={xfp} onChange={(e) => setXfp(e.target.value)} placeholder="X-Forwarded-For (bypass #52)" style={{ width: 160 }} />
          <button
            className="primary"
            onClick={() =>
              run(async () => {
                const r = await fetch("/api/auth/login", {
                  method: "POST",
                  headers: { "Content-Type": "application/json", ...(xfp ? { "X-Forwarded-For": xfp } : {}) },
                  credentials: "include",
                  body: JSON.stringify({ email, password, sessionId: sessionId || undefined }),
                }).then((x) => x.json());
                return r;
              })
            }
          >
            Login
          </button>
        </div>
        <p className="hint">
          Seed: <code>admin@vulnpc.local/admin123</code>, <code>victim@vulnpc.local/victim123</code> (#46). Message
          "User not found" vs "Invalid password" → enum (#67). Đổi X-Forwarded-For mỗi lần → rate limit vô nghĩa (#52).
          Brute force (#19): không lockout, không captcha.
        </p>
      </div>

      <div className="card">
        <h2>Quên mật khẩu (#66/#35)</h2>
        <button onClick={() => run(async () => api("/api/auth/forgot", { body: { email } }).then((r) => r.data))}>
          Gửi reset
        </button>
        <p className="hint">
          Token = md5(email) — đoán offline được, không hết hạn, dùng lại được. Link build từ header{" "}
          <code>X-Forwarded-Host</code> — host header poisoning.
        </p>
      </div>

      <div className="card">
        <h2>JWT staff token (#61/#24)</h2>
        <div className="row">
          <button
            className="primary"
            onClick={() =>
              run(async () => {
                const r = await api("/api/auth/jwt/login", { body: { email, password } }).then((x) => x.data);
                if (r.token) {
                  setJwt(r.token);
                  localStorage.setItem("vulnshop_jwt", r.token); // [VULN #21/#24]
                }
                return r;
              })
            }
          >
            Lấy JWT (secret jwt-secret-123)
          </button>
          <button onClick={() => run(async () => fetch(`/api/auth/jwt/whoami?token=${encodeURIComponent(jwt || "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJsZWdhY3ktYWRtaW4tMSIsInJvbGUiOiJhZG1pbiJ9.x")}`).then((r) => r.json()))}>
            whoami (decode KHÔNG verify)
          </button>
          {jwt && <code style={{ maxWidth: 300, overflow: "hidden" }}>{jwt.slice(0, 40)}...</code>}
        </div>
        <p className="hint">
          Secret lộ ở /internal → tự ký token mọi user. whoami dùng <code>jwt.decode()</code> — token tự chế, alg none
          đều chấp nhận.
        </p>
      </div>

      <div className="card">
        <h2>SAML SSO staff (#63)</h2>
        <div className="row">
          <button onClick={() => run(async () => api("/api/saml/sample").then((r) => r.data).then((d) => { setSaml(d.SAMLResponse); return d; }))}>
            Lấy assertion mẫu
          </button>
          <button
            className="danger"
            onClick={() =>
              run(async () =>
                api("/api/saml/consume", { body: { SAMLResponse: saml || btoa('<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"><saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:Subject><saml:NameID>admin@vulnpc.local</saml:NameID></saml:Subject></saml:Assertion></samlp:Response>') } }).then((r) => r.data)
              )
            }
          >
            Consume (không verify signature)
          </button>
        </div>
        <p className="hint">Sửa NameID thành bất kỳ email nào → đăng nhập với tư cách người đó; user lạ tự tạo.</p>
      </div>

      <div className="card">
        <h2>OAuth SSO (#62)</h2>
        <div className="row">
          <a href={`/api/oauth/authorize?client_id=vuln-client&redirect_uri=${encodeURIComponent(window.location.origin + "/api/oauth/client/callback")}&response_type=code&state=unused`}>
            <button className="primary">Code flow (state không validate)</button>
          </a>
          <a href={`/api/oauth/authorize?client_id=vuln-client&redirect_uri=${encodeURIComponent("https://example.com/attacker-cb")}&response_type=code`}>
            <button className="danger">Gửi code tới attacker domain</button>
          </a>
          <a href={`/api/oauth/authorize?client_id=vuln-client&redirect_uri=${encodeURIComponent(window.location.origin + "/api/oauth/client/callback")}&response_type=token`}>
            <button>Implicit flow (token trong fragment)</button>
          </a>
        </div>
      </div>

      <div className="card">
        <h2>Replay token (#18)</h2>
        <div className="row">
          <button onClick={() => run(async () => api("/api/auth/replay/issue").then((r) => r.data))}>Issue token</button>
          <button onClick={() => run(async () => api("/api/auth/replay/verify", { body: { token: (out.match(/"token":"([^"]+)"/) || [])[1] || "" } }).then((r) => r.data))}>
            Verify (dùng lại vô hạn)
          </button>
        </div>
      </div>

      {out && <pre>{out}</pre>}
    </div>
  );
}
