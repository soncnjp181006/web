import React, { useEffect, useState } from "react";
import { LS, SS, setInsecureCookie, readAllCookies, exfiltrate } from "../vuln/clientStorage.js";
import { VULN_CONFIG } from "../vuln/insecureAuth.js";

/* [VULN #16-#26] Client-side storage & token exposure lab. */
export default function Storage() {
  const [email, setEmail] = useState("admin@vulnshop.local");
  const [password, setPassword] = useState("admin123");
  const [dump, setDump] = useState({});
  const [telemetry, setTelemetry] = useState("");

  async function refresh() {
    setDump({
      localStorage: LS.all(), // [VULN #21]
      sessionStorage: SS.all(), // [VULN #22]
      cookies: readAllCookies(), // [VULN #23][#26]
      windowGlobals: { VULN_CONFIG }, // [VULN #18]
    });
  }
  useEffect(() => {
    refresh();
  }, []);

  /* [VULN #24] legacy JWT login -> token in localStorage + query param */
  async function legacyLogin() {
    const r = await fetch("/api/auth/jwt/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "include",
      body: JSON.stringify({ email, password }),
    }).then((x) => x.json());
    if (r.token) {
      LS.set("vulnshop_jwt", r.token); // [VULN #21][#24] JWT in localStorage
      SS.set("vulnshop_jwt_session", r.token); // [VULN #22]
      setInsecureCookie("vulnshop_track", r.token.slice(0, 12)); // [VULN #23]
      LS.set("vulnshop_creds", { email, password }); // [VULN #21] plaintext creds!
    }
    setDump((d) => ({ ...d, loginResponse: r }));
    refresh();
  }

  /* [VULN #25] token theft: "analytics" exfiltrates the loot */
  async function stealTokens() {
    const loot = {
      src: "storage-page",
      kind: "manual-exfil",
      jwt: LS.get("vulnshop_jwt"),
      cookies: readAllCookies(),
      localStorageKeys: Object.keys(LS.all()),
    };
    const r = await exfiltrate(loot);
    const list = await fetch("/api/telemetry").then((x) => x.json());
    setTelemetry(JSON.stringify(list, null, 2).slice(0, 8000));
    refresh();
  }

  return (
    <div>
      <h1>Storage & Token lab</h1>
      <div className="card">
        <h2>Legacy login (JWT → localStorage #21/#24)</h2>
        <div className="row">
          <input value={email} onChange={(e) => setEmail(e.target.value)} />
          <input value={password} onChange={(e) => setPassword(e.target.value)} />
          <button className="primary" onClick={legacyLogin}>
            Login (lưu token ở 4 nơi)
          </button>
        </div>
        <p className="hint">
          Token lưu: localStorage + sessionStorage + cookie không HttpOnly + plaintext credentials trong
          localStorage. Mọi XSS trong app đọc được tất cả (#25/#26).
        </p>
      </div>

      <div className="card">
        <h2>Token theft (#25) — mô phỏng attacker</h2>
        <div className="row">
          <button className="danger" onClick={stealTokens}>
            Exfiltrate loot → /api/telemetry
          </button>
          <button
            onClick={async () => setTelemetry(JSON.stringify(await fetch("/api/telemetry").then((x) => x.json()), null, 2).slice(0, 8000))}
          >
            Xem "attacker view" (collector)
          </button>
        </div>
        {telemetry && <pre>{telemetry}</pre>}
      </div>

      <div className="card">
        <h2>Toàn bộ storage của bạn (sensitive data exposure #16)</h2>
        <button onClick={refresh}>Refresh</button>
        <pre>{JSON.stringify(dump, null, 2)}</pre>
      </div>

      <div className="card">
        <h2>Session hijack nhanh (#26)</h2>
        <p className="hint">
          Cookie <code>session</code> (legacy) và <code>vulnshop_track</code> đọc được bằng{" "}
          <code>document.cookie</code> — copy giá trị rồi dán vào{" "}
          <code>/api/legacy/me?session=...</code> từ browser/máy khác → truy cập phiên.
        </p>
      </div>
    </div>
  );
}
