import React, { useEffect, useState } from "react";
import { LS, SS, setInsecureCookie, readAllCookies, exfiltrate } from "../vuln/clientStorage.js";

/* Thiết bị & phiên đăng nhập.
   [VULN #21/#22] localStorage/sessionStorage để token + plaintext creds
   [VULN #23] cookie client-side không HttpOnly/Secure/SameSite
   [VULN #24] JWT hiển thị + lưu localStorage
   [VULN #25] token theft: exfil tới collector, attacker view GET /api/telemetry
   [VULN #26] session hijack: copy cookie dùng từ máy khác */
export default function Sessions() {
  const [dump, setDump] = useState({});
  const [telemetry, setTelemetry] = useState("");
  const [ckName, setCkName] = useState("vulnpc_prefs");
  const [ckVal, setCkVal] = useState("theme=dark");

  async function refresh() {
    setDump({
      localStorage: LS.all(),
      sessionStorage: SS.all(),
      cookies: readAllCookies(),
      windowGlobals: (window.VULN_CONFIG && "VULN_CONFIG có API keys") || null,
    });
  }
  useEffect(() => {
    refresh();
  }, []);

  async function stealTokens() {
    await exfiltrate({
      src: "sessions-page",
      kind: "manual-exfil",
      jwt: LS.get("vulnshop_jwt"),
      cookies: readAllCookies(),
      localStorageKeys: Object.keys(LS.all()),
    });
    setTelemetry(JSON.stringify(await fetch("/api/telemetry").then((x) => x.json()), null, 2).slice(0, 8000));
    refresh();
  }

  return (
    <div>
      <h1>🖥 Thiết bị & phiên đăng nhập</h1>

      <div className="card">
        <h3>Lưu cookie cục bộ (#23)</h3>
        <div className="row">
          <input value={ckName} onChange={(e) => setCkName(e.target.value)} />
          <input value={ckVal} onChange={(e) => setCkVal(e.target.value)} style={{ flex: 1 }} />
          <button
            className="primary"
            onClick={() => {
              setInsecureCookie(ckName, ckVal); // không HttpOnly/Secure/SameSite
              refresh();
            }}
          >
            Lưu
          </button>
        </div>
      </div>

      <div className="card">
        <h3>Token theft (#25) — mô phỏng attacker</h3>
        <div className="row">
          <button className="danger" onClick={stealTokens}>
            Exfiltrate loot → /api/telemetry
          </button>
          <button onClick={async () => setTelemetry(JSON.stringify(await fetch("/api/telemetry").then((x) => x.json()), null, 2).slice(0, 8000))}>
            Xem attacker view
          </button>
        </div>
        {telemetry && <pre>{telemetry}</pre>}
      </div>

      <div className="card">
        <h3>Toàn bộ storage trên thiết bị này (#16/#21/#22)</h3>
        <button onClick={refresh}>Refresh</button>
        <pre>{JSON.stringify(dump, null, 2)}</pre>
      </div>

      <div className="card">
        <h3>Hijack phiên (#26)</h3>
        <p className="hint">
          Cookie <code>session</code> (legacy) đọc được bằng <code>document.cookie</code> — copy giá trị rồi gọi{" "}
          <code>/api/legacy/me?session=...</code> từ máy khác → chiếm phiên. Mọi XSS trong shop đều đọc được.
        </p>
      </div>
    </div>
  );
}
