import React, { useEffect, useState } from "react";

/* [VULN #28] postMessage listener WITHOUT origin check:
   any page (popup/iframe) can postMessage into this page and
   - set innerHTML (XSS)
   - mutate app state ("theme"/"config") */
export default function PostMessage() {
  const [received, setReceived] = useState([]);
  const [appliedTheme, setAppliedTheme] = useState("");

  useEffect(() => {
    function onMessage(e) {
      // BUG: no `e.origin` check, no `e.source` check
      setReceived((r) => [
        ...r,
        { origin: e.origin || "(null)", data: typeof e.data === "string" ? e.data : JSON.stringify(e.data) },
      ]);
      if (typeof e.data === "string") {
        // sink 1: render message as HTML
        const out = document.getElementById("pm-out");
        if (out) out.innerHTML = e.data;
        // sink 2: "theme" protocol -> inject CSS from message
        if (e.data.startsWith("theme:")) setAppliedTheme(e.data.slice(6));
      } else if (e.data && e.data.__vulnSetUser) {
        // sink 3: "setUser" protocol -> client-side auth takeover
        localStorage.setItem("vulnshop_user", JSON.stringify(e.data.__vulnSetUser));
      }
    }
    window.addEventListener("message", onMessage);
    return () => window.removeEventListener("message", onMessage);
  }, []);

  return (
    <div>
      <h1>postMessage lab (#28)</h1>
      <div className="card">
        <p className="hint">
          Listener <b>không kiểm tra origin</b>. Mở <a href="/postmessage-sender.html" target="_blank">/postmessage-sender.html</a>{" "}
          và gửi payload. Payload giao thức:
        </p>
        <ul className="hint">
          <li>chuỗi bất kỳ → render innerHTML (XSS)</li>
          <li>
            <code>theme:body&#123;background:red&#125;</code> → inject CSS
          </li>
          <li>
            <code>{'{"__vulnSetUser":{"role":"admin"}}'}</code> → chiếm "tài khoản" client-side
          </li>
        </ul>
        <div id="pm-out" className="comment" />
        {appliedTheme && (
          <style>{appliedTheme}</style>
        )}
        <h2>Received messages</h2>
        <pre>{received.length ? JSON.stringify(received, null, 2) : "(chưa nhận gì)"}</pre>
      </div>
      <div className="card">
        <h2>Tự gửi trong tab này (khai thác không cần trang attacker)</h2>
        <button
          className="danger"
          onClick={() => window.postMessage('<img src=x onerror=alert("postmessage-xss")>', "*")}
        >
          Gửi payload XSS cho chính mình
        </button>
      </div>
    </div>
  );
}
