import React, { useEffect, useState } from "react";

/* Trung tâm thông báo (postMessage bridge #28).
   Listener KHÔNG kiểm tra event.origin:
   - chuỗi → innerHTML (XSS)
   - theme:<css> → inject CSS
   - {"__vulnSetUser":{...}} → chiếm "phiên" client-side */
export default function Notifications() {
  const [received, setReceived] = useState([]);
  const [theme, setTheme] = useState("");

  useEffect(() => {
    function onMessage(e) {
      // BUG: không kiểm tra e.origin / e.source
      setReceived((r) => [
        ...r,
        { origin: e.origin || "(null)", data: typeof e.data === "string" ? e.data : JSON.stringify(e.data) },
      ]);
      if (typeof e.data === "string") {
        const out = document.getElementById("notif-out");
        if (out) out.innerHTML = e.data;
        if (e.data.startsWith("theme:")) setTheme(e.data.slice(6));
      } else if (e.data && e.data.__vulnSetUser) {
        localStorage.setItem("vulnshop_user", JSON.stringify(e.data.__vulnSetUser));
      }
    }
    window.addEventListener("message", onMessage);
    return () => window.removeEventListener("message", onMessage);
  }, []);

  return (
    <div>
      <h1>🔔 Thông báo</h1>
      <div className="card">
        <p className="hint">
          Bridge nhận push từ bất kỳ nguồn nào (không kiểm tra origin #28). Giao thức:
        </p>
        <ul className="hint">
          <li>chuỗi bất kỳ → render innerHTML (XSS)</li>
          <li>
            <code>theme:body&#123;background:red&#125;</code> → đổi theme
          </li>
          <li>
            <code>{'{"__vulnSetUser":{"role":"admin"}}'}</code> → chiếm phiên client
          </li>
        </ul>
        <div id="notif-out" className="comment" />
        {theme && <style>{theme}</style>}
        <h2>Received</h2>
        <pre>{received.length ? JSON.stringify(received, null, 2) : "(chưa nhận gì)"}</pre>
      </div>
      <div className="card">
        <button className="danger" onClick={() => window.postMessage('<img src=x onerror=alert("notif-xss")>', "*")}>
          Tự gửi payload XSS
        </button>{" "}
        <a href="/postmessage-sender.html" target="_blank">
          <button>Mở trang sender (tab mới)</button>
        </a>
      </div>
    </div>
  );
}
