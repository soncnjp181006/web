import React, { useEffect, useRef, useState } from "react";

export default function Chat() {
  const [msgs, setMsgs] = useState([]);
  const [text, setText] = useState("");
  const [status, setStatus] = useState("connecting...");
  const wsRef = useRef(null);

  useEffect(() => {
    // [VULN #60] WS endpoint without origin check / auth.
    const url = import.meta.env.VITE_WS_URL || `${location.protocol === "https:" ? "wss" : "ws"}://${location.host}/ws/chat`;
    let ws;
    try {
      ws = new WebSocket(url);
    } catch (e) {
      setStatus("WS error: " + e.message);
      return;
    }
    wsRef.current = ws;
    ws.onopen = () => {
      setStatus("connected");
      // [VULN #38][#25] client leaks stored credentials/token over the
      // unauthenticated, origin-unchecked WebSocket on connect
      const jwt = localStorage.getItem("vulnshop_jwt");
      const creds = localStorage.getItem("vulnshop_creds");
      if (jwt || creds) {
        ws.send(JSON.stringify({ system: true, text: `[leak] client token/creds broadcast: ${(jwt || creds).slice(0, 60)}...` }));
      }
    };
    ws.onclose = () => setStatus("disconnected");
    ws.onmessage = (ev) => {
      // [VULN #8][#60] messages rendered as raw HTML -> XSS via WebSocket
      setMsgs((m) => [...m, ev.data]);
    };
    return () => ws.close();
  }, []);

  return (
    <div>
      <h1>VulnChat</h1>
      <div className="card">
        <p className="hint">
          status: {status} · không có auth, không kiểm tra Origin (cross-site WebSocket hijacking #60), tin nhắn
          render bằng innerHTML → gửi <code>&lt;img src=x onerror=alert(1)&gt;</code> để XSS tất cả clients.
        </p>
        <div style={{ maxHeight: 320, overflow: "auto" }}>
          {msgs.map((m, i) => (
            <div className="comment" key={i} dangerouslySetInnerHTML={{ __html: m }} />
          ))}
        </div>
        <div className="row">
          <input
            value={text}
            onChange={(e) => setText(e.target.value)}
            style={{ flex: 1 }}
            placeholder="<img src=x onerror=alert(1)>"
          />
          <button
            className="primary"
            onClick={() => {
              if (wsRef.current && wsRef.current.readyState === 1) wsRef.current.send(text);
              setText("");
            }}
          >
            Send
          </button>
        </div>
      </div>
    </div>
  );
}
