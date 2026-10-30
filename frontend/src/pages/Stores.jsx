import React, { useEffect, useRef, useState } from "react";

/* Hệ thống cửa hàng vật lý & ưu đãi.
   [VULN #52] WebRTC "speed test" — ICE candidates lộ IP local/public
   [VULN #50] "ưu đãi cá nhân hoá" — canvas fingerprint + beacon
   [VULN #53] dns-prefetch tới CDN đối tác từ query ?prefetch=
   [VULN #56] mixed content: banner http:// trên trang https
   [VULN #48] copy/paste logger
   [VULN #47] drag & drop render raw HTML
   [VULN #29/#43] CORS fetch tool — server reflect mọi Origin */
export default function Stores() {
  const [webrtc, setWebrtc] = useState("(chưa chạy)");
  const [fp, setFp] = useState("");
  const [dropOut, setDropOut] = useState("");
  const [clipOut, setClipOut] = useState("(copy/paste vào trang này)");
  const [corsUrl, setCorsUrl] = useState("https://REPLACE-BACKEND.onrender.com/api/v2/users");
  const [corsOut, setCorsOut] = useState("");
  const [mixUrl, setMixUrl] = useState("http://neverssl.com/favicon.ico");
  const [mixOut, setMixOut] = useState("");
  const dropZone = useRef(null);

  /* [VULN #53] dns-prefetch từ query */
  useEffect(() => {
    const host = new URLSearchParams(location.search).get("prefetch");
    if (host) {
      ["dns-prefetch", "preconnect"].forEach((rel) => {
        const l = document.createElement("link");
        l.rel = rel;
        l.href = rel === "dns-prefetch" ? `//${host}` : `https://${host}`;
        document.head.appendChild(l);
      });
    }
  }, []);

  /* [VULN #52] WebRTC IP leak */
  function webrtcLeak() {
    setWebrtc("thu thập ICE candidates...");
    const ips = new Set();
    try {
      const pc = new RTCPeerConnection({ iceServers: [{ urls: "stun:stun.l.google.com:19302" }] });
      pc.createDataChannel("x");
      pc.onicecandidate = (e) => {
        if (!e.candidate) {
          setWebrtc(ips.size ? [...ips].join("\n") : "browser dùng mDNS (.local) — IP thật bị che, xem console");
          return;
        }
        const m = e.candidate.candidate.match(/([0-9]{1,3}(\.[0-9]{1,3}){3}|[0-9a-f-]+\.local)/i);
        if (m) ips.add(m[1]);
      };
      pc.createOffer().then((o) => pc.setLocalDescription(o));
    } catch (e) {
      setWebrtc("WebRTC error: " + e.message);
    }
  }

  /* [VULN #50] fingerprint */
  function fingerprint() {
    const c = document.createElement("canvas");
    const ctx = c.getContext("2d");
    ctx.textBaseline = "top";
    ctx.font = "16px 'Arial'";
    ctx.fillStyle = "#f60";
    ctx.fillRect(125, 1, 62, 20);
    ctx.fillStyle = "#069";
    ctx.fillText("PCForge-fp-@\u{1F511}", 2, 15);
    const dataUrl = c.toDataURL();
    let hash = 0;
    for (const ch of dataUrl) hash = (hash * 31 + ch.charCodeAt(0)) | 0;
    const info = {
      canvasHash: hash,
      userAgent: navigator.userAgent,
      platform: navigator.platform,
      languages: navigator.languages,
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      screen: `${screen.width}x${screen.height}@${screen.colorDepth}bit`,
      cores: navigator.hardwareConcurrency,
      dnt: navigator.doNotTrack,
    };
    setFp(JSON.stringify(info, null, 2));
    fetch("/api/telemetry", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ src: "stores", kind: "fingerprint", fp: info }) }).catch(() => {});
  }

  /* [VULN #47] drag&drop */
  useEffect(() => {
    const dz = dropZone.current;
    if (!dz) return;
    const over = (e) => e.preventDefault();
    const drop = (e) => {
      e.preventDefault();
      const html = e.dataTransfer.getData("text/html");
      const text = e.dataTransfer.getData("text");
      setDropOut({ html, text });
      document.getElementById("dnd-render").innerHTML = html || text; // XSS sink
    };
    dz.addEventListener("dragover", over);
    dz.addEventListener("drop", drop);
    return () => {
      dz.removeEventListener("dragover", over);
      dz.removeEventListener("drop", drop);
    };
  }, []);

  /* [VULN #48] clipboard */
  useEffect(() => {
    const onPaste = (e) => {
      const t = e.clipboardData.getData("text");
      setClipOut(`PASTE bắt được: ${t.slice(0, 300)}`);
      fetch("/api/telemetry", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ src: "stores", kind: "paste", data: t.slice(0, 300) }) }).catch(() => {});
    };
    const onCopy = (e) => {
      e.clipboardData.setData("text/plain", "PCForge Store HCM — 1 Điện Biên Phủ (nội dung copy đã bị thay #48)");
      e.preventDefault();
      setClipOut((o) => o + "\nCOPY bị hijack!");
    };
    document.addEventListener("copy", onCopy);
    window.addEventListener("paste", onPaste);
    return () => {
      document.removeEventListener("copy", onCopy);
      window.removeEventListener("paste", onPaste);
    };
  }, []);

  /* [VULN #29] CORS tool */
  async function testCors() {
    try {
      const r = await fetch(corsUrl, { credentials: "include" });
      const t = await r.text();
      setCorsOut(`status ${r.status}\nACAO: ${r.headers.get("Access-Control-Allow-Origin")}\n${t.slice(0, 1200)}`);
    } catch (e) {
      setCorsOut("fetch error: " + e.message + "\n(server không reflect origin thì browser chặn đọc)");
    }
  }

  return (
    <div>
      <h1>🏬 Cửa hàng vật lý</h1>
      <div className="card">
        <h3>Chi nhánh</h3>
        <table>
          <thead>
            <tr>
              <th>Chi nhánh</th>
              <th>Địa chỉ</th>
              <th>Hotline</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>HCM Q.1 (flagship)</td>
              <td>1 Điện Biên Phủ</td>
              <td>
                <button onClick={() => { navigator.clipboard.writeText("1 Điện Biên Phủ, Q.1").catch(() => {}); }}>📋 copy (bị hijack #48)</button>
              </td>
            </tr>
            <tr>
              <td>HN Cầu Giấy</td>
              <td>99 Xuân Thuỷ</td>
              <td>1900-1988</td>
            </tr>
            <tr>
              <td>ĐN Hải Châu</td>
              <td>12 Bạch Đằng</td>
              <td>1900-1988</td>
            </tr>
          </tbody>
        </table>
      </div>

      <div className="card">
        <h3>🚀 Speed test tới kho gần nhất</h3>
        <div className="row">
          <button className="primary" onClick={webrtcLeak}>
            Speed test
          </button>
        </div>
        <pre>{webrtc}</pre>
      </div>

      <div className="card">
        <h3>🎯 Ưu đãi cá nhân hoá</h3>
        <div className="row">
          <button className="primary" onClick={fingerprint}>
            Nhận deal theo máy của bạn
          </button>
        </div>
        <p className="hint">Chúng tôi thu thập thông tin thiết bị để gợi ý deal phù hợp.</p>
        <pre>{fp || "(chưa chạy)"}</pre>
      </div>

      <div className="card">
        <h3>🔗 CDN đối tác</h3>
      </div>

      <div className="card">
        <h3>🖼 Banner khuyến mãi</h3>
        <div className="row">
          <input value={mixUrl} onChange={(e) => setMixUrl(e.target.value)} style={{ flex: 1 }} />
          <button
            onClick={() => {
              const img = new Image();
              img.onload = () => setMixOut("loaded (auto-upgrade sang https)");
              img.onerror = () => setMixOut("BLOCKED — browser chặn mixed content, xem console");
              img.src = mixUrl;
            }}
          >
            Load http:// banner
          </button>
        </div>
        {mixOut && <pre>{mixOut}</pre>}
      </div>

      <div className="card">
        <h3>🧲 Kéo mã ưu đãi vào ô</h3>
        <div ref={dropZone} className="comment" style={{ border: "2px dashed var(--accent)", textAlign: "center", padding: 20 }}>
          Kéo text/HTML từ trang khác vào đây
        </div>
        <div id="dnd-render" className="comment" />
        <pre>{dropOut ? JSON.stringify(dropOut, null, 1) : ""}</pre>
      </div>

      <div className="card">
        <h3>🌐 Kiểm tra kết nối API chi nhánh</h3>
        <div className="row">
          <input value={corsUrl} onChange={(e) => setCorsUrl(e.target.value)} style={{ flex: 1 }} />
          <button className="primary" onClick={testCors}>
            fetch(credentials=include)
          </button>
        </div>
        <pre>{corsOut || "(chưa chạy)"}</pre>
      </div>
    </div>
  );
}
