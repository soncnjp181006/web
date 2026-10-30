import React, { useEffect, useState } from "react";
import { Link } from "react-router-dom";

/* Trung tâm offline & cache.
   [VULN #40] đăng ký Service Worker theo path người dùng (chain với unrestricted upload)
   [VULN #41] Cache API poisoning: lưu response giả cho URL thật
   [VULN #42] browser cache leakage (public cache + bfcache + autocomplete)
   [VULN #54] MIME sniffing: /uploads-sniff không nosniff */
export default function OfflineCenter() {
  const [swPath, setSwPath] = useState("/sw-demo.js");
  const [swStatus, setSwStatus] = useState("chưa đăng ký");
  const [key, setKey] = useState("/api/v2/users");
  const [poisonBody, setPoisonBody] = useState('{"users":[{"email":"attacker-controlled"}]}');
  const [readOut, setReadOut] = useState("");
  const [cacheList, setCacheList] = useState([]);
  const [sniffName, setSniffName] = useState("shell.html");
  const [sniffOut, setSniffOut] = useState("");

  async function listCache() {
    const cache = await caches.open("pcforge-cache");
    const keys = await cache.keys();
    setCacheList(keys.map((k) => k.url));
  }
  useEffect(() => {
    listCache();
  }, []);

  async function registerSW() {
    if (!("serviceWorker" in navigator)) {
      setSwStatus("browser không hỗ trợ serviceWorker (cần https + secure context)");
      return;
    }
    try {
      const reg = await navigator.serviceWorker.register(swPath, { scope: "/" });
      setSwStatus(`ĐÃ ĐĂNG KÝ: ${reg.scope} — mọi fetch của app đi qua script này (xem /api/telemetry)`);
    } catch (e) {
      setSwStatus("register failed: " + e.message + " (SW phải cùng origin — upload .js rồi dùng /uploads/<name>.js)");
    }
  }
  async function unregisterSW() {
    const regs = await navigator.serviceWorker.getRegistrations();
    await Promise.all(regs.map((r) => r.unregister()));
    setSwStatus(`unregistered ${regs.length} SW`);
  }

  async function poison() {
    const cache = await caches.open("pcforge-cache");
    await cache.put(new Request(key, { credentials: "include" }), new Response(poisonBody, { headers: { "Content-Type": "application/json", "X-Poisoned": "yes" } }));
    await listCache();
  }
  async function readPoisoned() {
    const cache = await caches.open("pcforge-cache");
    const hit = await cache.match(new Request(key, { credentials: "include" }));
    setReadOut(hit ? `CACHED (X-Poisoned: ${hit.headers.get("X-Poisoned")}):\n${(await hit.text()).slice(0, 1200)}` : "không có cache cho key này");
  }
  async function clearCache() {
    await caches.delete("pcforge-cache");
    await listCache();
    setReadOut("");
  }

  function testSniff(kind) {
    setSniffOut(`loading /uploads-sniff/${sniffName} as ${kind}...`);
    if (kind === "img") {
      const i = new Image();
      i.onload = () => setSniffOut(`img OK — browser sniff + render`);
      i.onerror = () => setSniffOut("img failed — thử iframe");
      i.src = `/uploads-sniff/${sniffName}`;
    } else {
      const f = document.createElement("iframe");
      f.src = `/uploads-sniff/${sniffName}`;
      f.style.width = "100%";
      f.style.height = "120px";
      const holder = document.getElementById("sniff-frame");
      holder.innerHTML = "";
      holder.appendChild(f);
      setSniffOut("iframe loaded — file HTML sẽ chạy trong origin app");
    }
  }

  return (
    <div>
      <h1>📴 Offline & Cache center</h1>

      <div className="card">
        <h3>Service Worker offline mode (#40)</h3>
        <div className="row">
          <input value={swPath} onChange={(e) => setSwPath(e.target.value)} style={{ flex: 1 }} />
          <button className="danger" onClick={registerSW}>
            Register SW
          </button>
          <button onClick={unregisterSW}>Unregister tất cả</button>
        </div>
        <pre>{swStatus}</pre>
      </div>

      <div className="card">
        <h3>Cache danh mục offline</h3>
        <div className="row">
          <input value={key} onChange={(e) => setKey(e.target.value)} style={{ flex: 1 }} />
        </div>
        <div className="row" style={{ width: "100%" }}>
          <textarea rows={2} value={poisonBody} onChange={(e) => setPoisonBody(e.target.value)} style={{ flex: 1 }} />
        </div>
        <div className="row">
          <button className="danger" onClick={poison}>
            Lưu cache thử nghiệm
          </button>
          <button className="primary" onClick={readPoisoned}>
            Đọc cache
          </button>
          <button onClick={clearCache}>Clear</button>
        </div>
        <p className="hint">Keys: {cacheList.join(" · ") || "(trống)"}</p>
        <pre>{readOut || "(chưa đọc)"}</pre>
      </div>

      <div className="card">
        <h3>Bộ nhớ đệm trình duyệt</h3>

      </div>

      <div className="card">

      </div>
    </div>
  );
}
