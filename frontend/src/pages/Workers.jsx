import React, { useEffect, useState } from "react";

/* [VULN #39] Web Worker created from user code (Blob) - runs attacker JS,
   can exfiltrate, block, and even import more code.
   [VULN #40] Service Worker hijack: register ANY same-origin script
   (chained with unrestricted upload -> /uploads/evil-sw.js). */
export default function Workers() {
  const [code, setCode] = useState("postMessage('hello from worker, navigator.userAgent=' + navigator.userAgent)");
  const [workerOut, setWorkerOut] = useState("");
  const [swPath, setSwPath] = useState("/sw-demo.js");
  const [swStatus, setSwStatus] = useState("chưa đăng ký");
  const [worker, setWorker] = useState(null);

  useEffect(() => () => worker && worker.terminate(), [worker]);

  function runWorker() {
    // [VULN #39] Blob worker from arbitrary user code
    const blob = new Blob([code], { type: "application/javascript" });
    const url = URL.createObjectURL(blob);
    const w = new Worker(url);
    w.onmessage = (e) => setWorkerOut(String(e.data).slice(0, 4000));
    w.onerror = (e) => setWorkerOut("worker error: " + e.message);
    setWorker(w);
  }

  async function runWorkerImport() {
    // [VULN #39][#32] worker + dynamic import of attacker URL (dep injection chain)
    const c = `import("/uploads/${swPath.replace(/^\//, "")}").then(m => postMessage("imported: " + JSON.stringify(Object.keys(m)))).catch(e => postMessage("import failed: " + e.message));`;
    const blob = new Blob([c], { type: "application/javascript" });
    const w = new Worker(URL.createObjectURL(blob));
    w.onmessage = (e) => setWorkerOut(String(e.data));
    setWorker(w);
  }

  /* [VULN #40] register a service worker from user-supplied path */
  async function registerSW() {
    if (!("serviceWorker" in navigator)) {
      setSwStatus("browser không hỗ trợ serviceWorker (cần https + secure context)");
      return;
    }
    try {
      const reg = await navigator.serviceWorker.register(swPath, { scope: "/" });
      setSwStatus(`ĐÃ ĐĂNG KÝ: ${reg.scope} — mọi fetch của app giờ đi qua script này (xem /api/telemetry)`);
    } catch (e) {
      setSwStatus("register failed: " + e.message + " (SW phải cùng origin; dùng /sw-demo.js hoặc upload 1 file .js rồi dùng /uploads/<name>.js)");
    }
  }

  async function unregisterSW() {
    const regs = await navigator.serviceWorker.getRegistrations();
    await Promise.all(regs.map((r) => r.unregister()));
    setSwStatus(`unregistered ${regs.length} SW`);
  }

  return (
    <div>
      <h1>Worker & Service Worker lab</h1>

      <div className="card">
        <h2>Web Worker từ code người dùng (#39)</h2>
        <div className="row">
          <textarea rows={3} value={code} onChange={(e) => setCode(e.target.value)} style={{ flex: 1 }} />
        </div>
        <div className="row">
          <button className="primary" onClick={runWorker}>
            Run worker (Blob)
          </button>
          <button className="danger" onClick={runWorkerImport}>
            Worker + dynamic import từ /uploads (chain #32)
          </button>
          <button onClick={() => worker && worker.terminate()}>Terminate</button>
        </div>
        <p className="hint">
          Worker chạy ngoài main thread nhưng vẫn cùng origin: đọc được fetch/XHR, importScripts, thậm chí{" "}
          <code>postMessage</code> data ra nơi khác. Payload mẫu exfil:{" "}
          <code>{"fetch('/api/telemetry',{method:'POST',body:document.cookie})"}</code> (worker không thấy document —
          nhưng thấy fetch/token nếu page gửi qua).
        </p>
        <pre>{workerOut || "(chưa chạy)"}</pre>
      </div>

      <div className="card">
        <h2>Service Worker hijacking (#40)</h2>
        <div className="row">
          <input value={swPath} onChange={(e) => setSwPath(e.target.value)} style={{ flex: 1 }} />
          <button className="danger" onClick={registerSW}>
            Register SW
          </button>
          <button onClick={unregisterSW}>Unregister tất cả</button>
        </div>
        <p className="hint">
          SW hợp lệ phải cùng origin — kết hợp unrestricted upload (#25): upload <code>evil-sw.js</code> (nội dung
          copy từ <code>/sw-demo.js</code>) rồi register <code>/uploads/evil-sw.js</code> → toàn bộ request của app
          bị MITM, body API (kèm token) báo về <code>/api/telemetry</code>. SW tồn tại qua restart tab → persistence.
        </p>
        <pre>{swStatus}</pre>
      </div>
    </div>
  );
}
