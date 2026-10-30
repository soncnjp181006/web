import React, { useEffect, useMemo, useState } from "react";
import { useLocation } from "react-router-dom";
import _ from "lodash";
import api from "../api.js";

/* Build PC — cấu hình máy theo ý.
   [VULN #31] tóm tắt build render bằng _.template (CSTI)
   [VULN #39] "Benchmark" chạy code người dùng trong Web Worker (Blob)
   [VULN #1/#59] chia sẻ build qua location.hash -> innerHTML (DOM XSS) + DOM clobbering (#6)
   [VULN #60] tổng tiền client tự tính rồi gửi lên server
   [VULN #2] nút "kiểm tra tương thích nâng cao" gọi /api/builds/compat (NoSQL-style) */

const SLOTS = [
  ["cpu", "CPU"],
  ["mainboard", "Mainboard"],
  ["gpu", "VGA"],
  ["ram", "RAM"],
  ["storage", "Ổ cứng"],
  ["psu", "PSU"],
  ["case", "Case"],
];

export default function BuildPC() {
  const location = useLocation();
  const [products, setProducts] = useState([]);
  const [picks, setPicks] = useState({});
  const [tpl, setTpl] = useState("Build của <%= user %>: <%= count %> linh kiện — sẵn sàng chiến!");
  const [benchCode, setBenchCode] = useState("postMessage('Benchmark mô phỏng: ' + 1000 + ' FPS (giả lập trong worker)')");
  const [benchOut, setBenchOut] = useState("");
  const [compatOut, setCompatOut] = useState("");
  const [saved, setSaved] = useState("");
  const [hashHtml, setHashHtml] = useState("");
  const [clobbered, setClobbered] = useState(false);
  const [worker, setWorker] = useState(null);

  useEffect(() => {
    api("/api/products").then((r) => setProducts((r.data && r.data.products) || []));
  }, []);

  // [VULN #1/#6/#59] nhập build từ link: #<JSON hoặc payload> -> innerHTML khi safe-mode bị clobber
  useEffect(() => {
    const raw = decodeURIComponent(location.hash.slice(1));
    setHashHtml(raw);
    let cfg = window.config;
    if (!cfg) {
      const el = document.getElementById("config");
      if (el) cfg = { version: el.getAttribute("name"), allow: false };
    }
    const safeMode = !(cfg && cfg.allow);
    setClobbered(!safeMode);
    if (raw && !safeMode) {
      const out = document.getElementById("import-out");
      if (out) out.innerHTML = raw; // XSS sink
    }
  }, [location.hash]);

  const byCat = useMemo(() => {
    const g = {};
    products.forEach((p) => {
      (g[p.category] = g[p.category] || []).push(p);
    });
    return g;
  }, [products]);

  const chosen = SLOTS.map(([cat]) => byCat[cat]?.find((p) => p.id === picks[cat])).filter(Boolean);
  const total = chosen.reduce((s, p) => s + Number(p.price), 0);

  /* [VULN #60] tổng client tự tính/giảm */
  const [discount, setDiscount] = useState(0);
  const finalTotal = total * (1 - Number(discount || 0) / 100);

  /* [VULN #31] CSTI: template do người dùng */
  function renderSummary() {
    try {
      return _.template(tpl)({ user: "bạn", count: chosen.length, total: finalTotal.toFixed(2) });
    } catch (e) {
      return `<span class="err">template error: ${_.escape(e.message)}</span>`;
    }
  }

  /* [VULN #39] Web Worker từ Blob chứa code người dùng */
  function runBenchmark() {
    const blob = new Blob([benchCode], { type: "application/javascript" });
    const w = new Worker(URL.createObjectURL(blob));
    w.onmessage = (e) => setBenchOut("worker → " + String(e.data).slice(0, 2000));
    w.onerror = (e) => setBenchOut("worker error: " + e.message);
    setWorker(w);
  }

  /* [VULN #2] compat engine NoSQL-style */
  async function checkCompat() {
    const r = await api("/api/builds/compat", { body: picks.cpu ? { name: { $ne: null } } : {} });
    setCompatOut(JSON.stringify(r.data, null, 1).slice(0, 3000));
  }

  async function saveBuild() {
    const r = await api("/api/builds", {
      body: {
        name: `Build ${chosen.length} món`,
        config: picks,
        total: finalTotal, // [VULN #60] client gửi tổng
      },
    });
    setSaved(JSON.stringify(r.data, null, 2));
  }

  return (
    <div>
      <h1>🛠 Build PC theo yêu cầu</h1>
      <p className="hint">
        Chọn linh kiện → hệ thống cảnh báo tương thích → lưu build. Chia sẻ build qua link{" "}
        <code>#&lt;cấu hình&gt;</code> — trang nhập dùng innerHTML + safe-mode có thể bị DOM clobbering (#6/#59).
      </p>

      {SLOTS.map(([cat, label]) => (
        <div className="card" key={cat}>
          <h3>{label}</h3>
          <div className="row">
            {(byCat[cat] || []).map((p) => (
              <button
                key={p.id}
                className={picks[cat] === p.id ? "primary" : ""}
                onClick={() => setPicks({ ...picks, [cat]: p.id })}
              >
                {p.name} · ${p.price}
              </button>
            ))}
          </div>
        </div>
      ))}

      <div className="card">
        <h2>Tóm tắt cấu hình</h2>
        <ul>
          {chosen.map((p) => (
            <li key={p.id}>
              {p.name} — <b>${p.price}</b>
            </li>
          ))}
        </ul>
        <div className="row">
          <label>
            Giảm giá client (%):{" "}
            <input value={discount} onChange={(e) => setDiscount(e.target.value)} style={{ width: 80 }} />
          </label>
          <h3>
            Tổng gửi lên server: <span className="price-big">${finalTotal.toFixed(2)}</span> <span className="hint">(#60 — server tin)</span>
          </h3>
        </div>
        <div className="row" style={{ width: "100%" }}>
          <input value={tpl} onChange={(e) => setTpl(e.target.value)} style={{ flex: 1 }} />
        </div>
        <p className="hint">
          CSTI (#31): <code>&lt;%= constructor.constructor("alert(document.domain)")() %&gt;</code>
        </p>
        <div dangerouslySetInnerHTML={{ __html: String(renderSummary()) }} />
        <div className="row" style={{ marginTop: 10 }}>
          <button className="primary" onClick={saveBuild}>
            💾 Lưu build
          </button>
          <button onClick={checkCompat}>Kiểm tra tương thích (NoSQL #2)</button>
          <a href={window.location.pathname + "#"} onClick={(e) => e.preventDefault()} style={{ display: "none" }} />
          <a
            href={`/build#${encodeURIComponent(
              '<form id=config><input name=allow></form><img src=x onerror=alert("build-xss")>'
            )}`}
          >
            <button className="danger">Mở link "chia sẻ build" (DOM XSS demo)</button>
          </a>
        </div>
        {saved && <pre>{saved}</pre>}
        {compatOut && <pre>{compatOut}</pre>}
      </div>

      <div className="card">
        <h3>⚡ Benchmark build (Web Worker #39)</h3>
        <p className="hint">
          Code chạy trong Worker tạo từ Blob — ngoài main thread nhưng cùng origin (fetch được, import được).
        </p>
        <textarea rows={2} value={benchCode} onChange={(e) => setBenchCode(e.target.value)} style={{ width: "100%" }} />
        <div className="row">
          <button className="primary" onClick={runBenchmark}>
            Chạy benchmark
          </button>
          <button onClick={() => worker && worker.terminate()}>Dừng worker</button>
        </div>
        {benchOut && <pre>{benchOut}</pre>}
      </div>

      <div className="card">
        <h3>📥 Nhập build từ link chia sẻ</h3>
        <p className="hint">
          Hash được decode và đưa vào innerHTML khi safe-mode tắt. Payload clobber:{" "}
          <code>&lt;form id=config&gt;&lt;input name=allow&gt;&lt;img src=x onerror=alert(1)&gt;</code>
        </p>
        <p>
          safe-mode: {clobbered ? <b className="err">BỊ CLOBBER — hash vào innerHTML</b> : <span className="hint">bật</span>}
        </p>
        <div id="import-out" className="comment" />
      </div>
    </div>
  );
}
