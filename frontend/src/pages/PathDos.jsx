import React, { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";

/* [VULN #11] client-side path traversal, [#58] DOM-based DoS,
   [#59] client ReDoS. */
export default function PathDos() {
  const [params] = useSearchParams();
  const [page, setPage] = useState("welcome.txt");
  const [out, setOut] = useState("");
  const [count, setCount] = useState("50000");
  const [redosInput, setRedosInput] = useState("aaaaaaaaaaaaaaaaaaaaaaaaab");
  const [redosOut, setRedosOut] = useState("(bấm để freeze tab)");

  /* [VULN #11] viewer fetches a "content file" theo đường dẫn người dùng */
  async function loadPage() {
    setOut("loading...");
    try {
      // sink: user input nối vào path — browser normalization xử lý ../
      const r = await fetch(`./content/${page}`, { credentials: "include" });
      const t = await r.text();
      setOut(`status ${r.status} — url thực tế: ${r.url}\n\n${t.slice(0, 4000)}`);
    } catch (e) {
      setOut("error: " + e.message);
    }
  }

  /* [VULN #58] DOM DoS: render N nodes / innerHTML bomb — block main thread */
  function domBomb() {
    const n = parseInt(count || "0", 10);
    if (!confirm(`Render ${n} DOM nodes sẽ đơ tab vài giây tới vài phút. Chạy?`)) return;
    const start = performance.now();
    let html = "";
    for (let i = 0; i < n; i++) html += `<div class="comment">row ${i}</div>`;
    document.getElementById("dom-bomb-out").innerHTML = html; // innerHTML bomb
    setOut(`DOM bomb x${n} hoàn thành trong ${Math.round(performance.now() - start)}ms (main thread bị block suốt thời gian đó)`);
  }

  /* [VULN #59] client ReDoS: catastrophic regex trên input — freeze tab */
  function runRedos() {
    const start = performance.now();
    const re = /^(a|a?)+$/;
    const matched = re.test(redosInput);
    setRedosOut(`matched=${matched} sau ${Math.round(performance.now() - start)}ms — main thread bị block toàn bộ thời gian đó`);
  }

  // [VULN #58] nữa: query ?rows= render ngay khi mở trang (DoS bằng URL share)
  useEffect(() => {
    const rows = parseInt(params.get("rows") || "0", 10);
    if (rows > 0) {
      let html = "";
      for (let i = 0; i < Math.min(rows, 2_000_000); i++) html += `<div>spam ${i}</div>`;
      document.getElementById("dom-bomb-out").innerHTML = html;
    }
  }, [params]);

  return (
    <div>
      <h1>Path traversal & DoS lab (client)</h1>

      <div className="card">
        <h2>Client-side path traversal (#11)</h2>
        <div className="row">
          <input value={page} onChange={(e) => setPage(e.target.value)} style={{ flex: 1 }} />
          <button className="primary" onClick={loadPage}>
            Load
          </button>
        </div>
        <p className="hint">
          Payload: <code>../index.html</code> (đọc SPA HTML) · <code>../../api/debug/config</code> (normalization
          đưa ra endpoint API!) · <code>..%2f..%2findex.html</code> (encoded). Client build path từ input = attacker
          quyết định path.
        </p>
        <pre>{out || "(chưa load)"}</pre>
      </div>

      <div className="card">
        <h2>DOM-based DoS (#58)</h2>
        <div className="row">
          <input value={count} onChange={(e) => setCount(e.target.value)} style={{ width: 120 }} />
          <button className="danger" onClick={domBomb}>
            Render N nodes
          </button>
          <span className="hint">hoặc mở URL với ?rows=200000 — DoS qua link share</span>
        </div>
        <div id="dom-bomb-out" style={{ maxHeight: 150, overflow: "auto" }} />
      </div>

      <div className="card">
        <h2>Client ReDoS (#59)</h2>
        <div className="row">
          <input value={redosInput} onChange={(e) => setRedosInput(e.target.value)} style={{ flex: 1 }} />
          <button className="danger" onClick={runRedos}>
            Test regex /&#94;(a|a?)+$/
          </button>
        </div>
        <p className="hint">Regex chạy trên main thread → tab đơ tới khi xong. 26-30 ký tự "a"+b = vài giây tới ~76s.</p>
        <pre>{redosOut}</pre>
      </div>
    </div>
  );
}
