import React, { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import api from "../api.js";

/* So sánh sản phẩm.
   [VULN #58] ?rows= render DOM hàng loạt -> block main thread (DOM DoS, share-able URL)
   [VULN #59] ReDoS client: regex kiểm tra "mã serial" chạy trên main thread
   [VULN #43] so sánh hiển thị cả internal_cost */
export default function Compare() {
  const [params, setParams] = useSearchParams();
  const ids = (params.get("ids") || "6,8,9").split(",").filter(Boolean);
  const [products, setProducts] = useState([]);
  const [rows, setRows] = useState(params.get("rows") || "20000");
  const [serial, setSerial] = useState("aaaaaaaaaaaaaaaaaaaaaaaaab");
  const [redosOut, setRedosOut] = useState("(bấm để test — tab có thể đơ vài chục giây)");
  const [bombMs, setBombMs] = useState("");

  useEffect(() => {
    Promise.all(ids.map((id) => api(`/api/products/${id}`).then((r) => r.data.product).catch(() => null))).then((ps) =>
      setProducts(ps.filter(Boolean))
    );
  }, [params]);

  /* [VULN #58] DOM bomb */
  function domBomb() {
    const n = parseInt(rows || "0", 10);
    if (!confirm(`Render ${n} hàng sẽ đơ tab. Chạy?`)) return;
    const t0 = performance.now();
    let html = "";
    for (let i = 0; i < n; i++) html += `<div class="hint">row ${i}: VulnPC config line</div>`;
    document.getElementById("bomb-out").innerHTML = html;
    setBombMs(`Render x${n} trong ${Math.round(performance.now() - t0)}ms — main thread block suốt thời gian đó`);
  }

  /* [VULN #59] client ReDoS */
  function runRedos() {
    const t0 = performance.now();
    const matched = /^(a|a?)+$/.test(serial);
    setRedosOut(`matched=${matched} sau ${Math.round(performance.now() - t0)}ms (regex /^(a|a?)+$/ trên main thread)`);
  }

  return (
    <div>
      <h1>So sánh sản phẩm</h1>
      <div className="card">
        <div className="row">
          <input
            defaultValue={params.get("ids") || "6,8,9"}
            placeholder="ids: 6,8,9"
            style={{ flex: 1 }}
            onKeyDown={(e) => e.key === "Enter" && setParams({ ids: e.target.value })}
          />
          <button className="primary" onClick={(e) => setParams({ ids: e.target.previousSibling.value })}>
            So sánh
          </button>
        </div>
      </div>

      {products.length > 0 && (
        <div className="card">
          <table>
            <thead>
              <tr>
                <th>Thông số</th>
                {products.map((p) => (
                  <th key={p.id}>{p.name}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              <tr>
                <td>Giá</td>
                {products.map((p) => (
                  <td key={p.id}>${p.price}</td>
                ))}
              </tr>
              <tr>
                <td>Giá vốn (#43)</td>
                {products.map((p) => (
                  <td key={p.id} className="hint">
                    ${p.internal_cost}
                  </td>
                ))}
              </tr>
              <tr>
                <td>Specs</td>
                {products.map((p) => (
                  <td key={p.id}>
                    <code>{p.specs}</code>
                  </td>
                ))}
              </tr>
              <tr>
                <td>Stock</td>
                {products.map((p) => (
                  <td key={p.id}>{p.stock}</td>
                ))}
              </tr>
            </tbody>
          </table>
        </div>
      )}

      <div className="card">
        <h3>Thử thách render (#58 DOM DoS)</h3>
        <div className="row">
          <input value={rows} onChange={(e) => setRows(e.target.value)} style={{ width: 120 }} />
          <button className="danger" onClick={domBomb}>
            Render N hàng
          </button>
          <span className="hint">hoặc share URL: /compare?ids=6&rows=300000 — nạn nhân mở là đơ</span>
        </div>
        {bombMs && <p>{bombMs}</p>}
        <div id="bomb-out" style={{ maxHeight: 120, overflow: "auto" }} />
      </div>

      <div className="card">
        <h3>Kiểm tra mã serial khuyến mãi (#59 client ReDoS)</h3>
        <div className="row">
          <input value={serial} onChange={(e) => setSerial(e.target.value)} style={{ flex: 1 }} />
          <button className="danger" onClick={runRedos}>
            Kiểm tra
          </button>
        </div>
        <p className="hint">Regex catastrophic chạy trên main thread — 30×'a'+b ≈ 76s đơ tab.</p>
        <pre>{redosOut}</pre>
      </div>
    </div>
  );
}
