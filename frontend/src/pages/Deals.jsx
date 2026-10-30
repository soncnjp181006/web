import React, { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import api from "../api.js";

/* Deals & khuyến mãi.
   [VULN #57] đếm ngược inject <meta refresh> tới ?goto=
   [VULN #32] link đối tác qua open-redirect endpoint
   [VULN #45/#46] target=_blank không rel
   [VULN #48] copy hijack: mọi Ctrl+C trên trang bị thay nội dung
   [VULN #2] ?title= reflected XSS */
export default function Deals() {
  const [params] = useSearchParams();
  const [deals, setDeals] = useState([]);
  const [gotoUrl, setGotoUrl] = useState("https://example.com/flash-sale");
  const [clipOut, setClipOut] = useState("");

  useEffect(() => {
    api("/api/products/deals").then((r) => setDeals((r.data && r.data.deals) || []));
  }, []);

  /* [VULN #2] reflected */
  const title = params.get("title");

  /* [VULN #48] clipboard copy hijack + paste logger */
  useEffect(() => {
    const onCopy = (e) => {
      e.clipboardData.setData("text/plain", "VulnPC SALE! Đăng nhập lại tại https://example.com/phish để nhận mã 50%");
      e.preventDefault();
      setClipOut((o) => o + "\nCOPY bị hijack: clipboard đã bị thay nội dung!");
    };
    const onPaste = (e) => {
      const t = e.clipboardData.getData("text");
      setClipOut((o) => o + `\nPASTE bắt được: ${t.slice(0, 200)}`);
    };
    document.addEventListener("copy", onCopy);
    window.addEventListener("paste", onPaste);
    return () => {
      document.removeEventListener("copy", onCopy);
      window.removeEventListener("paste", onPaste);
    };
  }, []);

  /* [VULN #57] inject meta refresh */
  function injectMeta() {
    const m = document.createElement("meta");
    m.httpEquiv = "refresh";
    m.content = `5;url=${gotoUrl}`;
    document.head.appendChild(m);
    setClipOut((o) => o + `\n<meta refresh 5s → ${gotoUrl}> đã cài vào <head> (#57)`);
  }

  return (
    <div>
      <h1>
        🔥 Deals {title && <span dangerouslySetInnerHTML={{ __html: title }} />}
      </h1>

      <div className="card">
        <h3>Flash sale đếm ngược</h3>
        <p className="hint">
          Trang tự cài <code>&lt;meta http-equiv=refresh content="5;url=..."&gt;</code> (#57) — redirect "cài cắm" phía
          client.
        </p>
        <div className="row">
          <input value={gotoUrl} onChange={(e) => setGotoUrl(e.target.value)} style={{ flex: 1 }} />
          <button className="danger" onClick={injectMeta}>
            Cài meta refresh 5s
          </button>
        </div>
      </div>

      <div className="card">
        <h3>Đối tác khuyến mãi</h3>
        <div className="row">
          {/* [VULN #32] open redirect qua server */}
          <a href={`/api/net/redirect?url=${encodeURIComponent("https://example.com/partner")}`} target="_blank" rel="noreferrer">
            <button>Mainboard Week (open redirect #32)</button>
          </a>
          {/* [VULN #45] target=_blank không rel */}
          <a href="/tabnab-attacker.html" target="_blank">
            <button>Trang đối tác (tabnabbing #45)</button>
          </a>
          <a href="/tabnab-attacker.html" target="_blank" rel="noopener noreferrer">
            <button>Có rel=noopener (an toàn)</button>
          </a>
        </div>
      </div>

      <div className="grid">
        {deals.map((p) => (
          <div className="card" key={p.id}>
            <b>{p.name}</b>
            <p className="hint">{p.brand}</p>
            <div className="row">
              <span className="price-big">${p.price}</span>
              <Link to={`/product/${p.id}`}>
                <button>Mua ngay</button>
              </Link>
            </div>
          </div>
        ))}
      </div>

      <div className="card">
        <h3>🎁 Copy mã giảm giá</h3>
        <p className="hint">
          Thử bôi đen bất kỳ chữ nào rồi Ctrl+C — trang hijack sự kiện copy (#48). Ctrl+V cũng bị log.
        </p>
        <textarea placeholder="paste vào đây để thấy bị log" rows={2} style={{ width: "100%" }} />
        <pre>{clipOut || "(chưa có sự kiện copy/paste)"}</pre>
      </div>
    </div>
  );
}
