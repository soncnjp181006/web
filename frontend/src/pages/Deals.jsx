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
  const [clipOut, setClipOut] = useState("");

  useEffect(() => {
    api("/api/products/deals").then((r) => setDeals((r.data && r.data.deals) || []));
  }, []);

  /* [VULN #2] reflected */
  const title = params.get("title");

  /* [VULN #57] flash sale countdown -> meta refresh khi URL có ?goto= */
  useEffect(() => {
    const g = params.get("goto");
    if (g) {
      const m = document.createElement("meta");
      m.httpEquiv = "refresh";
      m.content = `5;url=${g}`;
      document.head.appendChild(m);
    }
  }, [params]);

  /* [VULN #48] clipboard copy hijack + paste logger */
  useEffect(() => {
    const onCopy = (e) => {
      e.clipboardData.setData("text/plain", "PCForge SALE! Đăng nhập lại tại https://example.com/phish để nhận mã 50%");
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

  return (
    <div>
      <h1>
        🔥 Deals {title && <span dangerouslySetInnerHTML={{ __html: title }} />}
      </h1>

      <div className="card">
        <h3>Flash sale đếm ngược</h3>
        <p className="hint">Flash sale kết thúc sau 5 giây — trang sẽ tự chuyển đến trang deals chính.</p>
      </div>

      <div className="card">
        <h3>Đối tác khuyến mãi</h3>
        <div className="row">
          {/* [VULN #32] open redirect qua server */}
          <a href={`/api/net/redirect?url=${encodeURIComponent("https://example.com/partner")}`} target="_blank" rel="noreferrer">
            <button>Mainboard Week</button>
          </a>
          {/* [VULN #45] target=_blank không rel */}
          <a href="/assets-lab/tabnab.html" target="_blank">
            <button>Trang đối tác</button>
          </a>
          <a href="/assets-lab/tabnab.html" target="_blank" rel="noopener noreferrer">
            <button>Chính sách bảo hành đối tác</button>
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
        <textarea placeholder="paste vào đây để thấy bị log" rows={2} style={{ width: "100%" }} />
        <pre>{clipOut || "(chưa có sự kiện copy/paste)"}</pre>
      </div>
    </div>
  );
}
