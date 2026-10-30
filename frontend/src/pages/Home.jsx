import React, { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import api from "../api.js";

/* Trang chủ VulnPC Shop.
   [VULN #9] banner khuyến mãi đi qua open-redirect endpoint của server.
   [VULN #2] ô tìm kiếm -> reflected XSS ở trang /shop. */
const CATS = [
  ["pc", "🖥 PC dựng sẵn"],
  ["cpu", "🧠 CPU"],
  ["gpu", "🎮 VGA"],
  ["ram", "🧬 RAM"],
  ["mainboard", "🔩 Mainboard"],
  ["storage", "💾 SSD/HDD"],
  ["psu", "🔌 PSU"],
  ["case", "📦 Case"],
  ["monitor", "🖥 Monitor"],
  ["peripheral", "⌨ Gear"],
];

export default function Home() {
  const [deals, setDeals] = useState([]);
  const navigate = useNavigate();

  useEffect(() => {
    api("/api/products/deals").then((r) => setDeals((r.data && r.data.deals) || []));
  }, []);

  return (
    <div>
      <div className="hero">
        <h1>Dựng PC mơ ước của bạn — từ Office tới RTX 4090</h1>
        <p>Trả góp 0% · Bảo hành 36 tháng · Build test trước khi giao · Hỗ trợ trực tuyến 24/7</p>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            const v = new FormData(e.target).get("q");
            navigate(v ? `/shop?q=${encodeURIComponent(v)}` : "/shop");
          }}
          className="row"
        >
          <input name="q" placeholder="Tìm CPU, GPU, PC gaming..." style={{ flex: 1, maxWidth: 520 }} />
          <button className="primary">Tìm kiếm</button>
          <Link to="/build">
            <button type="button">🛠 Tự build PC</button>
          </Link>
        </form>
      </div>

      <div className="cats">
        {CATS.map(([c, label]) => (
          <Link key={c} to={`/shop?category=${c}`}>
            {label}
          </Link>
        ))}
      </div>

      <div className="card">
        <h2>🔥 Deal hot trong ngày</h2>
        <p className="hint">
          Banner đối tác:{" "}
          {/* [VULN #9/#32] redirect qua endpoint server - url không được kiểm tra */}
          <a href={`/api/net/redirect?url=${encodeURIComponent("https://example.com/partner-sale")}`}>
            Sale Mainboard & PSU tại trang đối tác →
          </a>{" "}
          (open redirect #9) · Xem <Link to="/deals">trang Deals</Link>
        </p>
        <div className="grid">
          {deals.map((p) => (
            <div className="card" key={p.id}>
              <b>{p.name}</b>
              <p className="hint">{p.brand} · {p.category}</p>
              <div className="row">
                <span className="price-big">${p.price}</span>
                <Link to={`/product/${p.id}`}>
                  <button>Xem chi tiết</button>
                </Link>
              </div>
            </div>
          ))}
        </div>
      </div>

      <div className="grid">
        {[
          ["🚚", "Giao nhanh 2h", "Nội thành HCM & Hà Nội"],
          ["🛡", "Bảo hành 36 tháng", "RMA online, kỹ thuật viên hỗ trợ qua ticket"],
          ["💳", "Trả góp 0%", "Quẹt thẻ tại cửa hàng hoặc chuyển ví"],
          ["🛠", "Build theo yêu cầu", "Cấu hình tương thích tự kiểm tra"],
        ].map(([icon, t, d]) => (
          <div className="card" key={t}>
            <h3>{icon} {t}</h3>
            <p className="hint">{d}</p>
          </div>
        ))}
      </div>
    </div>
  );
}
