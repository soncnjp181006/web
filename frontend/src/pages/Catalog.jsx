import React, { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import api from "../api.js";

/* Cửa hàng: danh mục PC & linh kiện.
   [VULN #1] ?q= và ?category= đi thẳng vào raw SQL (backend concat).
   [VULN #2] reflected XSS: q render lại bằng raw HTML.
   [VULN #2-NoSQL] bộ lọc nâng cao gửi JSON thẳng vào /api/products/filter. */
const CATS = [
  ["", "Tất cả"],
  ["pc", "PC dựng sẵn"],
  ["cpu", "CPU"],
  ["gpu", "VGA"],
  ["ram", "RAM"],
  ["mainboard", "Mainboard"],
  ["storage", "Ổ cứng"],
  ["psu", "PSU"],
  ["case", "Case"],
  ["monitor", "Màn hình"],
  ["peripheral", "Gear"],
];

export default function Catalog() {
  const [params, setParams] = useSearchParams();
  const q = params.get("q") || "";
  const category = params.get("category") || "";
  const sort = params.get("sort") || "id";
  const [products, setProducts] = useState([]);
  const [raw, setRaw] = useState(null);
  const [filterJson, setFilterJson] = useState('{"price":{"$lt":600}}');
  const [filterOut, setFilterOut] = useState("");

  useEffect(() => {
    // [VULN #1] mọi tham số được nối thẳng vào SQL phía server
    const url = `/api/products/search?q=${encodeURIComponent(q)}${category ? `&category=${encodeURIComponent(category)}` : ""}${sort !== "id" ? `&sortcol=${encodeURIComponent(sort)}` : ""}`;
    api(url).then((r) => {
      setRaw(r.data);
      setProducts((r.data && r.data.rows) || []);
    });
  }, [q, category, sort]);

  async function runNosqlFilter() {
    try {
      const body = JSON.parse(filterJson);
      const r = await api("/api/products/filter", { body });
      setFilterOut(JSON.stringify(r.data, null, 2).slice(0, 5000));
    } catch (e) {
      setFilterOut("JSON lỗi: " + e.message);
    }
  }

  return (
    <div>
      <h1>Cửa hàng {category && <span className="hint">— danh mục {category}</span>}</h1>

      <div className="card">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            const v = new FormData(e.target).get("q");
            setParams(v ? { q: v, ...(category && { category }) } : { ...(category && { category }) });
          }}
          className="row"
        >
          <input name="q" defaultValue={q} placeholder="Tìm kiếm sản phẩm..." style={{ flex: 1 }} />
          <select
            value={sort}
            onChange={(e) => setParams({ ...(q && { q }), ...(category && { category }), sort: e.target.value })}
          >
            <option value="id">Mới nhất</option>
            <option value="price">Giá ↑</option>
            <option value="price DESC">Giá ↓</option>
            <option value="name">Tên A-Z</option>
          </select>
          <button className="primary">Lọc</button>
        </form>
        <div className="cats" style={{ marginTop: 10 }}>
          {CATS.map(([c, label]) => (
            <Link key={c || "all"} to={c ? `/shop?category=${c}` : "/shop"}>
              {label}
            </Link>
          ))}
        </div>
        {q && (
          <p>
            Kết quả cho:{" "}
            {/* [VULN #2] reflected XSS — q in thẳng HTML */}
            <b style={{ color: "#f85149" }} dangerouslySetInnerHTML={{ __html: q }} />
          </p>
        )}
        <p className="hint">
          SQLi (#1): thử <code>%' OR 1=1--</code> hoặc{" "}
          <code>%' UNION SELECT 1, email, password_hash, 'x', 'user', 0, 0, 0, FALSE, 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x' FROM users--</code>{" "}
          (16 cột). ORDER BY injection: sort=price;SELECT pg_sleep(5)--
        </p>
      </div>

      <div className="grid">
        {products.map((p) => (
          <div className="card" key={p.id}>
            <b>{p.name}</b>
            <p className="hint">
              {p.brand} · {p.category} {p.featured ? "· ⭐" : ""} {p.stock <= 5 ? "· 🔥 sắp hết" : ""}
            </p>
            <div className="row">
              <span className="price-big">${p.price}</span>
              <Link to={`/product/${p.id}`}>
                <button>Chi tiết</button>
              </Link>
            </div>
          </div>
        ))}
      </div>

      <div className="card">
        <h3>Bộ lọc nâng cao (Power user) — NoSQL-style #2</h3>
        <p className="hint">
          Gửi JSON filter thẳng vào engine. Payload: <code>{"{\"price\":{\"$lt\":600}}"}</code>,{" "}
          <code>{"{\"category\":\"gpu\"}"}</code>, <code>{"{\"$where\":\"this.stock < 10\"}"}</code> (eval RCE #2/#27).
        </p>
        <div className="row" style={{ width: "100%" }}>
          <textarea rows={2} value={filterJson} onChange={(e) => setFilterJson(e.target.value)} style={{ flex: 1 }} />
          <button className="primary" onClick={runNosqlFilter}>
            Áp dụng
          </button>
        </div>
        {filterOut && <pre>{filterOut}</pre>}
      </div>

      {raw && raw.sql && (
        <div className="card">
          <h3>Raw SQL dùng cho query này (info disclosure #43)</h3>
          <pre>{raw.sql}</pre>
        </div>
      )}
    </div>
  );
}
