import React, { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import api from "../api.js";

export default function Home() {
  const [params, setParams] = useSearchParams();
  const q = params.get("q") || "";
  const [products, setProducts] = useState([]);
  const [raw, setRaw] = useState(null);

  useEffect(() => {
    if (q) {
      // [VULN #1] q goes straight into raw SQL on the backend
      api(`/api/products/search?q=${encodeURIComponent(q)}`).then((r) => {
        setRaw(r.data);
        setProducts((r.data && r.data.rows) || []);
      });
    } else {
      api("/api/products").then((r) => setProducts((r.data && r.data.products) || []));
    }
  }, [q]);

  return (
    <div>
      <h1>VulnShop</h1>
      <div className="card">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            const v = new FormData(e.target).get("q");
            setParams(v ? { q: v } : {});
          }}
        >
          <div className="row">
            <input name="q" defaultValue={q} placeholder="search products..." style={{ flex: 1 }} />
            <button className="primary">Search</button>
          </div>
        </form>
        {q && (
          <p className="hint">
            SQLi demo (#1): thử{" "}
            <code>%' OR 1=1--</code> hoặc{" "}
            <code>%' UNION SELECT 1, email, password_hash, 0, 0, 'x' FROM users--</code>
          </p>
        )}
        {/* [VULN #8] reflected XSS: search term rendered as raw HTML */}
        {q && (
          <h3>
            Bạn đã tìm: <span style={{ color: "#f85149" }} dangerouslySetInnerHTML={{ __html: q }} />
          </h3>
        )}
      </div>

      <div className="grid">
        {products.map((p) => (
          <div className="card" key={p.id}>
            <b>{p.name}</b>
            <p className="hint">{p.description}</p>
            <div className="row">
              <span>${p.price}</span>
              <Link to={`/product/${p.id}`}>Xem →</Link>
            </div>
          </div>
        ))}
      </div>

      {raw && (
        <div className="card">
          <h3>Raw SQL response (info disclosure #43)</h3>
          <pre>{JSON.stringify(raw, null, 2)}</pre>
        </div>
      )}
    </div>
  );
}
