import React, { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import _ from "lodash"; // 4.17.15 - known prototype-pollution CVEs (#72)
import api from "../api.js";

/* Trang chi tiết sản phẩm.
   [VULN #3/#8] review stored XSS (dangerouslySetInnerHTML)
   [VULN #31] chữ ký review biên dịch bằng _.template trong browser (CSTI)
   [VULN #45] tabnabbing | [VULN #46] reverse tabnabbing — link "trang hãng" target=_blank không rel (tabnabbing)
   [VULN #8] client-side template injection (CSTI) ở chữ ký review
   [VULN #54] giá client tự gửi khi add-to-cart */
export default function Product() {
  const { id } = useParams();
  const [product, setProduct] = useState(null);
  const [comments, setComments] = useState([]);
  const [body, setBody] = useState("");
  const [sig, setSig] = useState("<%= name %> đã mua <%= product %>");
  const [added, setAdded] = useState("");

  useEffect(() => {
    api(`/api/products/${id}`).then((r) => setProduct(r.data && r.data.product));
    api(`/api/products/${id}/comments`).then((r) => setComments((r.data && r.data.comments) || []));
  }, [id]);

  async function postComment(e) {
    e.preventDefault();
    await api(`/api/products/${id}/comments`, { body: { author: "web-user", body } });
    setBody("");
    const r = await api(`/api/products/${id}/comments`);
    setComments(r.data.comments || []);
  }

  async function addToCart() {
    const r = await api("/api/cart", { body: { productId: Number(id), qty: 1 } });
    setAdded(JSON.stringify(r.data));
  }

  async function addToWishlist() {
    const r = await api("/api/wishlist", { body: { productId: Number(id), note: "qua trang sản phẩm" } });
    setAdded(JSON.stringify(r.data));
  }

  let specs = {};
  try {
    specs = product && product.specs ? JSON.parse(product.specs) : {};
  } catch {}

  return (
    <div>
      {product && (
        <>
          <h1>{product.name}</h1>
          <div className="row">
            <span className="hint">
              {product.brand} · danh mục <b>{product.category}</b> · Còn {product.stock} cái
              {product.featured ? " · ⭐ Bán chạy" : ""}
            </span>
          </div>
          <div className="card">
            <p>{product.description}</p>
            <p className="price-big">${product.price}</p>
            <div className="row">
              <button className="primary" onClick={addToCart}>
                🛒 Thêm vào giỏ
              </button>
              <button onClick={addToWishlist}>❤ Thêm wishlist</button>
              <Link to="/cart">
                <button>Giỏ hàng →</button>
              </Link>
            </div>
            {added && <pre>{added}</pre>}
          </div>

          <div className="card">
            <h2>Thông số kỹ thuật</h2>
            <table className="spec-table">
              <tbody>
                {Object.entries(specs).map(([k, v]) => (
                  <tr key={k}>
                    <td>{k}</td>
                    <td>
                      <code>{JSON.stringify(v)}</code>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* [VULN #45/#46] target=_blank KHÔNG rel=noopener -> tab mới được window.opener */}
          <div className="card">
            <h3>Liên kết hãng</h3>
            <div className="row">
              <a href="https://example.com/manufacturer" target="_blank">
                Trang hãng {product.brand}
              </a>
              <a href="https://example.com/manufacturer" target="_blank" rel="noopener noreferrer">
                Chính sách bảo hành
              </a>
            </div>
          </div>
        </>
      )}

      <div className="card">
        <h2>Đánh giá ({comments.length})</h2>
        {/* [VULN #3/#8] review render raw HTML — stored XSS */}
        {comments.map((c) => (
          <div className="comment" key={c.id}>
            <b>{c.author}</b>
            <div dangerouslySetInnerHTML={{ __html: c.body }} />
          </div>
        ))}
        <form onSubmit={postComment}>
          <textarea
            rows={2}
            value={body}
            onChange={(e) => setBody(e.target.value)}
            placeholder="Viết đánh giá của bạn..."
            style={{ width: "100%" }}
          />
          <button className="primary">Đăng đánh giá</button>
        </form>
      </div>

      <div className="card">
        <h3>Chữ ký của bạn</h3>
        <div className="row">
          <input value={sig} onChange={(e) => setSig(e.target.value)} style={{ flex: 1 }} />
          <span dangerouslySetInnerHTML={{ __html: String(compileSig(sig)) }} />
        </div>
      </div>
    </div>
  );
}

// [VULN #31] compiles USER INPUT as a client-side template (lodash) -> code exec in browser
function compileSig(src) {
  try {
    return _.template(src)({ name: "web-user", product: "PCForge" });
  } catch (e) {
    return `<span class="err">template error: ${_.escape(e.message)}</span>`;
  }
}
