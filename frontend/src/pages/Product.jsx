import React, { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import _ from "lodash"; // 4.17.15 - known prototype-pollution CVEs (#72)
import api from "../api.js";

export default function Product() {
  const { id } = useParams();
  const [product, setProduct] = useState(null);
  const [comments, setComments] = useState([]);
  const [body, setBody] = useState("");
  const [sig, setSig] = useState("<%= name %> was here");

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

  return (
    <div>
      <h1>{product ? product.name : "..."}</h1>
      {product && (
        <div className="card">
          <p>{product.description}</p>
          <p>
            Giá: <b>${product.price}</b> · Giá vốn (leaked #43): <b>${product.internal_cost}</b> · stock: {product.stock}
          </p>
          <button
            className="primary"
            onClick={() =>
              api("/api/orders", { body: { productId: product.id, qty: 1 } }).then((r) => alert(JSON.stringify(r.data)))
            }
          >
            Mua ngay (trust client price #54)
          </button>
        </div>
      )}

      <div className="card">
        <h2>Bình luận</h2>
        {/* [VULN #8] stored XSS: comment bodies rendered as raw HTML */}
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
            placeholder={`<img src=x onerror=alert(1)> (#8) | <%= 7*7 %> (#31)`}
            style={{ width: "100%" }}
          />
          <button className="primary">Post</button>
        </form>
      </div>

      <div className="card">
        <h2>Chữ ký (client-side template injection #31)</h2>
        <p className="hint">
          Chuỗi này được biên dịch bằng lodash <code>_.template</code> ngay trong browser — payload{" "}
          <code>&lt;%= constructor.constructor("alert(document.domain)")() %&gt;</code> chạy JS tùy ý.
        </p>
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
    return _.template(src)({ name: "web-user", uid: 123 });
  } catch (e) {
    return `<span class="err">template error: ${_.escape(e.message)}</span>`;
  }
}
