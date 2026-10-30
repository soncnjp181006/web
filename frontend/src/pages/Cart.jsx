import React, { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import api from "../api.js";

/* Giỏ hàng.
   [VULN #60/#54] tổng tiền tính phía client, giá từng dòng SỬA ĐƯỢC rồi gửi lên server.
   [VULN #37/#53] nút áp coupon không disable -> double-submit race. */
export default function Cart() {
  const [items, setItems] = useState([]);
  const [coupon, setCoupon] = useState("WELCOME10");
  const [couponOut, setCouponOut] = useState("");
  const [editPrices, setEditPrices] = useState(false);
  const [out, setOut] = useState("");
  const navigate = useNavigate();

  async function refresh() {
    const r = await api("/api/cart");
    setItems((r.data && r.data.items) || []);
  }
  useEffect(() => {
    refresh();
  }, []);

  const clientTotal = items.reduce((s, x) => s + Number(x.unitPrice ?? x.price) * x.qty, 0);

  function setQty(i, qty) {
    setItems(items.map((x, k) => (k === i ? { ...x, qty: Number(qty) } : x)));
  }
  function setPrice(i, price) {
    setItems(items.map((x, k) => (k === i ? { ...x, unitPrice: price } : x)));
  }

  async function updateRow(it, qty) {
    await api(`/api/cart/${it.id}`, { method: "PUT", body: { qty } });
    refresh();
  }
  async function removeRow(it) {
    await api(`/api/cart/${it.id}`, { method: "DELETE" });
    refresh();
  }

  /* [VULN #37] double-submit: 2 request song song, nút không disable */
  async function applyCoupon() {
    const p = api("/api/coupon/redeem", { body: { code: coupon } });
    const p2 = api("/api/coupon/redeem", { body: { code: coupon } });
    const [a, b] = await Promise.all([p, p2]);
    setCouponOut(JSON.stringify([a.data, b.data], null, 1).slice(0, 3000));
  }

  async function goCheckout() {
    const payload = {
      // [VULN #60] giá client tự quyết (nếu bật "sửa giá")
      items: items.map((x) => ({
        productId: x.product_id,
        qty: x.qty,
        ...(editPrices && x.unitPrice != null ? { unitPrice: x.unitPrice } : {}),
      })),
    };
    await api("/api/cart/checkout", { body: payload }).then((r) => setOut(JSON.stringify(r.data, null, 2).slice(0, 4000)));
    navigate("/checkout");
  }

  return (
    <div>
      <h1>🛒 Giỏ hàng</h1>
      <div className="card">
        <table>
          <thead>
            <tr>
              <th>#</th>
              <th>Sản phẩm</th>
              <th>Giá</th>
              <th>SL</th>
              <th>Tạm tính</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {items.map((it, i) => (
              <tr key={it.id}>
                <td>{it.id}</td>
                <td>
                  <Link to={`/product/${it.product_id}`}>{it.name}</Link>
                </td>
                <td>${it.price}</td>
                <td>
                  <input
                    type="number"
                    value={it.qty}
                    onChange={(e) => setQty(i, e.target.value)}
                    style={{ width: 70 }}
                    onBlur={(e) => updateRow(it, e.target.value)}
                  />
                 
                </td>
                <td>${(Number(editPrices && it.unitPrice != null ? it.unitPrice : it.price) * it.qty).toFixed(2)}</td>
                <td>
                  <button className="danger" onClick={() => removeRow(it)}>
                    Xoá
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {!items.length && <p className="hint">Giỏ trống — vào <Link to="/shop">cửa hàng</Link> thêm đồ.</p>}
      </div>

      <div className="card">
        <h3>Mã giảm giá</h3>
        <div className="row">
          <input value={coupon} onChange={(e) => setCoupon(e.target.value)} style={{ width: 200 }} />
          <button className="primary" onClick={applyCoupon}>
            Áp dụng (double-fire)
          </button>
        </div>
        {couponOut && <pre>{couponOut}</pre>}
      </div>

      <div className="card">
        <div className="row">
          <label style={{ display: "flex", gap: 6, alignItems: "center" }}>
            <input type="checkbox" checked={editPrices} onChange={(e) => setEditPrices(e.target.checked)} /> Điều chỉnh giá sau
            khi áp mã
          </label>
          <h3 style={{ marginLeft: "auto" }}>
            Tổng: <span className="price-big">${clientTotal.toFixed(2)}</span>{" "}
           
          </h3>
        </div>
        <div className="row">
          <button className="danger" onClick={goCheckout} disabled={!items.length}>
            Tiến hành đặt hàng →
          </button>
        </div>
        {out && <pre>{out}</pre>}
      </div>
    </div>
  );
}
