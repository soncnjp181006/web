import React, { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import api from "../api.js";

/* Checkout: địa chỉ + thanh toán.
   [VULN #49] form thanh toán autocomplete bật + form autofill ẩn dưới màn hình
   [VULN #44] số thẻ gửi đi & lưu plaintext
   [VULN #54/#60] giá client quyết
   [VULN #22] link hóa đơn tải file bằng tham số path -> directory traversal
   [VULN #11] client-side path traversal khi "tải catalog offline" */
export default function Checkout() {
  const [items, setItems] = useState([]);
  const [form, setForm] = useState({ fullName: "", phone: "", address: "", cc: "", note: "" });
  const [coupon, setCoupon] = useState("");
  const [done, setDone] = useState(null);
  const [invoiceFile, setInvoiceFile] = useState("invoice.pdf");
  const [manualPath, setManualPath] = useState("../content/welcome.txt");
  const [out, setOut] = useState("");

  useEffect(() => {
    api("/api/cart").then((r) => setItems((r.data && r.data.items) || []));
  }, []);

  const total = items.reduce((s, x) => s + Number(x.price) * x.qty, 0);

  async function placeOrder(e) {
    e.preventDefault();
    const r = await api("/api/cart/checkout", {
      body: {
        items: items.map((x) => ({ productId: x.product_id, qty: x.qty })), // giá server-side từ client cart (#54)
        coupon,
        cc: form.cc, // [VULN #44] plaintext
        address: form.address,
        phone: form.phone,
        fullName: form.fullName,
      },
    });
    setDone(r.data);
    refresh();
  }
  async function refresh() {
    const r = await api("/api/cart");
    setItems((r.data && r.data.items) || []);
  }

  /* [VULN #11] client build path từ input -> fetch URL bất kỳ (normalization) */
  async function loadManual() {
    const r = await fetch(`./content/${manualPath}`, { credentials: "include" });
    const t = await r.text();
    setOut(`status ${r.status} — url: ${r.url}\n\n${t.slice(0, 1500)}`);
  }

  return (
    <div>
      <h1>Thanh toán</h1>
      <div className="card">
        <h3>Đơn hàng của bạn</h3>
        <table>
          <thead>
            <tr>
              <th>Sản phẩm</th>
              <th>SL</th>
              <th>Đơn giá</th>
              <th>Thành tiền</th>
            </tr>
          </thead>
          <tbody>
            {items.map((x) => (
              <tr key={x.id}>
                <td>{x.name}</td>
                <td>{x.qty}</td>
                <td>${x.price}</td>
                <td>${(Number(x.price) * x.qty).toFixed(2)}</td>
              </tr>
            ))}
            {!items.length && (
              <tr>
                <td colSpan={4} className="hint">
                  Giỏ trống — <Link to="/shop">mua gì đó</Link> đã.
                </td>
              </tr>
            )}
          </tbody>
        </table>
        <h3>
          Tổng: <span className="price-big">${total.toFixed(2)}</span>
        </h3>
      </div>

      <div className="card">
        <h3>Thông tin giao hàng & thanh toán</h3>
        <form onSubmit={placeOrder}>
          <div className="row">
            <div style={{ flex: 1 }}>
              <label>Họ tên</label>
              <input value={form.fullName} onChange={(e) => setForm({ ...form, fullName: e.target.value })} required style={{ width: "100%" }} />
            </div>
            <div style={{ flex: 1 }}>
              <label>Số điện thoại</label>
              <input value={form.phone} onChange={(e) => setForm({ ...form, phone: e.target.value })} style={{ width: "100%" }} />
            </div>
          </div>
          <label>Địa chỉ</label>
          <input value={form.address} onChange={(e) => setForm({ ...form, address: e.target.value })} style={{ width: "100%" }} />
          <div className="row">
            <div style={{ flex: 1 }}>
              <label>Số thẻ</label>
              {/* [VULN #49] autocomplete bật cho thẻ -> browser autofill dữ liệu thật */}
              <input
                value={form.cc}
                onChange={(e) => setForm({ ...form, cc: e.target.value })}
                autoComplete="cc-number"
                placeholder="4111 1111 1111 1111"
                style={{ width: "100%" }}
              />
            </div>
            <div style={{ width: 160 }}>
              <label>Mã giảm giá</label>
              <input value={coupon} onChange={(e) => setCoupon(e.target.value)} style={{ width: "100%" }} />
            </div>
          </div>
          <label>Ghi chú</label>
          <textarea rows={2} value={form.note} onChange={(e) => setForm({ ...form, note: e.target.value })} style={{ width: "100%" }} />
          <button className="danger" disabled={!items.length}>
            ✅ Đặt hàng (${total.toFixed(2)})
          </button>
        </form>
        {/* [VULN #49] offscreen autofill honeypot */}
        <form id="autofill-honey" style={{ position: "absolute", left: "-9999px", top: "-9999px", opacity: 0 }}>
          <input name="name" autoComplete="name" />
          <input name="email" type="email" autoComplete="email" />
          <input name="tel" autoComplete="tel" />
          <input name="cc-name" autoComplete="cc-name" />
          <input name="cc-number" autoComplete="cc-number" />
          <input name="cc-exp" autoComplete="cc-exp" />
        </form>
      </div>

      {done && (
        <div className="card">
          <h2 className="ok">✅ Đặt hàng thành công!</h2>
          <pre>{JSON.stringify(done.orders, null, 2)}</pre>
          <p className="hint">{done.note}</p>
          <h3>Hóa đơn</h3>
          <div className="row">
            <input value={invoiceFile} onChange={(e) => setInvoiceFile(e.target.value)} style={{ flex: 1 }} />
            <a href={`/api/orders/${done.orders?.[0]?.id}/invoice?file=${encodeURIComponent(invoiceFile)}`} target="_blank" rel="noreferrer">
              <button>Tải hóa đơn</button>
            </a>
          </div>
        </div>
      )}

      <div className="card">
        <h3>Tải catalog PDF (bản rút gọn)</h3>
        <div className="row">
          <input value={manualPath} onChange={(e) => setManualPath(e.target.value)} style={{ flex: 1 }} />
          <button className="primary" onClick={loadManual}>
            Tải
          </button>
        </div>
        {out && <pre>{out}</pre>}
      </div>
    </div>
  );
}
