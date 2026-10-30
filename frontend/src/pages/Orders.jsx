import React, { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import api from "../api.js";

/* Đơn hàng.
   [VULN #11] IDOR: /orders/:id không check ownership — đổi id là xem đơn người khác.
   [VULN #22] tải hóa đơn: file param traversal.
   [VULN #54] đơn âm tiền (qty âm) hiện rõ ở danh sách.
   RMA -> mở ticket hỗ trợ (flow nối suốt). */
export function OrdersList() {
  const [orders, setOrders] = useState([]);
  const [raceOut, setRaceOut] = useState("");
  useEffect(() => {
    api("/api/orders").then((r) => setOrders((r.data && r.data.orders) || []));
  }, []);
  return (
    <div>
      <h1>Đơn hàng của bạn</h1>
      <div className="card">
        <table>
          <thead>
            <tr>
              <th>#id</th>
              <th>Sản phẩm</th>
              <th>SL</th>
              <th>Đơn giá</th>
              <th>Tổng</th>
              <th>Coupon</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {orders.map((o) => (
              <tr key={o.id}>
                <td>
                  {/* [VULN #11] sequential id -> IDOR playground */}
                  <Link to={`/orders/${o.id}`}>{o.id}</Link>
                </td>
                <td>
                  <Link to={`/product/${o.product_id}`}>#{o.product_id}</Link>
                </td>
                <td className={o.qty < 0 ? "err" : ""}>{o.qty}</td>
                <td>${o.unit_price}</td>
                <td className={Number(o.total) < 0 ? "err" : ""}>${o.total}</td>
                <td>{o.coupon || "-"}</td>
                <td>
                  <Link to={`/orders/${o.id}`}>
                    <button>Chi tiết</button>
                  </Link>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        <p className="hint">
          IDOR (#11): thử <code>/orders/1</code>, <code>/orders/2</code>... để xem đơn của người khác — backend không
          kiểm tra ownership.
        </p>
      </div>

      <div className="card">
        <h3>Đấu coupon không kéo thả (race #53)</h3>
        <p className="hint">Bắn 8 request song song vào coupon PCLOVE50 — check-then-act backend không lock.</p>
        <div className="row">
          <button
            className="danger"
            onClick={() => {
              Promise.all(Array.from({ length: 8 }, () => api("/api/coupon/redeem", { body: { code: "PCLOVE50" } }))).then(
                (rs) => setRaceOut(JSON.stringify(rs.map((r) => r.data), null, 1).slice(0, 3000))
              );
            }}
          >
            Race x8 coupon PCLOVE50
          </button>
        </div>
        {raceOut && <pre>{raceOut}</pre>}
      </div>
    </div>
  );
}

export function OrderDetail() {
  const { id } = useParams();
  const [order, setOrder] = useState(null);
  const [err, setErr] = useState("");
  const [invoiceFile, setInvoiceFile] = useState("invoice.pdf");
  const [rmaReason, setRmaReason] = useState("Máy tự khởi động lại");
  const [rmaOut, setRmaOut] = useState("");

  useEffect(() => {
    api(`/api/orders/${id}`).then((r) => {
      setOrder(r.data && r.data.order);
      setErr(r.ok ? "" : JSON.stringify(r.data));
    });
  }, [id]);

  async function submitRma() {
    const r = await api(`/api/orders/${id}/rma`, { body: { reason: rmaReason } });
    setRmaOut(JSON.stringify(r.data, null, 2));
  }

  return (
    <div>
      <h1>Đơn hàng #{id}</h1>
      <div className="card">
        {err ? <p className="err">{err}</p> : <pre>{JSON.stringify(order, null, 2)}</pre>}
        <p className="hint">Đổi id trên URL để xem đơn của người khác — không check ownership (#11).</p>
      </div>

      <div className="card">
        <h3>⬇ Tải hóa đơn</h3>
        <div className="row">
          <input value={invoiceFile} onChange={(e) => setInvoiceFile(e.target.value)} style={{ flex: 1 }} />
          <a href={`/api/orders/${id}/invoice?file=${encodeURIComponent(invoiceFile)}`} target="_blank" rel="noreferrer">
            <button>Tải</button>
          </a>
        </div>
        <p className="hint">
          Path traversal (#22): <code>../../../../etc/passwd</code> — server join path không sanitize. Response lỗi còn
          lộ đường tuyệt đối (#43).
        </p>
      </div>

      <div className="card">
        <h3>🛡 Bảo hành / RMA (mở ticket hỗ trợ)</h3>
        <div className="row">
          <input value={rmaReason} onChange={(e) => setRmaReason(e.target.value)} style={{ flex: 1 }} />
          <button className="primary" onClick={submitRma}>
            Gửi yêu cầu RMA
          </button>
        </div>
        {rmaOut && (
          <pre>
            {rmaOut}
            {"\n→ theo dõi tại /support (ticket mới xuất hiện trong danh sách)"}
          </pre>
        )}
      </div>
    </div>
  );
}

export default OrdersList;
