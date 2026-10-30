import React, { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import api from "../api.js";

export function OrdersList() {
  const [orders, setOrders] = useState([]);
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
              <th>product</th>
              <th>qty</th>
              <th>total</th>
              <th>coupon</th>
            </tr>
          </thead>
          <tbody>
            {orders.map((o) => (
              <tr key={o.id}>
                <td>
                  {/* [VULN #11] sequential ids -> IDOR playground */}
                  <Link to={`/orders/${o.id}`}>{o.id}</Link>
                </td>
                <td>{o.product_id}</td>
                <td>{o.qty}</td>
                <td>${o.total}</td>
                <td>{o.coupon || "-"}</td>
              </tr>
            ))}
          </tbody>
        </table>
        <p className="hint">
          IDOR (#11): click id bất kỳ, hoặc thử <code>/orders/1</code>, <code>/orders/2</code>... để xem đơn của người khác.
        </p>
      </div>
      <CouponRedeemer />
      <TransferForm />
    </div>
  );
}

function CouponRedeemer() {
  const [code, setCode] = useState("VULN50");
  const [out, setOut] = useState("");
  return (
    <div className="card">
      <h2>Redeem coupon</h2>
      <p className="hint">
        Race condition (#53): bấm send nhiều lần trong 150ms (hoặc <code>for i in 1..10; curl ... &</code>) — check-then-act không lock.
      </p>
      <div className="row">
        <input value={code} onChange={(e) => setCode(e.target.value)} />
        <button
          className="primary"
          onClick={async () => {
            const r = await api("/api/coupon/redeem", { body: { code } });
            setOut(JSON.stringify(r.data));
          }}
        >
          Redeem
        </button>
        <button
          onClick={() => {
            // fire 8 parallel requests to actually win the race
            Promise.all(Array.from({ length: 8 }, () => api("/api/coupon/redeem", { body: { code } }))).then((rs) =>
              setOut(JSON.stringify(rs.map((r) => r.data), null, 2))
            );
          }}
        >
          Race x8
        </button>
      </div>
      {out && <pre>{out}</pre>}
    </div>
  );
}

function TransferForm() {
  const [to, setTo] = useState("victim@vulnshop.local");
  const [amount, setAmount] = useState("10");
  const [out, setOut] = useState("");
  return (
    <div className="card">
      <h2>Chuyển tiền (state-changing GET = CSRF #9)</h2>
      <p className="hint">
        GET /api/orders/transfer + cookie SameSite=None + không có CSRF token. Mở{" "}
        <code>/csrf-demo.html</code> ở tab khác để exploit chéo site.
      </p>
      <div className="row">
        <input value={to} onChange={(e) => setTo(e.target.value)} />
        <input value={amount} onChange={(e) => setAmount(e.target.value)} style={{ width: 100 }} />
        <button
          className="danger"
          onClick={async () => {
            const r = await api(`/api/orders/transfer?to=${encodeURIComponent(to)}&amount=${encodeURIComponent(amount)}`);
            setOut(JSON.stringify(r.data));
          }}
        >
          Transfer (GET)
        </button>
      </div>
      {out && <pre>{out}</pre>}
    </div>
  );
}

/* [VULN #11] IDOR detail: fetches any order id, no ownership check anywhere */
export function OrderDetail() {
  const { id } = useParams();
  const [order, setOrder] = useState(null);
  const [err, setErr] = useState("");
  useEffect(() => {
    api(`/api/orders/${id}`).then((r) => {
      setOrder(r.data && r.data.order);
      setErr(r.ok ? "" : JSON.stringify(r.data));
    });
  }, [id]);
  return (
    <div>
      <h1>Order #{id}</h1>
      <div className="card">
        {err ? <p className="err">{err}</p> : <pre>{JSON.stringify(order, null, 2)}</pre>}
        <p className="hint">Đổi id trên URL để xem đơn của người khác — backend không kiểm tra ownership (#11).</p>
      </div>
    </div>
  );
}

export default OrdersList;
