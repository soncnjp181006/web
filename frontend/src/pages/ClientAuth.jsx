import React, { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import {
  BACKUP_ADMIN,
  mergeDeep,
  parseNestedQuery,
  getClientUser,
  setClientUser,
  isClientAdmin,
  canSeeHiddenPanel,
} from "../vuln/insecureAuth.js";

/* [VULN #17] hardcoded creds, [#18] API keys, [#7] client prototype pollution,
   [#34] client authn bypass, [#35] client authz bypass, [#37] client race
   (double submit), [#60] client-side logic manipulation. */
export default function ClientAuth() {
  const [params] = useSearchParams();
  const [polluted, setPolluted] = useState(false);
  const [user, setUser] = useState(getClientUser());
  const [couponResults, setCouponResults] = useState([]);
  const [checkout, setCheckout] = useState({ qty: 1, price: 9.99, discountPct: 10 });
  const [sentOrder, setSentOrder] = useState("");

  /* [VULN #7] ?__proto__[unlockAllFeatures]=true&__proto__[isAdmin]=true */
  useEffect(() => {
    const parsed = parseNestedQuery(params.toString());
    if (Object.keys(parsed).length) {
      mergeDeep({}, parsed); // vulnerable merge -> Object.prototype polluted
      setPolluted({}.unlockAllFeatures === true || {}.isAdmin === true);
    }
  }, [params]);

  /* [VULN #34] backdoor login: hardcoded creds OR ?debug_login=1 */
  function clientLogin() {
    const u = params.get("debug_user");
    if (u || params.get("debug_login") === "1") {
      setClientUser({ name: u || "debug", role: "admin", is_admin: true }); // bypass
      setUser(getClientUser());
      return;
    }
    // production "logic": chỉ client kiểm tra (không gọi server)
    setUser(getClientUser());
  }

  /* [VULN #37] double submit - no disable while in-flight -> 2 redeems */
  async function applyCoupon() {
    const p = fetch("/api/coupon/redeem", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "include",
      body: JSON.stringify({ code: "VULN50" }),
    }).then((r) => r.json());
    const p2 = fetch("/api/coupon/redeem", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "include",
      body: JSON.stringify({ code: "VULN50" }),
    }).then((r) => r.json());
    const [a, b] = await Promise.all([p, p2]);
    setCouponResults((x) => [...x.slice(-4), a, b]);
  }

  /* [VULN #60] total tính ở client, server tin giá client gửi (#54) */
  function placeOrder() {
    const total = Number(checkout.qty) * Number(checkout.price) * (1 - Number(checkout.discountPct) / 100);
    const body = { productId: 1, qty: checkout.qty, price: checkout.price, clientTotal: total };
    setSentOrder(JSON.stringify(body, null, 2));
    fetch("/api/orders", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "include",
      body: JSON.stringify(body),
    }).then((r) => r.json());
  }

  return (
    <div>
      <h1>Client auth & logic lab</h1>

      <div className="card">
        <h2>Hardcoded credentials & API keys (#17/#18)</h2>
        <pre>{JSON.stringify({ BACKUP_ADMIN, ...{ inWindow: "window.VULN_CONFIG" } }, null, 2)}</pre>
        <p className="hint">
          Toàn bộ dữ liệu này nằm trong JS bundle — mở DevTools → Sources là thấy. API key thật trong app production
          cũng vậy: client-side secret = public.
        </p>
      </div>

      <div className="card">
        <h2>Prototype pollution client (#7)</h2>
        <p className="hint">
          Thêm query: <code>?__proto__[unlockAllFeatures]=true&__proto__[isAdmin]=true</code> — parser{" "}
          <code>parseNestedQuery</code> + <code>mergeDeep</code> (không lọc <code>__proto__</code>) làm bẩn{" "}
          <code>Object.prototype</code> → mọi feature-gate phía client mở.
        </p>
        <p>
          Status: {polluted ? <b className="err">POLLUTED — hidden panel unlocked</b> : <span className="hint">sạch</span>} ·{" "}
          canSeeHiddenPanel(): <code>{String(canSeeHiddenPanel("reports"))}</code>
        </p>
        {canSeeHiddenPanel("reports") && (
          <div className="comment">
            🎉 <b>Hidden admin reports panel</b> (chỉ hiện khi polluted / feature list chứa "reports")
          </div>
        )}
      </div>

      <div className="card">
        <h2>Client-side authn/authz bypass (#34/#35)</h2>
        <p className="hint">
          "Đăng nhập" chỉ là ghi JSON vào localStorage; vai trò chỉ kiểm tra ở browser. Bypass:{" "}
          <code>?debug_login=1</code> hoặc console:{" "}
          <code>localStorage.setItem('vulnshop_user','{"{"}"role":"admin"{"}"}')</code>
        </p>
        <div className="row">
          <button className="primary" onClick={clientLogin}>
            Login (client-only, hiểu ?debug_login / ?debug_user)
          </button>
          <button
            className="danger"
            onClick={() => {
              setClientUser({ name: "pwn", role: "admin", is_admin: true });
              setUser(getClientUser());
            }}
          >
            Tự set role=admin
          </button>
          <button
            onClick={() => {
              localStorage.removeItem("vulnshop_user");
              setUser(null);
            }}
          >
            Clear
          </button>
        </div>
        <pre>{JSON.stringify({ user, isClientAdmin: isClientAdmin() }, null, 2)}</pre>
        {isClientAdmin() && <div className="comment">🔓 Admin panel (client gate — server vẫn yêu cầu thật)</div>}
      </div>

      <div className="card">
        <h2>Race condition client (#37) — double submit</h2>
        <div className="row">
          <button className="danger" onClick={applyCoupon}>
            Apply coupon VULN50 (double-fire)
          </button>
        </div>
        <p className="hint">
          Nút không disable khi đang gửi → 2 request cùng lúc; kết hợp #53 để over-redeem. Kết quả:
        </p>
        <pre>{couponResults.length ? JSON.stringify(couponResults, null, 1) : "(chưa chạy)"}</pre>
      </div>

      <div className="card">
        <h2>Client-side logic manipulation (#60)</h2>
        <div className="row">
          <label>
            qty
            <input
              value={checkout.qty}
              onChange={(e) => setCheckout({ ...checkout, qty: e.target.value })}
              style={{ width: 70 }}
            />
          </label>
          <label>
            price (client sends!)
            <input
              value={checkout.price}
              onChange={(e) => setCheckout({ ...checkout, price: e.target.value })}
              style={{ width: 110 }}
            />
          </label>
          <label>
            discount%
            <input
              value={checkout.discountPct}
              onChange={(e) => setCheckout({ ...checkout, discountPct: e.target.value })}
              style={{ width: 80 }}
            />
          </label>
          <button className="danger" onClick={placeOrder}>
            Place order (giá client quyết)
          </button>
        </div>
        <p className="hint">Đặt price=0.01 hoặc discount=100000 → server tin client (#54/#60).</p>
        {sentOrder && <pre>{sentOrder}</pre>}
      </div>
    </div>
  );
}
