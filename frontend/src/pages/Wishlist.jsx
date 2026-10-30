import React, { useEffect, useState } from "react";
import api from "../api.js";

/* Wishlist.
   [VULN #49] xem wishlist người khác qua ?owner=
   [VULN #6] export XML — note nối thẳng vào document
   [VULN #44] "kiểm tra quà" — XS-Leak oracle qua img onload/onerror */
export default function Wishlist() {
  const [owner, setOwner] = useState("");
  const [items, setItems] = useState([]);
  const [oracle, setOracle] = useState("(chưa test)");
  const [note, setNote] = useState("Mong nhận được món này 😍");

  async function load(o) {
    const r = await api(`/api/wishlist${o ? `?owner=${encodeURIComponent(o)}` : ""}`);
    setItems((r.data && r.data.items) || []);
  }
  useEffect(() => {
    load("");
  }, []);

  /* [VULN #44] login-state oracle: 200 -> onload (đã đăng nhập), 401 -> onerror */
  function testOracle() {
    setOracle("testing...");
    const img = new Image();
    img.onload = () => setOracle("ĐÃ ĐĂNG NHẬP (200 + cacheable) — leak không cần đọc response!");
    img.onerror = () => setOracle("CHƯA đăng nhập (401 → onerror)");
    img.src = "/api/cache/profile/gift-" + Date.now() + ".css";
  }

  return (
    <div>
      <h1>❤ Wishlist</h1>
      <div className="card">
        <div className="row">
          <input
            value={owner}
            onChange={(e) => setOwner(e.target.value)}
            placeholder="user_id bạn bè (BOLA #49 — để trống = của bạn)"
            style={{ flex: 1 }}
          />
          <button className="primary" onClick={() => load(owner)}>
            Xem
          </button>
          <a href="/api/wishlist/export/xml" target="_blank" rel="noreferrer">
            <button>Xuất XML (#6)</button>
          </a>
        </div>
        <p className="hint">
          BOLA (#49): thử <code>legacy-victim-2</code> — backend trả wishlist của bất kỳ ai. XML export nối note thẳng
          vào document — payload seed đã phá cấu trúc XML sẵn.
        </p>
      </div>

      <div className="card">
        <table>
          <thead>
            <tr>
              <th>#</th>
              <th>Owner</th>
              <th>Sản phẩm</th>
              <th>Giá</th>
              <th>Note</th>
            </tr>
          </thead>
          <tbody>
            {items.map((w) => (
              <tr key={w.id}>
                <td>{w.id}</td>
                <td>
                  <code>{w.user_id}</code>
                </td>
                <td>{w.product || "(đã xoá)"}</td>
                <td>{w.price ? `$${w.price}` : "-"}</td>
                <td>
                  <code>{w.note}</code>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="card">
        <h3>🎁 "BạnFriend muốn tặng quà?" — XS-Leak oracle (#44)</h3>
        <div className="row">
          <button className="primary" onClick={testOracle}>
            Kiểm tra trạng thái đăng nhập
          </button>
          <span>{oracle}</span>
        </div>
        <p className="hint">
          Trang attacker chỉ cần <code>&lt;img src="/api/cache/profile/x.css"&gt;</code> — onload/onerror đủ đoán trạng
          thái login của nạn nhân.
        </p>
      </div>
    </div>
  );
}
