import React from "react";
import { Outlet, Link, NavLink } from "react-router-dom";
import Session from "supertokens-auth-react/recipe/session";
import { useEffect, useState } from "react";

const groups = [
  {
    label: "Shop",
    links: [
      ["/", "Trang chủ"],
      ["/shop", "Cửa hàng"],
      ["/build", "Build PC"],
      ["/compare", "So sánh"],
      ["/deals", "Deals"],
    ],
  },
  {
    label: "Của bạn",
    links: [
      ["/cart", "🛒 Giỏ hàng"],
      ["/orders", "Đơn hàng"],
      ["/wishlist", "❤ Wishlist"],
      ["/support", "Hỗ trợ"],
      ["/profile", "Hồ sơ"],
      ["/sessions", "Thiết bị"],
    ],
  },
  {
    label: "Khác",
    links: [
      ["/stores", "Cửa hàng vật lý"],
      ["/offline", "Offline"],
      ["/notifications", "Thông báo"],
    ],
  },
  {
    label: "Nhân viên",
    links: [
      ["/legacy", "Staff portal (legacy)"],
      ["/admin", "Admin"],
      ["/internal", "Diagnostics"],
    ],
  },
];

export default function App() {
  const [hasSession, setHasSession] = useState(false);
  useEffect(() => {
    Session.doesSessionExist().then(setHasSession).catch(() => {});
  }, []);

  return (
    <div className="app">
      <div className="banner">
        ⚠️ <b>VulnPC Shop</b> — website bán PC chứa lỗi bảo mật <b>CỐ Ý</b> dùng để học bảo mật. Không dùng dữ liệu thật!
      </div>
      <div className="topbar">
        <Link to="/" className="logo">
          🔥 VulnPC<span className="logo-accent">Shop</span>
        </Link>
        <span className="topbar-hint">Gaming · Workstation · Linh kiện — giao toàn quốc</span>
        {hasSession ? (
          <button
            className="signout"
            onClick={async () => {
              await Session.signOut();
              window.location.href = "/";
            }}
          >
            Sign out (ST)
          </button>
        ) : (
          <Link className="signin" to="/auth">
            Đăng nhập / Đăng ký
          </Link>
        )}
      </div>
      <nav>
        {groups.map((g) => (
          <span className="nav-group" key={g.label}>
            {g.links.map(([to, label]) => (
              <NavLink key={to} to={to} end={to === "/"} className={({ isActive }) => (isActive ? "active" : "")}>
                {label}
              </NavLink>
            ))}
            <span className="nav-sep" />
          </span>
        ))}
      </nav>
      <main className="page">
        <Outlet />
      </main>
      <footer>
        VulnPC Shop · Hotline 1900-VULN · Map đầy đủ 135 lỗi xem <Link to="/internal">/internal</Link> và docs/VULNS.md
      </footer>
    </div>
  );
}
