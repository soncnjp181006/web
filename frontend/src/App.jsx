import React from "react";
import { Outlet, Link, NavLink } from "react-router-dom";
import Session from "supertokens-auth-react/recipe/session";
import { useEffect, useState } from "react";

const links = [
  ["/", "Shop"],
  ["/orders", "Orders"],
  ["/profile", "Profile"],
  ["/upload", "Upload"],
  ["/files", "Files"],
  ["/admin", "Admin"],
  ["/chat", "Chat"],
  ["/legacy", "Legacy login"],
  ["/domxss", "DOM XSS lab"],
  ["/lab", "Attack lab"],
  ["/oauth-demo", "OAuth"],
  ["/debug", "Debug"],
];

export default function App() {
  const [hasSession, setHasSession] = useState(false);
  useEffect(() => {
    Session.doesSessionExist().then(setHasSession).catch(() => {});
  }, []);

  return (
    <div className="app">
      <div className="banner">
        ⚠️ VulnShop — <b>app chứa lỗi bảo mật CỐ Ý</b> dùng để học bảo mật. Không dùng dữ liệu thật!
      </div>
      <nav>
        {links.map(([to, label]) => (
          <NavLink key={to} to={to} className={({ isActive }) => (isActive ? "active" : "")}>
            {label}
          </NavLink>
        ))}
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
            Sign in / Sign up (Supertokens)
          </Link>
        )}
      </nav>
      <main className="page">
        <Outlet />
      </main>
      <footer>
        Training-only app · map đầy đủ 75 lỗi xem <Link to="/debug">/debug</Link> và docs/VULNS.md
      </footer>
    </div>
  );
}
