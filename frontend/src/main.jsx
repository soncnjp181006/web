import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import SuperTokens, { SuperTokensWrapper } from "supertokens-auth-react";
import EmailPassword, { EmailPasswordPreBuiltUI } from "supertokens-auth-react/recipe/emailpassword";
import Session, { SessionAuth } from "supertokens-auth-react/recipe/session";
import { SuperTokensRoute } from "supertokens-auth-react/ui";

import App from "./App.jsx";
import Home from "./pages/Home.jsx";
import Product from "./pages/Product.jsx";
import Orders, { OrderDetail } from "./pages/Orders.jsx";
import Profile from "./pages/Profile.jsx";
import Upload from "./pages/Upload.jsx";
import Files from "./pages/Files.jsx";
import Admin from "./pages/Admin.jsx";
import Chat from "./pages/Chat.jsx";
import LegacyAuth from "./pages/LegacyAuth.jsx";
import DomXss from "./pages/DomXss.jsx";
import Lab from "./pages/Lab.jsx";
import Debug from "./pages/Debug.jsx";
import OAuthDemo from "./pages/OAuthDemo.jsx";
import "./styles.css";

// [auth] Supertokens: EmailPassword (sign up / sign in with email+password).
// apiDomain = websiteDomain = current origin: Cloudflare Pages proxies /auth
// and /api to the Render backend, so cookies stay first-party.
SuperTokens.init({
  appInfo: {
    appName: "VulnShop",
    apiDomain: window.location.origin,
    websiteDomain: window.location.origin,
    apiBasePath: "/auth",
    websiteBasePath: "/auth",
  },
  recipeList: [EmailPassword.init(), Session.init()],
});

ReactDOM.createRoot(document.getElementById("root")).render(
  <React.StrictMode>
    <SuperTokensWrapper>
      <BrowserRouter>
        <Routes>
          <Route path="/auth/*" element={<SuperTokensRoute preBuiltUIList={[EmailPasswordPreBuiltUI]} />} />

          <Route path="/" element={<App />}>
            <Route index element={<Home />} />
            <Route path="product/:id" element={<Product />} />
            <Route
              path="orders"
              element={
                <SessionAuth>
                  <Orders />
                </SessionAuth>
              }
            />
            <Route
              path="orders/:id"
              element={
                <SessionAuth>
                  <OrderDetail />
                </SessionAuth>
              }
            />
            <Route
              path="profile"
              element={
                <SessionAuth>
                  <Profile />
                </SessionAuth>
              }
            />
            <Route path="upload" element={<Upload />} />
            <Route path="files" element={<Files />} />
            <Route path="admin" element={<Admin />} />
            <Route path="chat" element={<Chat />} />
            <Route path="legacy" element={<LegacyAuth />} />
            <Route path="domxss" element={<DomXss />} />
            <Route path="lab" element={<Lab />} />
            <Route path="debug" element={<Debug />} />
            <Route path="oauth-demo" element={<OAuthDemo />} />
            <Route path="*" element={<div className="page"><h2>404</h2><p>Try the nav above.</p></div>} />
          </Route>
        </Routes>
      </BrowserRouter>
    </SuperTokensWrapper>
  </React.StrictMode>
);
