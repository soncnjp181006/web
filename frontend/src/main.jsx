import React from "react";
import ReactDOM from "react-dom/client";
import * as reactRouterDom from "react-router-dom";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import SuperTokens, { SuperTokensWrapper } from "supertokens-auth-react";
import EmailPassword from "supertokens-auth-react/recipe/emailpassword";
import * as EPUI from "supertokens-auth-react/recipe/emailpassword/prebuiltui";
import Session, { SessionAuth } from "supertokens-auth-react/recipe/session";
import { getSuperTokensRoutesForReactRouterDom } from "supertokens-auth-react/ui";

// EmailPasswordPreBuiltUI nằm ở subpath prebuiltui (bundle có default + named)
const EmailPasswordPreBuiltUI = EPUI.EmailPasswordPreBuiltUI ?? EPUI.default;

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
import Storage from "./pages/Storage.jsx";
import Injection from "./pages/Injection.jsx";
import Redirects from "./pages/Redirects.jsx";
import ClientAuth from "./pages/ClientAuth.jsx";
import PostMessage from "./pages/PostMessage.jsx";
import Workers from "./pages/Workers.jsx";
import Leaks from "./pages/Leaks.jsx";
import PathDos from "./pages/PathDos.jsx";
import Cache from "./pages/Cache.jsx";
import Supply from "./pages/Supply.jsx";
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
          {/* Supertokens prebuilt UI: sign in / sign up / reset password tại /auth/* */}
          {getSuperTokensRoutesForReactRouterDom(reactRouterDom, [EmailPasswordPreBuiltUI])}

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
            <Route path="storage" element={<Storage />} />
            <Route path="injection" element={<Injection />} />
            <Route path="redirects" element={<Redirects />} />
            <Route path="clientauth" element={<ClientAuth />} />
            <Route path="postmessage" element={<PostMessage />} />
            <Route path="workers" element={<Workers />} />
            <Route path="leaks" element={<Leaks />} />
            <Route path="pathdos" element={<PathDos />} />
            <Route path="cache" element={<Cache />} />
            <Route path="supply" element={<Supply />} />
            <Route path="*" element={<div className="page"><h2>404</h2><p>Try the nav above.</p></div>} />
          </Route>
        </Routes>
      </BrowserRouter>
    </SuperTokensWrapper>
  </React.StrictMode>
);
