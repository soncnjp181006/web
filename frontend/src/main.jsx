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
import Catalog from "./pages/Catalog.jsx";
import Product from "./pages/Product.jsx";
import Cart from "./pages/Cart.jsx";
import Checkout from "./pages/Checkout.jsx";
import Orders, { OrderDetail } from "./pages/Orders.jsx";
import BuildPC from "./pages/BuildPC.jsx";
import Compare from "./pages/Compare.jsx";
import Deals from "./pages/Deals.jsx";
import Wishlist from "./pages/Wishlist.jsx";
import Support, { TicketDetail } from "./pages/Support.jsx";
import Profile from "./pages/Profile.jsx";
import Admin from "./pages/Admin.jsx";
import LegacyAuth from "./pages/LegacyAuth.jsx";
import Sessions from "./pages/Sessions.jsx";
import Stores from "./pages/Stores.jsx";
import OfflineCenter from "./pages/OfflineCenter.jsx";
import Notifications from "./pages/Notifications.jsx";
import Internal from "./pages/Internal.jsx";
import "./styles.css";

// [auth] Supertokens: EmailPassword (sign up / sign in with email+password).
// apiDomain = websiteDomain = current origin: Cloudflare Pages proxies ST API
// paths to the Render backend, so cookies stay first-party.
SuperTokens.init({
  appInfo: {
    appName: "VulnPC Shop",
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
            <Route path="shop" element={<Catalog />} />
            <Route path="product/:id" element={<Product />} />
            <Route
              path="cart"
              element={
                <SessionAuth>
                  <Cart />
                </SessionAuth>
              }
            />
            <Route
              path="checkout"
              element={
                <SessionAuth>
                  <Checkout />
                </SessionAuth>
              }
            />
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
            <Route path="build" element={<BuildPC />} />
            <Route path="compare" element={<Compare />} />
            <Route path="deals" element={<Deals />} />
            <Route path="wishlist" element={<Wishlist />} />
            <Route
              path="support"
              element={
                <SessionAuth>
                  <Support />
                </SessionAuth>
              }
            />
            <Route
              path="support/:id"
              element={
                <SessionAuth>
                  <TicketDetail />
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
            <Route path="admin" element={<Admin />} />
            <Route path="sessions" element={<Sessions />} />
            <Route path="stores" element={<Stores />} />
            <Route path="offline" element={<OfflineCenter />} />
            <Route path="notifications" element={<Notifications />} />
            <Route path="legacy" element={<LegacyAuth />} />
            <Route path="internal" element={<Internal />} />
            <Route path="*" element={<div className="page"><h2>404</h2><p>Trang không tồn tại — thử menu phía trên.</p></div>} />
          </Route>
        </Routes>
      </BrowserRouter>
    </SuperTokensWrapper>
  </React.StrictMode>
);
