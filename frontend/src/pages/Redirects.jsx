import React, { useEffect, useState } from "react";
import { useSearchParams, useNavigate } from "react-router-dom";

/* [VULN #9→client] Open Redirect (client-side), [#10] DOM-based open redirect
   (hash / window.name / referrer), [#57] insecure redirect handling (meta refresh). */
export default function Redirects() {
  const [params] = useSearchParams();
  const navigate = useNavigate();
  const [out, setOut] = useState("");
  const [metaUrl, setMetaUrl] = useState("https://example.com");

  // [VULN #9] client open redirect via ?next= - NO validation (no allowlist)
  useEffect(() => {
    const next = params.get("next");
    if (next && !params.get("stay")) {
      setOut(`?next= phát hiện → location.assign("${next}") trong 1.5s (thêm &stay=1 để giữ trang)`);
      const t = setTimeout(() => {
        window.location.assign(next);
      }, 1500);
      return () => clearTimeout(t);
    }
  }, [params]);

  // [VULN #10] DOM-based open redirect via hash: #https://evil.tld
  useEffect(() => {
    const h = decodeURIComponent(location.hash.slice(1));
    if (/^https?:\/\//i.test(h)) {
      setOut((o) => o + `\n\nHash redirect: "${h}" → sẽ nhảy khi bấm nút "Go (hash)"`);
    }
  }, []);

  function goHash() {
    const h = decodeURIComponent(location.hash.slice(1));
    if (h) window.location.href = h; // [VULN #10] sink
  }

  function injectMetaRefresh() {
    const m = document.createElement("meta");
    m.httpEquiv = "refresh";
    m.content = `3;url=${metaUrl}`; // [VULN #57] user input thẳng vào meta refresh
    document.head.appendChild(m);
    setOut((o) => o + `\n\nMeta refresh 3s → ${metaUrl} đã inject vào <head>`);
  }

  return (
    <div>
      <h1>Redirect lab (client-side)</h1>
      <div className="card">
        <h2>Open redirect (#9) — query param</h2>
        <p className="hint">
          Thử: <code>?next=https://example.com</code> — client chuyển hướng không kiểm tra allowlist. Payload
          phổ biến: <code>?next=javascript:alert(1)</code> (một số browser vẫn chạy),{" "}
          <code>?next=//evil.tld</code> (protocol-relative).
        </p>
        <div className="row">
          <a href={`?next=https://example.com&stay=1`}>mở ?next=https://example.com (stay)</a>
          <a href={`?next=//example.com&stay=1`}>mở ?next=//example.com (stay)</a>
        </div>
      </div>

      <div className="card">
        <h2>DOM-based open redirect (#10) — hash & window.name</h2>
        <p className="hint">
          Đặt hash <code>#https://example.com</code> rồi bấm — sink là{" "}
          <code>window.location.href = hash</code> (đọc từ DOM, không qua server).
        </p>
        <div className="row">
          <button className="primary" onClick={goHash}>
            Go (hash)
          </button>
          <span className="hint">hash hiện tại: {decodeURIComponent(location.hash.slice(1)) || "(trống)"}</span>
        </div>
      </div>

      <div className="card">
        <h2>Insecure redirect handling (#57) — meta refresh injection</h2>
        <div className="row">
          <input value={metaUrl} onChange={(e) => setMetaUrl(e.target.value)} style={{ flex: 1 }} />
          <button className="danger" onClick={injectMetaRefresh}>
            Inject &lt;meta refresh&gt;
          </button>
        </div>
        <p className="hint">3 giây sau trang tự nhảy tới URL bạn nhập — redirect "cài cắm" từ client.</p>
      </div>

      <div className="card">
        <h2>Spa-router redirect (react-router)</h2>
        <p className="hint">
          Cả SPA navigation cũng có thể bị lạm dụng: <code>?next=/domxss</code> — điều hướng nội bộ dùng{" "}
          <code>navigate()</code>:
        </p>
        <button onClick={() => navigate(params.get("next") || "/")}>navigate(?next)</button>
      </div>

      <pre>{out || "(chưa có redirect)"}</pre>
    </div>
  );
}
