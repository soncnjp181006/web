import React, { useEffect, useState } from "react";
import { useLocation } from "react-router-dom";

/* [VULN #59] DOM-based XSS sink + [VULN #58] DOM clobbering gadget.
   Fragment is decoded and (when "safe mode" is bypassed) injected via innerHTML.

   Clobber payload (paste after # in the URL):
     #<form id=config><input name=allow></form><img src=x onerror=alert(document.domain)>

   How it works: `window.config` resolves to the <form id=config> element
   (window named access), `config.allow` resolves to the <input name=allow>
   child (form named access) -> truthy -> safe mode disabled -> hash goes
   into innerHTML. */
export default function DomXss() {
  const location = useLocation();
  const [hashHtml, setHashHtml] = useState("");
  const [version, setVersion] = useState("unknown");

  useEffect(() => {
    const raw = decodeURIComponent(location.hash.slice(1));
    setHashHtml(raw);

    // [VULN #58] deliberately clobberable config resolution
    let cfg = window.config;
    if (!cfg) {
      const el = document.getElementById("config");
      if (el) cfg = { version: el.getAttribute("name"), allow: false };
    }
    const v = cfg && cfg.version;
    setVersion(typeof v === "string" ? v : v ? "[object]" : "unknown");

    // safe mode gate - bypassed by DOM clobbering
    const safeMode = !(cfg && cfg.allow);
    if (raw && !safeMode) {
      // XSS SINK (#59)
      document.getElementById("domxss-out").innerHTML = raw;
    }
  }, [location.hash]);

  return (
    <div>
      <h1>DOM XSS + DOM clobbering lab</h1>
      <div className="card">
        <p className="hint">
          #59: hash được decode và đưa vào innerHTML khi safe-mode bị tắt. #58: <code>window.config.allow</code> bị
          clobber bởi <code>&lt;form id=config&gt;&lt;input name=allow&gt;</code> → safe mode off.
        </p>
        <p>
          config.version: <code>{String(version)}</code>
        </p>
        <div id="domxss-out" className="comment" />
        <p className="hint">
          Thử URL: <code>your-site/#&lt;form id=config&gt;&lt;input name=allow&gt;&lt;img src=x onerror=alert(1)&gt;</code>
        </p>
      </div>
      <div className="card">
        <h2>Safe render (textContent)</h2>
        <pre>{hashHtml || "(hash trống)"}</pre>
      </div>
    </div>
  );
}
