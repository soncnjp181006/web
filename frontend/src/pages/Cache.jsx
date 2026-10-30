import React, { useEffect, useState } from "react";

/* [VULN #41] client-side cache poisoning (Cache API keyed by user URL),
   [#42] browser cache leakage (sensitive data cached + bfcache),
   [#54] MIME sniffing client demo. */
export default function Cache() {
  const [key, setKey] = useState("/api/v2/users");
  const [poisonBody, setPoisonBody] = useState('{"users":[{"email":"attacker-controlled"}]}');
  const [readOut, setReadOut] = useState("");
  const [cacheList, setCacheList] = useState([]);
  const [sniffName, setSniffName] = useState("shell.html");
  const [sniffOut, setSniffOut] = useState("");

  /* [VULN #41] poison: cache một response GIẢ cho URL thật — mọi code gọi
     caches.match(url) sẽ nhận response độc */
  async function poison() {
    const cache = await caches.open("vulnshop-poison");
    const fake = new Response(poisonBody, {
      headers: { "Content-Type": "application/json", "X-Poisoned": "yes" },
    });
    await cache.put(new Request(key, { credentials: "include" }), fake);
    await listCache();
  }

  /* đọc lại: code "bình thường" ưu tiên caches.match trước network */
  async function readPoisoned() {
    const cache = await caches.open("vulnshop-poison");
    const hit = await cache.match(new Request(key, { credentials: "include" }));
    if (hit) {
      const body = await hit.text();
      setReadOut(`CACHED (poisoned, X-Poisoned: ${hit.headers.get("X-Poisoned")}):\n${body.slice(0, 1500)}`);
    } else {
      setReadOut("không có cache cho key này");
    }
  }

  async function listCache() {
    const cache = await caches.open("vulnshop-poison");
    const keys = await cache.keys();
    setCacheList(keys.map((k) => k.url));
  }
  useEffect(() => {
    listCache();
  }, []);

  async function clearCache() {
    await caches.delete("vulnshop-poison");
    await listCache();
    setReadOut("");
  }

  /* [VULN #54] MIME sniffing: file upload bất kỳ -> browser tự "đoán" type */
  function testSniff(kind) {
    setSniffOut(`loading /uploads-sniff/${sniffName} as ${kind}... (xem console/alert)`);
    if (kind === "img") {
      const i = new Image();
      i.onload = () => setSniffOut(`img OK: browser sniff và render (kích thước ${i.width}x${i.height})`);
      i.onerror = () => setSniffOut("img failed — nhưng sniff vẫn xảy ra với object/iframe; thử nút iframe");
      i.src = `/uploads-sniff/${sniffName}`;
    } else {
      const f = document.createElement("iframe");
      f.src = `/uploads-sniff/${sniffName}`;
      f.style.width = "100%";
      f.style.height = "120px";
      document.getElementById("sniff-frame").innerHTML = "";
      document.getElementById("sniff-frame").appendChild(f);
      setSniffOut("iframe loaded — nếu file là HTML, script trong đó chạy trong origin của app");
    }
  }

  return (
    <div>
      <h1>Cache lab (client-side)</h1>

      <div className="card">
        <h2>Client-side cache poisoning (#41)</h2>
        <div className="row">
          <input value={key} onChange={(e) => setKey(e.target.value)} style={{ flex: 1 }} placeholder="URL key" />
        </div>
        <div className="row" style={{ width: "100%" }}>
          <textarea rows={2} value={poisonBody} onChange={(e) => setPoisonBody(e.target.value)} style={{ flex: 1 }} />
        </div>
        <div className="row">
          <button className="danger" onClick={poison}>
            Poison cache key
          </button>
          <button className="primary" onClick={readPoisoned}>
            Đọc (app sẽ dùng cache trước)
          </button>
          <button onClick={listCache}>List keys</button>
          <button onClick={clearCache}>Clear</button>
        </div>
        <p className="hint">
          Cache API lưu theo URL người dùng chọn. Service worker hoặc app-code đọc <code>caches.match</code> trước
          network sẽ nhận response giả (số dư, user list...). Kết hợp SW hijack (#40) → poison vĩnh viễn mọi tab.
        </p>
        <p className="hint">Keys: {cacheList.join(" · ") || "(trống)"}</p>
        <pre>{readOut || "(chưa đọc)"}</pre>
      </div>

      <div className="card">
        <h2>Browser cache leakage (#42)</h2>
        <p className="hint">
          3 nguồn leak trên chính browser:
        </p>
        <ul className="hint">
          <li>
            Server trả <code>Cache-Control: public</code> cho data cá nhân (<code>/api/cache/profile/x.css</code>{" "}
            #38) → dữ liệu nằm trong HTTP cache của browser, đọc lại không cần network.
          </li>
          <li>
            bfcache/back-button: bấm Back sau khi logout — state trang (kèm data) có thể sống lại trong RAM.
          </li>
          <li>
            Form với <code>autocomplete</code> bật cho password/CC → browser lưu plaintext (xem #49 trang XS-Leaks).
          </li>
        </ul>
        <img
          src="/api/cache/profile/bfcache-test.css"
          alt="cache probe"
          style={{ display: "none" }}
          onError={(e) => (e.target.style.display = "none")}
        />
      </div>

      <div className="card">
        <h2>MIME sniffing (#54)</h2>
        <div className="row">
          <input value={sniffName} onChange={(e) => setSniffName(e.target.value)} placeholder="tên file đã upload" />
          <button className="primary" onClick={() => testSniff("img")}>
            Load as &lt;img&gt;
          </button>
          <button className="danger" onClick={() => testSniff("iframe")}>
            Load as &lt;iframe&gt;
          </button>
        </div>
        <p className="hint">
          Endpoint <code>/uploads-sniff/:name</code> trả <code>text/plain</code> nhưng KHÔNG có{" "}
          <code>X-Content-Type-Options: nosniff</code> → browser sniff nội dung: upload{" "}
          <code>shell.html</code> (trang Upload) rồi iframe ở đây → HTML/script chạy.
        </p>
        <div id="sniff-frame" />
        <pre>{sniffOut}</pre>
      </div>
    </div>
  );
}
