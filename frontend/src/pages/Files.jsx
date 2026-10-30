import React, { useState } from "react";
import api from "../api.js";

export default function Files() {
  const [name, setName] = useState("welcome.txt");
  const [out, setOut] = useState("");

  async function run(path) {
    const r = await api(path);
    setOut(JSON.stringify(r.data, null, 2).slice(0, 20000));
  }

  return (
    <div>
      <h1>Files lab</h1>
      <div className="card">
        <h2>Directory traversal (#22) & LFI (#23) & RFI (#24)</h2>
        <div className="row">
          <input value={name} onChange={(e) => setName(e.target.value)} style={{ flex: 1 }} />
          <button className="primary" onClick={() => run(`/api/files/download?name=${encodeURIComponent(name)}`)}>
            download (#22)
          </button>
          <button onClick={() => run(`/api/files/read?page=${encodeURIComponent(name)}`)}>read/LFI-RFI (#23/#24)</button>
        </div>
        <p className="hint">
          #22: <code>../../../../etc/passwd</code> hoặc <code>/etc/passwd</code> · #23:{" "}
          <code>../../../package.json</code> · #24: dán URL thẳng <code>https://...</code> — nội dung được{" "}
          <b>eval()</b> ngay trên server.
        </p>
      </div>
      <div className="card">
        <h2>Server response</h2>
        <pre>{out || "(chưa chạy)"}</pre>
      </div>
    </div>
  );
}
