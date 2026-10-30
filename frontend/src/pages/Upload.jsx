import React, { useEffect, useState } from "react";
import api from "../api.js";

export default function Upload() {
  const [list, setList] = useState([]);
  const [out, setOut] = useState("");

  async function refresh() {
    const r = await api("/api/files/list");
    setList((r.data && r.data.uploads) || []);
  }
  useEffect(() => {
    refresh();
  }, []);

  return (
    <div>
      <h1>Upload file</h1>
      <div className="card">
        <h2>Unrestricted file upload (#25/#26)</h2>
        <p className="hint">
          Không kiểm tra extension/MIME/nội dung. Upload <code>shell.html</code> hoặc <code>x.svg</code> chứa{" "}
          <code>&lt;script&gt;alert(document.cookie)&lt;/script&gt;</code> rồi mở link — stored XSS. Tên file giữ
          nguyên (có thể chứa <code>../</code>).
        </p>
        <form
          onSubmit={async (e) => {
            e.preventDefault();
            const fd = new FormData(e.target);
            const r = await api("/api/files/upload", { method: "POST", body: fd });
            setOut(JSON.stringify(r.data, null, 2));
            refresh();
          }}
        >
          <input name="file" type="file" required />
          <button className="primary">Upload</button>
        </form>
        {out && <pre>{out}</pre>}
      </div>

      <div className="card">
        <h2>Files trên server</h2>
        <table>
          <thead>
            <tr>
              <th>#</th>
              <th>filename</th>
              <th>uploader</th>
              <th>links</th>
            </tr>
          </thead>
          <tbody>
            {list.map((u) => (
              <tr key={u.id}>
                <td>{u.id}</td>
                <td>
                  <code>{u.filename}</code>
                </td>
                <td>{u.uploader}</td>
                <td>
                  <a href={`/uploads/${u.filename}`} target="_blank" rel="noreferrer">
                    open
                  </a>{" "}
                  ·{" "}
                  <a href={`/uploads-sniff/${u.filename}`} target="_blank" rel="noreferrer">
                    sniff (#69)
                  </a>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        <p className="hint">Nginx bật autoindex cho /uploads/ — directory listing (#42).</p>
      </div>
    </div>
  );
}
