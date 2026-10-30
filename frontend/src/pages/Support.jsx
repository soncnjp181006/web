import React, { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import api from "../api.js";

/* Trung tâm hỗ trợ.
   [VULN #49/#11] danh sách ticket — chi tiết không check ownership
   [VULN #3] tin nhắn render raw HTML (stored XSS) — xem ở TicketDetail */
export default function Support() {
  const [tickets, setTickets] = useState([]);
  const [subject, setSubject] = useState("");
  const [firstMessage, setFirstMessage] = useState("");

  async function refresh() {
    const r = await api("/api/support/tickets");
    setTickets((r.data && r.data.tickets) || []);
  }
  useEffect(() => {
    refresh();
  }, []);

  async function createTicket(e) {
    e.preventDefault();
    await api("/api/support/tickets", { body: { subject, firstMessage } });
    setSubject("");
    setFirstMessage("");
    refresh();
  }

  return (
    <div>
      <h1>🎧 Hỗ trợ kỹ thuật</h1>
      <div className="card">
        <h3>Tạo ticket mới</h3>
        <form onSubmit={createTicket}>
          <input
            value={subject}
            onChange={(e) => setSubject(e.target.value)}
            placeholder="Tiêu đề:VD: Máy tự restart khi chơi game"
            style={{ width: "100%" }}
            required
          />
          <textarea
            rows={2}
            value={firstMessage}
            onChange={(e) => setFirstMessage(e.target.value)}
            placeholder="Mô tả chi tiết lỗi..."
            style={{ width: "100%" }}
          />
          <button className="primary">Tạo ticket</button>
        </form>
      </div>

      <div className="card">
        <h3>Ticket của bạn</h3>
        <table>
          <thead>
            <tr>
              <th>#</th>
              <th>Tiêu đề</th>
              <th>Trạng thái</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {tickets.map((t) => (
              <tr key={t.id}>
                <td>{t.id}</td>
                <td>
                  <Link to={`/support/${t.id}`}>{t.subject}</Link>
                </td>
                <td>{t.status}</td>
                <td>
                  <Link to={`/support/${t.id}`}>
                    <button>Xem</button>
                  </Link>
                </td>
              </tr>
            ))}
            {!tickets.length && (
              <tr>
                <td colSpan={4} className="hint">
                  Chưa có ticket nào.
                </td>
              </tr>
            )}
          </tbody>
        </table>
        <p className="hint">
          IDOR (#11): mở thẳng <code>/support/1</code> — ticket của người khác. BOLA v2: <code>/api/v2/tickets/1</code>.
        </p>
      </div>
    </div>
  );
}

/* Chi tiết ticket: tin nhắn innerHTML (#3), chat WS (#60/#38/#25),
   đính kèm unrestricted upload (#25/#26), email update (#68),
   notification bridge postMessage (#28). */
export function TicketDetail() {
  const { id } = useParams();
  const [data, setData] = useState(null);
  const [reply, setReply] = useState("");
  const [wsStatus, setWsStatus] = useState("-");
  const [chat, setChat] = useState([]);
  const [chatText, setChatText] = useState("");
  const [attachOut, setAttachOut] = useState("");
  const [mailFrom, setMailFrom] = useState("admin@vulnpc.local");
  const [mailOut, setMailOut] = useState("");
  const [notif, setNotif] = useState([]);
  const wsRef = React.useRef(null);

  async function refresh() {
    const r = await api(`/api/support/tickets/${id}`);
    setData(r.data);
  }
  useEffect(() => {
    refresh();
  }, [id]);

  /* [VULN #28] notification bridge: postMessage không check origin */
  useEffect(() => {
    function onMsg(e) {
      // không kiểm tra e.origin!
      setNotif((n) => [...n.slice(-4), { origin: e.origin || "(null)", text: String(typeof e.data === "string" ? e.data : JSON.stringify(e.data)).slice(0, 300) }]);
      if (typeof e.data === "string") {
        const out = document.getElementById("notif-render");
        if (out) out.innerHTML = e.data; // XSS sink qua postMessage
      }
    }
    window.addEventListener("message", onMsg);
    return () => window.removeEventListener("message", onMsg);
  }, []);

  /* [VULN #60/#38/#25] support live chat qua WS: không origin check, leak token */
  useEffect(() => {
    const url = import.meta.env.VITE_WS_URL || `${location.protocol === "https:" ? "wss" : "ws"}://${location.host}/ws/chat`;
    let ws;
    try {
      ws = new WebSocket(url);
    } catch (e) {
      setWsStatus("WS error: " + e.message);
      return;
    }
    ws.onopen = () => {
      setWsStatus("connected");
      const jwt = localStorage.getItem("vulnshop_jwt");
      if (jwt) ws.send(JSON.stringify({ system: true, text: `[leak] ticket#${id} client token: ${jwt.slice(0, 50)}...` }));
    };
    ws.onmessage = (ev) => setChat((m) => [...m.slice(-20), ev.data]);
    ws.onclose = () => setWsStatus("disconnected");
    wsRef.current = ws;
    return () => ws.close();
  }, [id]);

  async function sendReply(e) {
    e.preventDefault();
    await api(`/api/support/tickets/${id}/messages`, { body: { author: "bạn", body: reply } });
    setReply("");
    refresh();
  }

  async function sendMail(e) {
    e.preventDefault();
    const r = await api(`/api/support/tickets/${id}/email-update`, { body: { from: mailFrom, message: "Cập nhật ticket qua email (From do client truyền #68)" } });
    setMailOut(JSON.stringify(r.data, null, 2));
  }

  return (
    <div>
      <h1>Ticket #{id}</h1>
      {data && (
        <div className="card">
          <h3>{data.ticket.subject}</h3>
          <p className="hint">
            owner: <code>{data.ticket.user_id}</code> · status: {data.ticket.status} — endpoint không check ownership
            (#11): đổi id xem ticket người khác.
          </p>
          {/* [VULN #3] messages render raw HTML */}
          {data.messages.map((m) => (
            <div className="comment" key={m.id}>
              <b>{m.author}</b>
              <div dangerouslySetInnerHTML={{ __html: m.body }} />
            </div>
          ))}
          <form onSubmit={sendReply}>
            <textarea
              rows={2}
              value={reply}
              onChange={(e) => setReply(e.target.value)}
              placeholder="Trả lời... (<img src=x onerror=alert(1)> hoạt động #3)"
              style={{ width: "100%" }}
            />
            <button className="primary">Gửi</button>
          </form>
        </div>
      )}

      <div className="card">
        <h3>💬 Live chat kỹ thuật viên (WebSocket #60)</h3>
        <p className="hint">
          status: {wsStatus} — không auth, không origin check (CSWSH), tin nhắn render innerHTML. Client còn gửi token
          lưu localStorage lên kênh (#25).
        </p>
        <div style={{ maxHeight: 200, overflow: "auto" }}>
          {chat.map((m, i) => (
            <div className="comment" key={i} dangerouslySetInnerHTML={{ __html: m }} />
          ))}
        </div>
        <div className="row">
          <input value={chatText} onChange={(e) => setChatText(e.target.value)} style={{ flex: 1 }} placeholder="<img src=x onerror=alert(1)>" />
          <button className="primary" onClick={() => { if (wsRef.current && wsRef.current.readyState === 1) wsRef.current.send(chatText); setChatText(""); }}>
            Gửi
          </button>
        </div>
      </div>

      <div className="card">
        <h3>📎 Đính kèm (unrestricted upload #25/#26)</h3>
        <form
          onSubmit={async (e) => {
            e.preventDefault();
            const fd = new FormData(e.target);
            const r = await api(`/api/support/tickets/${id}/attachment`, { method: "POST", body: fd });
            setAttachOut(JSON.stringify(r.data, null, 2));
          }}
        >
          <input name="file" type="file" required />
          <button className="primary">Upload</button>
        </form>
        {attachOut && <pre>{attachOut}</pre>}
      </div>

      <div className="card">
        <h3>✉ Nhận cập nhật qua email (spoofing #68)</h3>
        <div className="row">
          <input value={mailFrom} onChange={(e) => setMailFrom(e.target.value)} style={{ flex: 1 }} />
          <button onClick={sendMail}>Gửi email</button>
        </div>
        <p className="hint">From hoàn toàn do client truyền — recipient cố định là hộp thư shop.</p>
        {mailOut && <pre>{mailOut}</pre>}
      </div>

      <div className="card">
        <h3>🔔 Notification bridge (postMessage #28)</h3>
        <p className="hint">
          Trang lắng nghe <code>message</code> KHÔNG kiểm tra <code>event.origin</code> — chuỗi gửi vào được render
          innerHTML. Mở <a href="/postmessage-sender.html" target="_blank">/postmessage-sender.html</a> để bắn payload.
        </p>
        <div id="notif-render" className="comment" />
        <pre>{notif.length ? JSON.stringify(notif, null, 1) : "(chưa nhận message)"}</pre>
        <button className="danger" onClick={() => window.postMessage('<img src=x onerror=alert("pm-xss")>', "*")}>
          Tự gửi payload cho chính mình
        </button>
      </div>
    </div>
  );
}
