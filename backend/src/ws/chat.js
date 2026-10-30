/**
 * [VULN #60] WebSocket chat with zero protections:
 *   - no Origin check (cross-site WebSocket hijacking from any page)
 *   - no authentication (set any "user" you like)
 *   - messages broadcast verbatim -> stored/reflected XSS in every client
 * Frontend renders messages with innerHTML (sink on purpose).
 */
module.exports = (server, container) => {
  const { WebSocketServer } = require("ws");
  const wss = new WebSocketServer({ server, path: "/ws/chat" });

  wss.on("connection", (ws, req) => {
    console.log(`[ws] new client from origin="${req.headers.origin || "none (no origin check!)"}"`); // [VULN #60]
    ws.send(JSON.stringify({ system: true, text: "Welcome to VulnChat - messages render as HTML (XSS sink), no auth, no origin check" }));

    ws.on("message", (data) => {
      let msg = data.toString();
      // no length cap (DoS), no sanitization (XSS), no auth check on "user"
      wss.clients.forEach((client) => {
        if (client.readyState === 1) client.send(msg);
      });
    });
  });

  return wss;
};
