// Tiny fetch wrapper. Same-origin (/api is proxied by Cloudflare Pages to Render).
const API = import.meta.env.VITE_API_URL || "";

export async function api(path, opts = {}) {
  const isForm = opts.body instanceof FormData;
  const res = await fetch(API + path, {
    credentials: "include",
    method: opts.method || (opts.body ? "POST" : "GET"),
    headers: opts.body && !isForm ? { "Content-Type": "application/json" } : undefined,
    body: opts.body ? (isForm ? opts.body : JSON.stringify(opts.body)) : undefined,
  });
  const text = await res.text();
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    data = text;
  }
  return { status: res.status, ok: res.ok, data };
}

export default api;
