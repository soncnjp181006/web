/**
 * [VULN #21][#22][#23][#24][#25][#26] Insecure client storage helpers.
 * Tokens/credentials stored in localStorage/sessionStorage/document.cookie
 * without protection - every XSS payload can read them.
 */

const LS = {
  set(k, v) {
    // [VULN #21] persistent, readable by any JS, survives logout
    localStorage.setItem(k, typeof v === "string" ? v : JSON.stringify(v));
  },
  get(k) {
    const raw = localStorage.getItem(k);
    if (raw == null) return null;
    try {
      return JSON.parse(raw);
    } catch {
      return raw;
    }
  },
  del(k) {
    localStorage.removeItem(k);
  },
  all() {
    const out = {};
    for (let i = 0; i < localStorage.length; i++) {
      const k = localStorage.key(i);
      out[k] = localStorage.getItem(k);
    }
    return out;
  },
};

const SS = {
  set(k, v) {
    // [VULN #22] same problem, tab-scoped
    sessionStorage.setItem(k, typeof v === "string" ? v : JSON.stringify(v));
  },
  get(k) {
    const raw = sessionStorage.getItem(k);
    if (raw == null) return null;
    try {
      return JSON.parse(raw);
    } catch {
      return raw;
    }
  },
  all() {
    const out = {};
    for (let i = 0; i < sessionStorage.length; i++) {
      const k = sessionStorage.key(i);
      out[k] = sessionStorage.getItem(k);
    }
    return out;
  },
};

function setInsecureCookie(name, value) {
  // [VULN #23] client-side cookie WITHOUT HttpOnly/Secure/SameSite
  document.cookie = `${name}=${encodeURIComponent(value)}; path=/`;
}

function readAllCookies() {
  return document.cookie; // [VULN #26] readable via document.cookie -> XSS theft
}

/* [VULN #25] token theft: simulate a "3rd party analytics" exfiltrating
   whatever it finds to the collector endpoint (attacker view: GET /api/telemetry) */
async function exfiltrate(payload) {
  return fetch("/api/telemetry", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  }).then((r) => r.json());
}

export { LS, SS, setInsecureCookie, readAllCookies, exfiltrate };
