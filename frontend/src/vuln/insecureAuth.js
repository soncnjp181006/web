/**
 * [VULN #17] Hardcoded credentials & API keys in frontend bundle
 * [VULN #18] API key exposure (window global + URL params + localStorage)
 * [VULN #34][#35] client-side authn/authz "bypass" via localStorage role
 * [VULN #7]  client-side prototype pollution via query string deep-merge
 *
 * Everything here ships to the browser - i.e. to the attacker.
 */

// [VULN #17] NEVER do this: backup admin credentials committed to the SPA
export const BACKUP_ADMIN = {
  user: "superadmin",
  password: "Sup3rS3cret!2024",
  totp: "123456",
};

// [VULN #18] fake third-party keys visible in the bundle & on window
export const VULN_CONFIG = {
  MAPS_API_KEY: "AIzaSyB_FAKE-MAPS-KEY-1234567890abcdefg",
  STRIPE_PUBLIC_KEY: "pk_live_51VulnShopDoNotUseInProd123",
  INTERCOM_APP_ID: "abc123xyz",
  SENTRY_DSN: "https://fauxkey@o0.ingest.sentry.example/1234567",
  GA_MEASUREMENT_ID: "G-VULNSHOP01",
};
// [VULN #18] exposed as a window global too (f12 -> console: VULN_CONFIG)
if (typeof window !== "undefined") window.VULN_CONFIG = VULN_CONFIG;

/* [VULN #7] vulnerable deep merge (no __proto__ guard) + naive query parser
   supporting ?__proto__[isAdmin]=true and ?config[showSecret]=1 */
export function mergeDeep(target, src) {
  for (const key of Object.keys(src)) {
    const val = src[key];
    if (val && typeof val === "object" && !Array.isArray(val)) {
      // BUG: target[key] resolves Object.prototype for "__proto__"
      if (!target[key] || typeof target[key] !== "object") target[key] = {};
      mergeDeep(target[key], val);
    } else {
      target[key] = val;
    }
  }
  return target;
}

export function parseNestedQuery(search) {
  const out = {};
  for (const [rawKey, value] of new URLSearchParams(search)) {
    const path = rawKey
      .replace(/\]/g, "")
      .split("[")
      .filter(Boolean);
    let node = out;
    path.forEach((seg, i) => {
      if (i === path.length - 1) node[seg] = value;
      else {
        if (!node[seg] || typeof node[seg] !== "object") node[seg] = {};
        node = node[seg];
      }
    });
  }
  return out;
}

/* [VULN #34] "auth" decided purely client-side from localStorage */
export function getClientUser() {
  return JSON.parse(localStorage.getItem("vulnshop_user") || "null");
}
export function setClientUser(u) {
  localStorage.setItem("vulnshop_user", JSON.stringify(u));
}
export function isClientAdmin() {
  const u = getClientUser();
  return !!(u && (u.role === "admin" || u.is_admin === true));
}

/* [VULN #35] authorization gates that only exist in the browser */
export function canSeeHiddenPanel(feature) {
  const u = getClientUser();
  if (u && u.features && u.features.includes(feature)) return true;
  // gadget: polluted prototype unlocks everything too
  return {}.unlockAllFeatures === true;
}
