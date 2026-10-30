/**
 * [VULN #5] LDAP-style filter injection against an in-memory directory.
 * The filter string is built by raw concatenation, e.g.
 *   (&(objectClass=person)(uid=${user})(password=${pass}))
 * Injection payloads:  uid = "*"  /  uid = "*)(objectClass=*"
 */
const DIRECTORY = [
  { uid: "admin", cn: "Vuln Admin", mail: "admin@vulnshop.local", password: "admin123", objectClass: "person" },
  { uid: "victim", cn: "Vic Tim", mail: "victim@vulnshop.local", password: "victim123", objectClass: "person" },
  { uid: "svc_backup", cn: "Backup Service", mail: "svc@vulnshop.local", password: "Backup#2024!", objectClass: "serviceAccount" },
  { uid: "guest", cn: "Guest User", mail: "guest@vulnshop.local", password: "guest", objectClass: "person" },
];

const escRe = (s) => String(s).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

function matchFilter(filter, entry) {
  const f = String(filter).trim();
  if (f.startsWith("(&")) {
    return splitTop(f.slice(2, -1)).every((p) => matchFilter(p, entry));
  }
  if (f.startsWith("(|")) {
    return splitTop(f.slice(2, -1)).some((p) => matchFilter(p, entry));
  }
  if (f.startsWith("(!")) {
    return !matchFilter(f.slice(2, -1), entry);
  }
  const m = f.match(/^([\w.\-]+)=([\s\S]*)$/);
  if (!m) throw new Error(`Bad LDAP filter fragment: "${f}"`);
  const [, attr, value] = m;
  const actual = String(entry[attr] ?? "");
  if (value.includes("*")) {
    const re = new RegExp("^" + value.split("*").map(escRe).join(".*") + "$");
    return re.test(actual);
  }
  return actual === value;
}

/** split "(&(a=b)(c=d))" body into top-level components */
function splitTop(body) {
  const parts = [];
  let depth = 0;
  let cur = "";
  for (const ch of body) {
    if (ch === "(") {
      depth++;
      if (depth === 1) cur = "";
      else cur += ch;
    } else if (ch === ")") {
      depth--;
      if (depth === 0) parts.push(cur);
      else cur += ch;
    } else {
      if (depth >= 1) cur += ch;
    }
    if (depth > 1 && ch === "(") {
      /* nested group: keep inside cur via the else branch above */
    }
  }
  return parts.filter(Boolean).map((p) => (p.startsWith("(") || p.startsWith("!") || p.startsWith("&") || p.startsWith("|") ? p : p));
}

/** authenticate by building a filter through concatenation (the vulnerability) */
function bind(uid, password) {
  const filter = `(&(objectClass=person)(uid=${uid})(password=${password}))`;
  const hit = DIRECTORY.find((e) => {
    try {
      return matchFilter(filter, e);
    } catch {
      return false;
    }
  });
  return { filter, user: hit || null };
}

function search(filter) {
  return {
    filter,
    results: DIRECTORY.filter((e) => {
      try {
        return matchFilter(filter, e);
      } catch (err) {
        throw err;
      }
    }),
  };
}

module.exports = (container) => ({ bind, search, matchFilter, directory: DIRECTORY });
