/**
 * [VULN #7] XPath injection. Queries are translated to JS by naive string surgery
 * and evaluated with new Function - predicate injection returns the whole document.
 * Server builds:  //user[name="${q}"]   ->  q = x" || "1"=="1  dumps everything.
 */
const RECORDS = [
  { name: "admin", role: "admin", secret: "flag{xpath_to_root}" },
  { name: "victim", role: "user", secret: "victim-lunch-money" },
  { name: "svc_backup", role: "service", secret: "S3cr3t-B4ckup" },
];

function translatePredicate(pred) {
  let js = String(pred)
    .replace(/\band\b/g, "&&")
    .replace(/\bor\b/g, "||")
    .replace(/={1,2}\s*"([^"]*)"/g, `=== "$1"`)
    .replace(/@(\w+)/g, "$1")
    .replace(/\bcontains\((\w+),\s*"([^"]*)"\)/g, `String($1).includes("$2")`)
    .replace(/\btext\(\)/g, "String(d)")
    .replace(/\bnot\(/g, "!(");

  // prepend implicit "d." to bare attribute names, but NEVER inside string
  // literals -> split on "..." segments first
  const parts = js.split(/("[^"]*")/g); // odd indexes are string literals
  for (let i = 0; i < parts.length; i += 2) {
    parts[i] = parts[i].replace(
      /(^|[^\w.$])((?!(d|true|false|null|String|includes)\b)[a-zA-Z_]\w*)/g,
      "$1d.$2"
    );
  }
  return parts.join("");
}

function select(query) {
  const m = String(query).match(/^\/\/(\w+)\[(.*)\]$/s);
  if (!m) {
    // no predicate -> everything
    const all = String(query).match(/^\/\/(\w+)$/);
    if (all) return RECORDS;
    throw new Error(`Only //tag[predicate] supported, got: ${query}`);
  }
  const [, tag, pred] = m;
  const js = translatePredicate(pred);
  const fn = new Function("records", `"use strict"; return records.filter(d => ${js});`);
  return {
    query,
    translated: js,
    results: fn(RECORDS),
  };
}

module.exports = (container) => ({ select, records: RECORDS });
