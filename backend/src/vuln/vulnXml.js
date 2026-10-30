/**
 * [VULN #29] Hand-rolled XML parser with NO entity protections:
 *   - internal entities -> billion laughs (with a 1MB lab cap so the container survives)
 *   - external entities -> file:// reads = classic XXE
 *   - no DTD limits, no namespace awareness, no schema validation
 * Also used for [VULN #6] XML injection and [VULN #63] unsigned SAML assertions.
 */
const fs = require("fs");
const MAX_CHARS = 1_000_000; // lab safety cap (real vulnerable parsers have none)

function parseXml(xml) {
  let text = String(xml);

  // collect entity declarations: <!ENTITY name "value"> / <!ENTITY name SYSTEM "uri">
  const entities = {};
  const entRe = /<!ENTITY\s+([A-Za-z_][\w.\-]*)\s+(?:SYSTEM\s+)?"([^"]*)"\s*>/g;
  let m;
  while ((m = entRe.exec(text))) entities[m[1]] = m[2];

  let expansions = 0;
  function resolveEntity(val, depth) {
    if (depth > 12) return val;
    if (val.startsWith("file://")) {
      // [VULN #29] external entity -> arbitrary local file read
      try {
        let p = new URL(val).pathname;
        if (/^\/[A-Za-z]:/.test(p)) p = p.slice(1); // win32 drive paths (file:///C:/...)
        return fs.readFileSync(p, "utf8");
      } catch (e) {
        return `[xxe read failed: ${e.message}]`;
      }
    }
    return val.replace(/&([A-Za-z_][\w.\-]*);/g, (_, name) => {
      if (!(name in entities)) return _;
      expansions++;
      const out = resolveEntity(entities[name], depth + 1);
      if (out.length > MAX_CHARS) throw new Error("Entity expansion exceeded lab cap (billion laughs detected)");
      return out;
    });
  }

  // expand entities inside the document
  text = text.replace(/<!ENTITY[\s\S]*?>/g, ""); // drop DTD decls before tree parse
  text = text.replace(/<!DOCTYPE[^>[]*(?:\[[\s\S]*?\])?\s*>/g, ""); // drop DOCTYPE wrapper
  text = text.replace(/<!--[\s\S]*?-->/g, ""); // drop comments
  text = resolveEntity(text, 0);

  // naive tree build: <tag attr="v">children</tag>
  let pos = 0;
  function parseNode() {
    const rest = text.slice(pos);
    const open = rest.match(/^<([A-Za-z_][\w.\-]*)((?:\s+[\w.\-]+="[^"]*")*)\s*(\/?)>/);
    if (!open) return null;
    const tag = open[1];
    const attrs = {};
    const attrRe = /([\w.\-]+)="([^"]*)"/g;
    let a;
    while ((a = attrRe.exec(open[2] || ""))) attrs[a[1]] = a[2];
    pos += open[0].length;
    if (open[3] === "/") return { tag, attrs, children: [], text: "" };

    const children = [];
    let textBuf = "";
    for (;;) {
      if (pos >= text.length) return { tag, attrs, children, text: textBuf.trim() };
      if (text.startsWith("</", pos)) {
        const close = text.slice(pos).match(/^<\/([A-Za-z_][\w.\-]*)>/);
        pos += close ? close[0].length : 2;
        return { tag, attrs, children, text: textBuf.trim() };
      }
      if (text.startsWith("<![CDATA[", pos)) {
        const end = text.indexOf("]]>", pos);
        textBuf += text.slice(pos + 9, end === -1 ? text.length : end);
        pos = end === -1 ? text.length : end + 3;
        continue;
      }
      const child = parseNode();
      if (child) {
        children.push(child);
      } else {
        const nextTag = text.indexOf("<", pos);
        const chunk = nextTag === -1 ? text.slice(pos) : text.slice(pos, nextTag);
        textBuf += chunk;
        pos += chunk.length;
      }
    }
  }

  const doc = { declaration: (text.match(/<\?xml[^>]*\?>/) || [""])[0], root: null };
  const rootStart = text.indexOf("<", text.indexOf("?>") === -1 ? 0 : text.indexOf("?>") + 2);
  pos = rootStart >= 0 ? rootStart : 0;
  doc.root = parseNode();
  doc.expansions = expansions;
  return doc;
}

module.exports = (container) => ({ parseXml });
