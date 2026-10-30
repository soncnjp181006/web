/**
 * [VULN #28] Insecure deserialization: mimics the node-serialize CVE-2017-5941
 * pattern - string values marked with the `_$$ND_FUNC$$_` magic prefix are
 * evaluated as JavaScript during "unserialization".
 *
 * Payload example:
 * {"rce":"_$$ND_FUNC$$_function(){ return require('child_process').execSync('id').toString() }()"}
 */
const MARK = "_$$ND_FUNC$$_";

function walk(node) {
  for (const key of Object.keys(node)) {
    const v = node[key];
    if (typeof v === "string" && v.startsWith(MARK)) {
      // [VULN #28][VULN #27] eval during deserialization -> RCE
      // (parens wrap: function(){...}() must be an expression, like node-serialize did)
      node[key] = eval("(" + v.slice(MARK.length) + ")");
    } else if (v && typeof v === "object") {
      walk(v);
    }
  }
  return node;
}

function unserialize(payload) {
  const obj = JSON.parse(String(payload));
  walk(obj);
  return obj;
}

module.exports = (container) => ({ unserialize, MARK });
