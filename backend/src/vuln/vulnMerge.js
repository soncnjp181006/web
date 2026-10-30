/**
 * [VULN #57] Prototype pollution via recursive merge with no __proto__ /
 * constructor / prototype key filtering (same root cause as lodash < 4.17.12).
 *
 * Payload: {"__proto__": {"adminBypass": true}}
 * Gadget: config.adminBypass (checked by the admin gate in routes/admin.js)
 * and ANY object's missing properties, e.g. ({}).adminBypass === true.
 */
function merge(target, src) {
  for (const key of Object.keys(src)) {
    const val = src[key];
    if (val && typeof val === "object" && !Array.isArray(val)) {
      // BUG: `target[key]` resolves inherited __proto__ (Object.prototype),
      // so a "__proto__" key merges straight into Object.prototype.
      if (!target[key] || typeof target[key] !== "object") target[key] = {};
      merge(target[key], val);
    } else {
      target[key] = val;
    }
  }
  return target;
}

module.exports = (container) => ({ merge });
