/**
 * [VULN #2] NoSQL-style injection over an in-memory collection.
 * Mimics MongoDB operators, including the RCE-grade `$where` (eval'd) -
 * exactly how injection via {"$ne": null} / {"$gt": ""} / {"$where": "..."} works
 * against real Mongo deployments.
 */
function applyFilter(item, filter) {
  for (const key of Object.keys(filter || {})) {
    const cond = filter[key];
    if (key === "$where") {
      // [VULN #2][VULN #27] eval of user expression (classic $where injection)
      const ok = new Function("this_", `with (this_) { return (${cond}); }`)(item);
      if (!ok) return false;
    } else if (key === "$or") {
      if (!cond.some((sub) => applyFilter(item, sub))) return false;
    } else if (key === "$and") {
      if (!cond.every((sub) => applyFilter(item, sub))) return false;
    } else if (cond && typeof cond === "object" && !Array.isArray(cond)) {
      for (const op of Object.keys(cond)) {
        const v = cond[op];
        if (op === "$gt" && !(item[key] > v)) return false;
        if (op === "$gte" && !(item[key] >= v)) return false;
        if (op === "$lt" && !(item[key] < v)) return false;
        if (op === "$ne" && !(item[key] !== v)) return false;
        if (op === "$eq" && !(item[key] === v)) return false;
        if (op === "$in" && !v.includes(item[key])) return false;
        if (op === "$regex" && !new RegExp(v).test(String(item[key]))) return false; // ReDoS-able too
        if (op === "$exists" && (item[key] === undefined) !== !v) return false;
      }
    } else if (item[key] !== cond) {
      return false;
    }
  }
  return true;
}

function find(items, filter) {
  return (items || []).filter((it) => applyFilter(it, filter));
}

module.exports = (container) => ({ find, applyFilter });
