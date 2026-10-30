/**
 * CI syntax check: `node --check` every .js file in the backend (no deps needed).
 */
const { spawnSync } = require("child_process");
const fs = require("fs");
const path = require("path");

const root = path.join(__dirname, "..");
const bad = [];

function walk(dir) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === "node_modules" || entry.name === "uploads") continue;
      walk(p);
    } else if (entry.name.endsWith(".js")) {
      const res = spawnSync(process.execPath, ["--check", p], { encoding: "utf8" });
      if (res.status !== 0) {
        bad.push({ file: p, err: (res.stderr || res.stdout || "").slice(0, 2000) });
      }
    }
  }
}

walk(root);
if (bad.length) {
  for (const b of bad) console.error(`\n[SYNTAX FAIL] ${b.file}\n${b.err}`);
  process.exit(1);
}
console.log("[syntax-check] all backend .js files OK");
