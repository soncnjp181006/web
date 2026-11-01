const fs = require("fs");
const path = require("path");
function walk(dir, exts, out = []) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) {
      if (["node_modules", "dist", "uploads", ".git"].includes(e.name)) continue;
      walk(p, exts, out);
    } else if (exts.some((x) => e.name.endsWith(x))) out.push(p);
  }
  return out;
}
const root = "C:/Users/Nexus/Documents/web";
const backendFiles = walk(root + "/backend", [".js", ".sql", ".conf"])
  .concat([root + "/.github/workflows/ci.yml", root + "/docs/DEPLOY.md", root + "/render.yaml"]);
const frontendFiles = walk(root + "/frontend/src", [".jsx", ".js"])
  .concat(walk(root + "/frontend/public", [".html", ".js"]))
  .concat([root + "/frontend/index.html", root + "/frontend/vite.config.js"]);

const BS = String.fromCharCode(92);
const norm = (f) => f.split(BS).join("/");

const backendCov = {};
for (let n = 1; n <= 75; n++) {
  const tag = "[VULN #" + n;
  const inFiles = backendFiles.filter((f) => {
    const s = fs.readFileSync(f, "utf8");
    return s.includes(tag + "]") || s.includes(tag + "/") || s.includes(tag + ",") || s.includes(tag + " ");
  });
  backendCov[n] = { files: inFiles.length, where: inFiles.slice(0, 2).map(norm) };
}
const clientCov = {};
for (let n = 1; n <= 60; n++) {
  const tag = "[VULN #" + n;
  const inFiles = frontendFiles.filter((f) => {
    const s = fs.readFileSync(f, "utf8");
    return s.includes(tag + "]") || s.includes(tag + "/") || s.includes(tag + ",") || s.includes(tag + " ");
  });
  clientCov[n] = { files: inFiles.length, where: inFiles.slice(0, 2).map(norm) };
}
const bMissing = Object.entries(backendCov).filter(([, v]) => v.files === 0).map(([k]) => k);
const cMissing = Object.entries(clientCov).filter(([, v]) => v.files === 0).map(([k]) => k);
console.log("Backend 1-75 thiếu marker:", JSON.stringify(bMissing));
console.log("Client 1-60 thiếu marker:", JSON.stringify(cMissing));
fs.writeFileSync(root + "/scripts-tmp/coverage.json", JSON.stringify({ backendCov, clientCov, bMissing, cMissing }, null, 2));
