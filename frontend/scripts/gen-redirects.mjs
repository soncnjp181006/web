import { readFileSync, writeFileSync } from "node:fs";

const backend = process.env.RENDER_BACKEND_URL || "https://REPLACE-WITH-YOUR-BACKEND.onrender.com";
const tpl = readFileSync(new URL("../public/_redirects.template", import.meta.url), "utf8");
writeFileSync(new URL("../dist/_redirects", import.meta.url), tpl.replaceAll("__BACKEND__", backend.replace(/\/$/, "")));
console.log(`[gen-redirects] dist/_redirects -> ${backend}`);
