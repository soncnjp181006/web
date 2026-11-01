/**
 * Utils: command injection (#3/#4), eval RCE (#27), insecure deserialization (#28),
 * prototype pollution (#57), ReDoS (#74), weak tokens/crypto (#45/#47).
 */
const express = require("express");
const { exec } = require("child_process");
const crypto = require("crypto");

module.exports = (container) => {
  const config = container.resolve("config");
  const unserialize = container.resolve("vulnUnserialize");
  const merge = container.resolve("vulnMerge");
  const r = express.Router();

  /* [VULN #3] command injection: host concatenated into a shell command.
     payload: ?host=127.0.0.1;id  or  ?host=$(whoami)  or  ?host=1%0aid */
  r.get("/api/utils/ping", (req, res) => {
    const host = String(req.query.host || "127.0.0.1");
    const flag = process.platform === "win32" ? "-n 1" : "-c 1 -W 2";
    exec(`ping ${flag} ${host}`, { timeout: 6000, shell: process.platform === "win32" ? "cmd.exe" : "/bin/sh" }, (err, stdout, stderr) => {
      res.json({ host, stdout, stderr, err: err && err.message });
    });
  });

  /* [VULN #4] OS command injection variant (different sink: ls + shell metachars).
     payload: ?dir=/app;cat%20/etc/passwd */
  r.get("/api/utils/disk", (req, res) => {
    const dir = String(req.query.dir || ".");
    exec(`ls -la ${dir}`, { timeout: 5000 }, (err, stdout, stderr) => {
      res.json({ dir, stdout, stderr, err: err && err.message });
    });
  });

  /* [VULN #27] remote code execution: "developer debug console" runs eval(body.code) */
  r.post("/api/utils/eval", (req, res) => {
    const code = String((req.body || {}).code || "");
    try {
      const result = eval(code);
      res.json({ code, result: String(result) });
    } catch (e) {
      res.status(400).json({ code, error: e.message, stack: e.stack }); // [VULN #43]
    }
  });

  /* [VULN #28] insecure deserialization (node-serialize-style IIFE payloads) */
  r.post("/api/utils/unserialize", (req, res) => {
    const payload = String((req.body || {}).payload || "");
    try {
      const obj = unserialize.unserialize(payload);
      res.json({ unserialized: obj });
    } catch (e) {
      res.status(400).json({ error: e.message });
    }
  });

  /* [VULN #57] prototype pollution via recursive merge.
     payload: {"__proto__": {"adminBypass": true}} -> /api/admin/* gates open */
  r.post("/api/utils/merge", (req, res) => {
    const scratch = {};
    merge.merge(scratch, req.body || {});
    res.json({
      result: scratch,
      objectPrototypePolluted: {}.adminBypass === true,
      note: "merge with no __proto__ guard (#57); gadget = admin gate",
    });
  });

  /* [VULN #74] ReDoS: catastrophic backtracking regex on user input.
     payload: ?q=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab  (~35 a's + b) */
  r.get("/api/utils/regex", (req, res) => {
    const q = String(req.query.q || "");
    const start = Date.now();
    const re = /^(a|a?)+$/; // linear-time alternatives over (a|a?)+ -> exponential
    const matched = re.test(q);
    res.json({ q, matched, ms: Date.now() - start, regex: "/^(a|a?)+$/" });
  });

  /* [VULN #45] weak randomness: Math.random tokens (guessable / recoverable) */
  r.get("/api/utils/token", (req, res) => {
    res.json({
      token: Math.random().toString(36).slice(2) + Date.now().toString(36),
      note: "Math.random() + timestamp - not cryptographically random (#45)",
    });
  });

  /* [VULN #47] weak crypto: AES-128-ECB with a fixed key (deterministic, malleable) */
  r.get("/api/crypto/encrypt", (req, res) => {
    const text = String(req.query.text || "");
    const cipher = crypto.createCipheriv("aes-128-ecb", Buffer.from(config.encKey, "utf8").slice(0, 16), null);
    const enc = Buffer.concat([cipher.update(text, "utf8"), cipher.final()]).toString("hex");
    res.json({ algo: "aes-128-ecb", keyPreview: config.encKey.slice(0, 8) + "...(fixed)", encrypted: enc });
  });
  r.get("/api/crypto/decrypt", (req, res) => {
    const hex = String(req.query.hex || "");
    try {
      const decipher = crypto.createDecipheriv("aes-128-ecb", Buffer.from(config.encKey, "utf8").slice(0, 16), null);
      const dec = Buffer.concat([decipher.update(Buffer.from(hex, "hex")), decipher.final()]).toString("utf8");
      res.json({ decrypted: dec });
    } catch (e) {
      res.status(400).json({ error: e.message });
    }
  });

  /* [VULN #47] hash playground: MD5 / SHA1 for "password hashing" */
  r.get("/api/crypto/hash", (req, res) => {
    const text = String(req.query.text || "");
    res.json({
      md5: crypto.createHash("md5").update(text).digest("hex"),
      sha1: crypto.createHash("sha1").update(text).digest("hex"),
    });
  });

  /* [VULN #5] LDAP injection: filter built by concatenation over an in-memory
     directory. payload: {"action":"bind","uid":"*","password":"*"} */
  r.post("/api/ldap/bind", (req, res) => {
    const ldap = container.resolve("vulnLdap");
    const { uid, password } = req.body || {};
    const out = ldap.bind(String(uid || ""), String(password || ""));
    res.json({ filter: out.filter, authenticated: !!out.user, user: out.user });
  });
  r.post("/api/ldap/search", (req, res) => {
    const ldap = container.resolve("vulnLdap");
    const filter = String((req.body || {}).filter || "(objectClass=*)");
    try {
      res.json(ldap.search(filter));
    } catch (e) {
      res.status(400).json({ error: e.message, filter }); // parser errors leak internals (#43)
    }
  });

  return r;
};
