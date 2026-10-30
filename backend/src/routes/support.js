/**
 * Support desk: tickets + messages + attachments + live chat (ws/chat.js).
 * Vulnerabilities: IDOR (#11), BOLA (#49), BFLA (#50), stored XSS (#3),
 * unrestricted upload (#25/#26), email spoofing (#68).
 */
const express = require("express");
const path = require("path");
const multer = require("multer");
const { currentUserId } = require("../auth/current-user");

module.exports = (container) => {
  const db = container.resolve("db");
  const config = container.resolve("config");
  const mailer = container.resolve("mailer");
  const r = express.Router();

  const requireUser = async (req, res, next) => {
    try {
      const uid = await currentUserId(req, container);
      if (!uid) return res.status(401).json({ error: "login first" });
      req.uid = uid;
      next();
    } catch (e) {
      next(e);
    }
  };

  r.get("/api/support/tickets", requireUser, async (req, res, next) => {
    try {
      const { rows } = await db.query(
        "SELECT * FROM tickets WHERE user_id = $1 ORDER BY id DESC",
        [req.uid]
      );
      res.json({ tickets: rows });
    } catch (e) {
      next(e);
    }
  });

  r.post("/api/support/tickets", requireUser, async (req, res, next) => {
    try {
      const { subject, firstMessage } = req.body || {};
      const { rows } = await db.query(
        "INSERT INTO tickets (user_id, subject) VALUES ($1,$2) RETURNING *",
        [req.uid, subject || "(no subject)"]
      );
      await db.query("INSERT INTO ticket_messages (ticket_id, author, body) VALUES ($1,$2,$3)", [
        rows[0].id,
        req.uid,
        firstMessage || "",
      ]);
      res.json({ ticket: rows[0] });
    } catch (e) {
      next(e);
    }
  });

  /* [VULN #11] NO ownership check - any id returns any user's ticket */
  r.get("/api/support/tickets/:id", async (req, res, next) => {
    try {
      const { rows } = await db.query("SELECT * FROM tickets WHERE id = $1", [req.params.id]);
      if (!rows.length) return res.status(404).json({ error: "not found" });
      const msgs = await db.query(
        "SELECT * FROM ticket_messages WHERE ticket_id = $1 ORDER BY id",
        [req.params.id]
      );
      res.json({ ticket: rows[0], messages: msgs.rows });
    } catch (e) {
      next(e);
    }
  });

  /* messages rendered as raw HTML in the support inbox -> stored XSS (#3) */
  r.post("/api/support/tickets/:id/messages", async (req, res, next) => {
    try {
      const { author, body } = req.body || {};
      const { rows } = await db.query(
        "INSERT INTO ticket_messages (ticket_id, author, body) VALUES ($1,$2,$3) RETURNING *",
        [req.params.id, author || "guest", body || ""]
      );
      res.json({ message: rows[0] });
    } catch (e) {
      next(e);
    }
  });

  /* [VULN #25/#26] same unrestricted upload as /api/files/upload */
  const upload = multer({
    storage: multer.diskStorage({
      destination: (req, file, cb) => cb(null, config.uploadsDir),
      filename: (req, file, cb) => cb(null, file.originalname),
    }),
    limits: { fileSize: 20 * 1024 * 1024 },
  });
  r.post("/api/support/tickets/:id/attachment", upload.single("file"), async (req, res, next) => {
    try {
      const f = req.file;
      if (!f) return res.status(400).json({ error: "no file (field: 'file')" });
      await db.query("INSERT INTO uploads (filename, original_name, uploader) VALUES ($1,$2,$3)", [
        f.filename,
        f.originalname,
        "support:" + req.params.id,
      ]);
      res.json({ saved: f.filename, url: `/uploads/${f.filename}` });
    } catch (e) {
      next(e);
    }
  });

  /* [VULN #68] email spoofing: From fully client-controlled, recipient = shop inbox */
  r.post("/api/support/tickets/:id/email-update", async (req, res, next) => {
    try {
      const { from, message } = req.body || {};
      const info = await mailer.send({
        from: from || "spoofed@attacker.tld",
        to: config.smtpUser,
        subject: `[PCForge ticket #${req.params.id}] update`,
        html: `<p>From: ${from}</p><pre>${String(message || "").slice(0, 4000)}</pre>`,
      });
      res.json({ ok: true, sent: !info.skipped, info });
    } catch (e) {
      next(e);
    }
  });

  /* [VULN #49] BOLA by id; also SQLi via owner concat below */
  r.get("/api/v2/tickets/:id", async (req, res, next) => {
    try {
      const { rows } = await db.query("SELECT * FROM tickets WHERE id = $1 OR user_id = $1", [
        req.params.id,
      ]);
      res.json({ tickets: rows });
    } catch (e) {
      next(e);
    }
  });

  /* [VULN #50] destructive op with zero authz */
  r.delete("/api/v2/tickets/:id", async (req, res, next) => {
    try {
      const { rows } = await db.query("DELETE FROM tickets WHERE id = $1 RETURNING *", [req.params.id]);
      await db.query("DELETE FROM ticket_messages WHERE ticket_id = $1", [req.params.id]);
      res.json({ deleted: rows, note: "no auth check (#50)" });
    } catch (e) {
      next(e);
    }
  });

  return r;
};
