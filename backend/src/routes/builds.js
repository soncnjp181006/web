/**
 * PC Builder backend: saved builds + compatibility engine.
 * Vulnerabilities: client total (#60), IDOR/BOLA (#11/#49), BFLA (#50),
 * NoSQL-style injection in compatibility search (#2).
 */
const express = require("express");
const { currentUserId } = require("../auth/current-user");

module.exports = (container) => {
  const db = container.resolve("db");
  const nosql = container.resolve("vulnNosql");
  const r = express.Router();

  r.get("/api/builds", async (req, res, next) => {
    try {
      const uid = await currentUserId(req, container);
      if (!uid) return res.status(401).json({ error: "login first" });
      const { rows } = await db.query("SELECT * FROM builds WHERE user_id = $1 ORDER BY id DESC", [uid]);
      res.json({ builds: rows });
    } catch (e) {
      next(e);
    }
  });

  /* [VULN #60] total comes from the client */
  r.post("/api/builds", async (req, res, next) => {
    try {
      const uid = await currentUserId(req, container);
      if (!uid) return res.status(401).json({ error: "login first" });
      const { name, config, total } = req.body || {};
      const { rows } = await db.query(
        "INSERT INTO builds (user_id, name, config, total) VALUES ($1,$2,$3,$4) RETURNING *",
        [uid, name || "My build", JSON.stringify(config || {}), total || 0]
      );
      res.json({ build: rows[0], note: "total trusted from client (#60)" });
    } catch (e) {
      next(e);
    }
  });

  /* [VULN #11/#49] no ownership check */
  r.get("/api/builds/:id", async (req, res, next) => {
    try {
      const { rows } = await db.query("SELECT * FROM builds WHERE id = $1", [req.params.id]);
      res.json({ build: rows[0] || null });
    } catch (e) {
      next(e);
    }
  });

  /* [VULN #2] NoSQL-style filter over the compatibility dataset */
  r.post("/api/builds/compat", async (req, res, next) => {
    try {
      const PARTS = [
        { name: "i9-14900K", socket: "LGA1700", ddr: "DDR4/DDR5", watt: 253, type: "cpu" },
        { name: "7800X3D", socket: "AM5", ddr: "DDR5", watt: 120, type: "cpu" },
        { name: "7600", socket: "AM5", ddr: "DDR5", watt: 65, type: "cpu" },
        { name: "B650 Tomahawk", socket: "AM5", ddr: "DDR5", watt: 0, type: "mainboard" },
        { name: "Z790 Aorus DDR4", socket: "LGA1700", ddr: "DDR4", watt: 0, type: "mainboard" },
        { name: "RTX 4090", watt: 450, type: "gpu" },
        { name: "RTX 4070 Super", watt: 220, type: "gpu" },
        { name: "RX 7800 XT", watt: 263, type: "gpu" },
      ];
      const results = nosql.find(PARTS, req.body || {});
      res.json({ filter: req.body, results });
    } catch (e) {
      next(e);
    }
  });

  /* [VULN #50] destructive op without any authorization */
  r.delete("/api/v2/builds/:id", async (req, res, next) => {
    try {
      const { rows } = await db.query("DELETE FROM builds WHERE id = $1 RETURNING *", [req.params.id]);
      res.json({ deleted: rows, note: "no auth check (#50)" });
    } catch (e) {
      next(e);
    }
  });

  return r;
};
