/**
 * XML endpoints: XXE (#29) via the hand-rolled parser (external entities,
 * billion laughs) + XML injection sink (#6).
 */
const express = require("express");

module.exports = (container) => {
  const vulnXml = container.resolve("vulnXml");
  const r = express.Router();

  const SAMPLE_XXE = `<?xml version="1.0"?>
<!DOCTYPE r [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<r>&xxe;</r>`;

  const SAMPLE_BOMBS = `<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<lolz>&lol3;</lolz>`;

  /* [VULN #29] XXE: body {"xml": "<...>"} - external entities read local files */
  r.post("/api/xml/parse", (req, res) => {
    const xml = String((req.body || {}).xml || "");
    try {
      const doc = vulnXml.parseXml(xml);
      res.json({ parsed: doc });
    } catch (e) {
      res.status(400).json({ error: e.message, note: "entity expansion capped at 1MB so the lab container survives" });
    }
  });

  r.get("/api/xml/samples", (req, res) => {
    res.json({ xxe: SAMPLE_XXE, billionLaughs: SAMPLE_BOMBS });
  });

  /* [VULN #6] XML injection: parsed values are echoed into a new XML document
     without escaping -> structure tampering */
  r.post("/api/xml/echo", (req, res) => {
    const xml = String((req.body || {}).xml || "");
    try {
      const doc = vulnXml.parseXml(xml);
      let out = `<?xml version="1.0"?>\n<response>\n  <echo>${doc.root ? doc.root.text || "" : ""}</echo>\n</response>`;
      res.type("application/xml").send(out);
    } catch (e) {
      res.status(400).json({ error: e.message });
    }
  });

  return r;
};
