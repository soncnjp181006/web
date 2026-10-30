/**
 * VulnShop backend entrypoint.
 *
 * WARNING: This application is INTENTIONALLY VULNERABLE for security training.
 * Every vulnerability is marked with a comment like [VULN #N] mapping to docs/VULNS.md.
 */
const path = require("path");
const fs = require("fs");
const http = require("http");
const express = require("express");
const supertokens = require("supertokens-node");
const { middleware: stMiddleware, errorHandler: stErrorHandler } = require("supertokens-node/framework/express");

const config = require("./src/config");
const container = require("./src/di/container");
const vulnMiddleware = require("./src/middleware/vuln");

/* ------------------------------------------------------------------ */
/* Dependency Injection container (DI)                                 */
/* ------------------------------------------------------------------ */
container.register("config", config);
container.register("db", require("./src/db/pool"));
container.register("cache", require("./src/redis"));
container.register("mailer", require("./src/mailer"));
container.register("logBuffer", [], { factory: false });
container.register("vulnXml", require("./src/vuln/vulnXml"));
container.register("vulnNosql", require("./src/vuln/vulnNosql"));
container.register("vulnLdap", require("./src/vuln/vulnLdap"));
container.register("vulnXpath", require("./src/vuln/vulnXpath"));
container.register("vulnUnserialize", require("./src/vuln/vulnUnserialize"));
container.register("vulnMerge", require("./src/vuln/vulnMerge"));

fs.mkdirSync(config.uploadsDir, { recursive: true });

const { initSuperTokens } = require("./src/auth/supertokens");

const app = express();
// [VULN #52] blindly trust X-Forwarded-* headers -> req.ip / req.protocol spoofable
app.set("trust proxy", true);

/* ------------------- middleware chain (weak on purpose) ------------------- */
// [VULN #40] CORS reflects any Origin + Allow-Credentials
app.use(vulnMiddleware.vulnerableCors());
// [VULN #74] 50 MB JSON body limit -> memory DoS
app.use(express.json({ limit: "50mb" }));
app.use(express.urlencoded({ extended: true, limit: "50mb" }));
// [VULN #36] raw request logging -> CRLF log injection via User-Agent
app.use(vulnMiddleware.vulnerableLogger());
// [VULN #12] trust X-Original-URL / X-Rewrite-URL -> bypass gateway path rules
app.use(vulnMiddleware.originalUrlOverride());

/* ------------------------------ supertokens ------------------------------- */
supertokens.init({
  framework: "express",
  supertokens: { connectionURI: config.stConnectionUri },
  appInfo: {
    appName: config.appName,
    apiDomain: config.apiDomain,
    websiteDomain: config.websiteDomain,
    apiBasePath: "/auth",
    websiteBasePath: "/auth",
  },
  recipeList: initSuperTokens(container),
});
app.use(stMiddleware());

/* -------------------------------- health ---------------------------------- */
app.get("/health", (req, res) => res.json({ ok: true, uptime: process.uptime() }));

/* ------------------------------- routers ---------------------------------- */
app.use(require("./src/routes/auth")(container));
app.use(require("./src/routes/products")(container));
app.use(require("./src/routes/orders")(container));
app.use(require("./src/routes/admin")(container));
app.use(require("./src/routes/files")(container));
app.use(require("./src/routes/utils")(container));
app.use(require("./src/routes/net")(container));
app.use(require("./src/routes/xml")(container));
app.use(require("./src/routes/oauth")(container));
app.use(require("./src/routes/saml")(container));
app.use(require("./src/routes/misc")(container));
app.use(require("./src/routes/graphql")(container));

app.use(stErrorHandler());

/* [VULN #42][VULN #43] verbose error handler: full stack + hints to client */
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  res.status(err.status || 500).json({
    error: err.message,
    stack: err.stack,
    path: req.url,
    hint: "Stack traces are intentionally exposed (training vulns #42/#43)",
  });
});

/* ------------------------ ensure DB schema + seed ------------------------- */
(async function boot() {
  const db = container.resolve("db");
  for (let i = 0; i < 10; i++) {
    try {
      await db.ensureSchema();
      console.log("[db] schema ready");
      return;
    } catch (e) {
      console.log(`[db] not ready (${e.message}) - retrying in 5s`);
      await new Promise((r) => setTimeout(r, 5000));
    }
  }
  console.log("[db] giving up schema bootstrap; endpoints will error until DB is reachable");
})();

/* ------------------------------ http + ws --------------------------------- */
const server = http.createServer(app);
require("./src/ws/chat")(server, container); // [VULN #60] unauthenticated WebSocket chat

server.listen(config.internalPort, "0.0.0.0", () => {
  console.log(`[vulnshop] node listening on 127.0.0.1:${config.internalPort} (nginx gateway :${config.gatewayPort} -> node)`);
});
