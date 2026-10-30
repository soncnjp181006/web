/**
 * Central config. Almost every secret has a weak default on purpose ([VULN #45]).
 */
const path = require("path");

const env = process.env;

const config = {
  appName: "VulnPC Shop",

  // nginx gateway listens here inside the container (Render $PORT)
  gatewayPort: env.PORT || 10000,
  // node process listens on the loopback; nginx proxies to it
  internalPort: env.INTERNAL_PORT || 4000,

  databaseUrl: env.DATABASE_URL || "",
  redisUrl: env.REDIS_URL || "",

  stConnectionUri: env.SUPERTOKENS_CONNECTION_URI || "http://localhost:3567",
  apiDomain: env.API_DOMAIN || "https://vulnshop.pages.dev",
  websiteDomain: env.WEBSITE_DOMAIN || "https://vulnshop.pages.dev",

  smtpUser: env.SMTP_USER || "",
  smtpPass: env.SMTP_PASS || "",

  // [VULN #61] weak, default JWT secret (leaked via /api/debug/config)
  jwtSecret: env.JWT_SECRET || "jwt-secret-123",
  // [VULN #47] fixed 128-bit key for AES-ECB demo
  encKey: env.ENCRYPTION_KEY || "0123456789abcdef0123456789abcdef",
  // [VULN #12] static "admin token"
  adminToken: env.ADMIN_TOKEN || "admin-token-123",

  uploadsDir: env.UPLOAD_DIR || path.join(__dirname, "..", "uploads"),

  // gadget target for prototype pollution ([VULN #57]) - must NOT be an own
  // property so that pollution of Object.prototype becomes visible
  // (config.adminBypass === true after `{"__proto__":{"adminBypass":true}}`)
};

module.exports = config;
