/**
 * Nodemailer wrapper (Gmail SMTP).
 * Credentials come ONLY from env (SMTP_USER / SMTP_PASS set in Render dashboard).
 * [VULN #68] "from" is caller-controlled in /api/contact -> email spoofing.
 */
module.exports = (container) => {
  const config = container.resolve("config");
  let transport = null;

  function getTransport() {
    if (!transport) {
      const nodemailer = require("nodemailer");
      transport = nodemailer.createTransport({
        service: "gmail",
        auth: { user: config.smtpUser, pass: config.smtpPass },
      });
    }
    return transport;
  }

  async function send({ from, to, subject, html, text }) {
    if (!config.smtpUser || !config.smtpPass) {
      console.log("[mailer] SMTP not configured, skipping send:", subject);
      return { skipped: true };
    }
    const info = await getTransport().sendMail({
      // [VULN #68] from is whatever the caller passes (spoofable)
      from: from || config.smtpUser,
      to: to || config.smtpUser,
      subject: subject || "(no subject)",
      html,
      text,
    });
    return { messageId: info.messageId };
  }

  return { send };
};
