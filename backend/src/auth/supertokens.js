/**
 * Supertokens setup: EmailPassword (sign up / sign in with email + password)
 * + Session recipes. Password reset emails are sent via our SMTP (nodemailer).
 *
 * The ST login/signup flow itself stays standard; the deliberately vulnerable
 * auth flows live in routes/auth.js ("legacy" endpoints).
 */
const EmailPassword = require("supertokens-node/recipe/emailpassword");
const Session = require("supertokens-node/recipe/session");

function initSuperTokens(container) {
  const db = () => container.resolve("db");
  const mailer = () => container.resolve("mailer");

  return [
    EmailPassword.init({
      // SMTP-backed password reset email (uses SMTP_USER / SMTP_PASS env)
      createAndSendCustomEmail: async (user, resetURLWithToken) => {
        try {
          await mailer().send({
            to: user.email,
            subject: "VulnShop - password reset",
            html: `<p>Click to reset your password:</p><p><a href="${resetURLWithToken}">${resetURLWithToken}</a></p>`,
          });
        } catch (e) {
          console.log("[supertokens] reset email failed:", e.message);
        }
      },
      override: {
        apis: (o) => ({
          ...o,
          // mirror every ST signup into our raw-SQL users table so the rest of
          // the app (orders, profiles, IDOR...) works for ST users too
          signUpPOST: async (input) => {
            const resp = await o.signUpPOST(input);
            try {
              if (resp && resp.status === "OK" && resp.user) {
                await db().query(
                  `INSERT INTO users (id, email, role) VALUES ($1, $2, 'user')
                   ON CONFLICT (id) DO NOTHING`,
                  [resp.user.id, resp.user.email]
                );
              }
            } catch (e) {
              console.log("[supertokens] mirror signup failed:", e.message);
            }
            return resp;
          },
        }),
      },
    }),
    Session.init({
      cookieSameSite: "lax",
      cookieSecure: "auto",
      antiCsrf: "NONE", // cookie-based sessions on a same-origin proxied frontend
    }),
  ];
}

module.exports = { initSuperTokens };
