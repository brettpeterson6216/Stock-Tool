// ============================================================
//  Email helper — Resend integration
// ============================================================
const { Resend }   = require("resend");
const { FROM_EMAIL } = require("./config");

const resend = process.env.RESEND_API_KEY ? new Resend(process.env.RESEND_API_KEY) : null;

async function sendEmail({ to, subject, html }) {
  if (!resend) {
    console.log("[email] RESEND_API_KEY not set — would send to", to, "|", subject);
    return { sent: false, simulated: true };
  }
  try {
    await resend.emails.send({ from: FROM_EMAIL, to, subject, html });
    console.log("[email] Sent to", to);
    return { sent: true, simulated: false };
  } catch (e) {
    console.error("[email] Send failed:", e.message);
    return { sent: false, simulated: false, error: e.message };
  }
}

module.exports = { sendEmail };
