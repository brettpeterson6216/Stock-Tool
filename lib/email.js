// ============================================================
//  Email helper — Resend integration
// ============================================================
const { Resend }   = require("resend");
const { FROM_EMAIL } = require("./config");

const resend = process.env.RESEND_API_KEY ? new Resend(process.env.RESEND_API_KEY) : null;

function interpretResendResponse(response) {
  if (response?.error) {
    return {
      sent: false,
      simulated: false,
      error: String(response.error.message || response.error.name || "Email provider rejected the request."),
    };
  }
  if (!response?.data?.id) {
    return { sent: false, simulated: false, error: "Email provider returned no delivery id." };
  }
  return { sent: true, simulated: false, id: String(response.data.id) };
}

async function sendEmail({ to, subject, html }) {
  if (!resend) {
    console.log("[email] RESEND_API_KEY not set — would send to", to, "|", subject);
    return { sent: false, simulated: true };
  }
  try {
    const response = interpretResendResponse(await resend.emails.send({ from: FROM_EMAIL, to, subject, html }));
    if (!response.sent) {
      console.error("[email] Send failed:", response.error);
      return response;
    }
    console.log("[email] Sent to", to);
    return response;
  } catch (e) {
    console.error("[email] Send failed:", e.message);
    return { sent: false, simulated: false, error: e.message };
  }
}

module.exports = { sendEmail, interpretResendResponse };
