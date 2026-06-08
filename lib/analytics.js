// ============================================================
//  Analytics — fire-and-forget event tracking
//  All calls are async; errors are swallowed so tracking never
//  crashes the request that triggers it.
// ============================================================
const { db } = require("./db");

/**
 * track(event, props, sessionId, userId)
 *
 * event     — string, e.g. "signup_completed"
 * props     — plain object (will be JSON-serialised)
 * sessionId — req.sessionID  (may be undefined)
 * userId    — req.session.userId (may be undefined)
 */
async function track(event, props = {}, sessionId = null, userId = null) {
  try {
    await db.execute({
      sql:  `INSERT INTO analytics_events (event, session_id, user_id, properties)
             VALUES (?, ?, ?, ?)`,
      args: [
        String(event),
        sessionId  ? String(sessionId)  : null,
        userId     ? Number(userId)     : null,
        JSON.stringify(props),
      ],
    });
  } catch (err) {
    // Never let analytics crash the caller
    console.error("[analytics] track() error:", err.message || err);
  }
}

module.exports = { track };
