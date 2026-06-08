// ============================================================
//  CSRF protection — lightweight double-submit session token
//
//  Pattern:
//    1. GET /api/csrf returns a per-session token (created on demand)
//    2. Every state-mutating request must include:
//         X-CSRF-Token: <token>   (as a request header)
//    3. validateCsrf middleware compares header to session value
//
//  Why this is sufficient here:
//    - Session cookie is SameSite=Lax, so cross-site POST from
//      another origin won't have the session cookie.
//    - Even if it did (e.g. same-site subdomain attack), the
//      attacker can't read the token because it's only visible
//      to same-origin JS — cross-origin fetches are blocked by
//      the browser's CORS policy.
// ============================================================
const crypto = require("crypto");

/**
 * Express middleware: validates X-CSRF-Token header against the
 * token stored in the session. Call on all mutation routes.
 */
function validateCsrf(req, res, next) {
  const sessionToken = req.session && req.session.csrfToken;
  const headerToken  = req.headers["x-csrf-token"];

  if (!sessionToken || !headerToken || sessionToken !== headerToken) {
    return res.status(403).json({ error: "Invalid or missing CSRF token." });
  }
  next();
}

/**
 * Returns (and lazily creates) the CSRF token for this session.
 */
function getOrCreateToken(req) {
  if (!req.session.csrfToken) {
    req.session.csrfToken = crypto.randomBytes(32).toString("hex");
  }
  return req.session.csrfToken;
}

module.exports = { validateCsrf, getOrCreateToken };
