// ============================================================
//  Auth routes — signup, login, logout, me, saves,
//                password reset, username/password change,
//                admin grant-pro
// ============================================================
const express   = require("express");
const bcrypt    = require("bcryptjs");
const crypto    = require("crypto");
const rateLimit = require("express-rate-limit");

const { db }               = require("../lib/db");
const { getEffectivePlan, FREE_DAILY_LIMIT, GUEST_DAILY_LIMIT } = require("../lib/plan");
const { sendEmail }        = require("../lib/email");
const { BCRYPT_ROUNDS, APP_URL, ADMIN_SECRET } = require("../lib/config");
const { validateCsrf } = require("../lib/csrf");
const { track }        = require("../lib/analytics");

// Fail fast if ADMIN_SECRET is missing in production
if (process.env.NODE_ENV === "production" && !ADMIN_SECRET) {
  console.error("[config] FATAL: ADMIN_SECRET not set in production. Refusing to start.");
  process.exit(1);
}

const router = express.Router();

// ── Email verification helpers ───────────────────────────────
function _verifToken() {
  return crypto.randomBytes(32).toString("hex");
}

async function _sendVerificationEmail(email, token) {
  const link = `${APP_URL}/verify-email?token=${token}`;
  await sendEmail({
    to:      email,
    subject: "Verify your ImpliedLens email",
    html:    `<p>Thanks for signing up to ImpliedLens.</p>
<p>Click the link below to verify your email address. The link expires in 24 hours.</p>
<p><a href="${link}" style="background:#C8882A;color:#fff;padding:10px 20px;text-decoration:none;border-radius:6px;display:inline-block;">Verify Email →</a></p>
<p style="color:#888;font-size:12px;">Or copy this URL: ${link}</p>
<p style="color:#888;font-size:12px;">If you did not create an account, you can safely ignore this email.</p>`,
  });
}

// ---- Rate limiter — applied only to mutation/auth endpoints ----
// NOT applied to /saves (GET) or /auth/me — those fire on every page load
// and would lock users out after a few refreshes.
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many attempts. Try again in 15 minutes." },
});

// ---- Validation helpers ----
const EMAIL_RE    = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const USERNAME_RE = /^[a-zA-Z0-9_.\-]{3,32}$/;

function validateSignup({ username, email, password }) {
  const errors = [];
  if (!username || !USERNAME_RE.test(username))
    errors.push("Username must be 3-32 chars (letters, numbers, _ . -).");
  if (!email || !EMAIL_RE.test(email))
    errors.push("Please enter a valid email address.");
  if (!password || password.length < 8)
    errors.push("Password must be at least 8 characters.");
  if (password && password.length > 200)
    errors.push("Password is too long.");
  return errors;
}

// ============================================================
//  Signup / Login / Logout / Me
// ============================================================
router.post("/auth/signup",           authLimiter, async (req, res) => {
  try {
    const username = String(req.body.username || "").trim();
    const email    = String(req.body.email    || "").trim().toLowerCase();
    const password = String(req.body.password || "");

    const errors = validateSignup({ username, email, password });
    if (errors.length) return res.status(400).json({ error: errors.join(" ") });

    const byUser  = await db.execute({ sql: "SELECT id FROM users WHERE username = ? LIMIT 1", args: [username] });
    if (byUser.rows.length) return res.status(409).json({ error: "That username is already taken." });

    const byEmail = await db.execute({ sql: "SELECT id FROM users WHERE email = ? LIMIT 1", args: [email] });
    if (byEmail.rows.length) return res.status(409).json({ error: "An account with that email already exists." });

    const hash = await bcrypt.hash(password, BCRYPT_ROUNDS);
    let ins;
    try {
      ins = await db.execute({ sql: "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)", args: [username, email, hash] });
    } catch (dbErr) {
      const msg = (dbErr.message || "").toLowerCase();
      if (msg.includes("unique") && msg.includes("username")) return res.status(409).json({ error: "That username is already taken." });
      if (msg.includes("unique") && msg.includes("email"))    return res.status(409).json({ error: "An account with that email already exists." });
      if (msg.includes("unique"))                             return res.status(409).json({ error: "That username or email is already taken." });
      throw dbErr;
    }
    const userId  = Number(ins.lastInsertRowid);
    const userRow = await db.execute({ sql: "SELECT id, username, email, created_at FROM users WHERE id = ?", args: [userId] });
    req.session.userId = userId;
    // Fire-and-forget analytics
    track("signup_completed", { username, plan: "free" }, req.sessionID, userId).catch(() => {});
    // Send verification email (fire-and-forget — don't fail signup if email fails)
    const verifToken = _verifToken();
    const verifExpiry = Date.now() + 24 * 60 * 60 * 1000; // 24h
    db.execute({
      sql:  "INSERT INTO email_verif_tokens (token, user_id, expires_at) VALUES (?, ?, ?)",
      args: [verifToken, userId, verifExpiry],
    }).then(() => _sendVerificationEmail(email, verifToken)).catch(e => console.error("[verif] token/email error:", e));
    return res.status(201).json({ user: { ...(userRow.rows[0] || {}), email_verified: 0 } });
  } catch (err) {
    console.error("signup error:", err);
    return res.status(500).json({ error: "Could not create account." });
  }
});

router.post("/auth/login",             authLimiter, async (req, res) => {
  try {
    const identifier = String(req.body.identifier || req.body.username || req.body.email || "").trim();
    const password   = String(req.body.password || "");
    if (!identifier || !password) return res.status(400).json({ error: "Please enter your username/email and password." });

    const lookup = identifier.includes("@") ? identifier.toLowerCase() : identifier;
    const result = await db.execute({ sql: "SELECT id, username, email, password_hash FROM users WHERE username = ? OR email = ? LIMIT 1", args: [lookup, lookup] });
    const row = result.rows[0];
    if (!row) return res.status(401).json({ error: "No account found with that username or email." });

    const ok = await bcrypt.compare(password, row.password_hash);
    if (!ok) return res.status(401).json({ error: "Incorrect password." });

    req.session.userId = Number(row.id);
    track("login_completed", {}, req.sessionID, Number(row.id)).catch(() => {});
    return res.json({ user: { id: Number(row.id), username: row.username, email: row.email } });
  } catch (err) {
    console.error("login error:", err);
    return res.status(500).json({ error: "Login failed." });
  }
});

router.post("/auth/logout", validateCsrf, (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("il.sid");
    res.json({ ok: true });
  });
});

router.get("/auth/me", async (req, res) => {
  if (!req.session.userId) return res.json({ user: null });
  try {
    const result = await db.execute({
      sql:  "SELECT id, username, email, created_at, plan, trial_ends_at, email_verified FROM users WHERE id = ?",
      args: [req.session.userId],
    });
    const user = result.rows[0] || null;
    if (user) user.effectivePlan = getEffectivePlan(user);
    return res.json({ user });
  } catch (err) {
    return res.json({ user: null });
  }
});

// ============================================================
//  Admin — grant/revoke Pro without Stripe
// ============================================================
router.post("/admin/grant-pro", authLimiter, validateCsrf, async (req, res) => {
  // Secret must come via header only — never accepted from request body
  const secret = req.headers["x-admin-secret"];
  if (!secret || !ADMIN_SECRET || secret !== ADMIN_SECRET) {
    console.warn("[admin] grant-pro rejected — bad or missing secret from IP", req.ip);
    return res.status(403).json({ error: "Forbidden" });
  }

  const { email, revoke } = req.body || {};
  if (!email) return res.status(400).json({ error: "email required" });
  const action = revoke ? "revoked" : "granted";
  try {
    if (revoke) {
      await db.execute({ sql: "UPDATE users SET plan = 'free', trial_ends_at = NULL WHERE email = ?", args: [email.toLowerCase()] });
    } else {
      await db.execute({ sql: "UPDATE users SET plan = 'pro', trial_ends_at = NULL WHERE email = ?", args: [email.toLowerCase()] });
    }
    console.log(`[admin] Pro ${action} for ${email} by ${req.ip} at ${new Date().toISOString()}`);
    return res.json({ ok: true, action, email });
  } catch (err) {
    console.error("[admin] grant-pro db error:", err.message);
    return res.status(500).json({ error: err.message });
  }
});

// ============================================================
//  Saved analyses
// ============================================================
router.get("/saves", async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: "Not logged in" });
  try {
    const r = await db.execute({
      sql:  "SELECT id, ticker, type, label, data, created_at FROM saved_analyses WHERE user_id=? ORDER BY created_at DESC LIMIT 200",
      args: [req.session.userId],
    });
    res.json(r.rows.map(row => ({
      id: row.id, ticker: row.ticker, type: row.type,
      label: row.label, data: JSON.parse(row.data || "{}"), created_at: row.created_at,
    })));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

router.post("/saves", validateCsrf, async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: "Not logged in" });
  const { ticker, type, label, data } = req.body || {};
  if (!ticker || !data) return res.status(400).json({ error: "ticker and data required" });
  try {
    const r = await db.execute({
      sql:  "INSERT INTO saved_analyses (user_id, ticker, type, label, data) VALUES (?,?,?,?,?)",
      args: [req.session.userId, ticker.toUpperCase(), type || "price", label || "", JSON.stringify(data)],
    });
    res.json({ ok: true, id: Number(r.lastInsertRowid) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

router.delete("/saves/:id", validateCsrf, async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: "Not logged in" });
  try {
    await db.execute({ sql: "DELETE FROM saved_analyses WHERE id=? AND user_id=?", args: [req.params.id, req.session.userId] });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

router.delete("/saves", validateCsrf, async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: "Not logged in" });
  try {
    await db.execute({ sql: "DELETE FROM saved_analyses WHERE user_id=?", args: [req.session.userId] });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ============================================================
//  Password reset
// ============================================================
router.post("/auth/forgot-password",   authLimiter, async (req, res) => {
  const email = String(req.body.email || "").trim().toLowerCase();
  if (!email) return res.status(400).json({ error: "Email is required." });
  try {
    const result = await db.execute({ sql: "SELECT id FROM users WHERE email = ?", args: [email] });
    if (!result.rows.length) return res.json({ ok: true }); // prevent enumeration

    const token   = crypto.randomBytes(32).toString("hex");
    const expires = Date.now() + 60 * 60 * 1000;
    await db.execute({ sql: "INSERT INTO reset_tokens (token, user_id, expires_at) VALUES (?, ?, ?)", args: [token, result.rows[0].id, expires] });

    const resetUrl = `${APP_URL}/reset-password?token=${token}`;
    await sendEmail({
      to: email,
      subject: "Reset your ImpliedLens password",
      html: `
        <div style="font-family:Arial,sans-serif;max-width:520px;margin:0 auto;padding:32px 24px;background:#08090D;color:#e0e1e8;border-radius:12px;">
          <h2 style="font-size:1.4rem;margin-bottom:8px;color:#fff;">Reset your <span style="color:#C8882A;">ImpliedLens</span> password</h2>
          <p style="color:rgba(220,225,232,.65);font-size:.9rem;margin-bottom:24px;">Click the button below to set a new password. This link expires in 1 hour.</p>
          <a href="${resetUrl}" style="display:inline-block;padding:12px 28px;background:#C8882A;color:#fff;border-radius:8px;text-decoration:none;font-weight:600;font-size:.95rem;">Reset Password →</a>
          <p style="margin-top:24px;font-size:.75rem;color:rgba(220,225,232,.35);">If you didn't request this, you can safely ignore this email.</p>
          <hr style="border:none;border-top:1px solid rgba(255,255,255,.08);margin:24px 0;">
          <p style="font-size:.72rem;color:rgba(220,225,232,.25);">ImpliedLens · impliedlens.com</p>
        </div>`,
    });
    console.log("[reset] Link generated for", email);
    return res.json({ ok: true });
  } catch (err) {
    console.error("forgot-password error:", err);
    return res.status(500).json({ error: "Something went wrong." });
  }
});

router.post("/auth/reset-password",    authLimiter, async (req, res) => {
  const { token, password } = req.body;
  if (!token || !password || password.length < 8)
    return res.status(400).json({ error: "Invalid request." });
  try {
    const r   = await db.execute({ sql: "SELECT user_id, expires_at, used FROM reset_tokens WHERE token = ?", args: [token] });
    const row = r.rows[0];
    if (!row)                              return res.status(400).json({ error: "Invalid or expired link." });
    if (row.used)                          return res.status(400).json({ error: "This link has already been used." });
    if (Number(row.expires_at) < Date.now()) return res.status(400).json({ error: "This link has expired. Please request a new one." });

    const hash = await bcrypt.hash(password, BCRYPT_ROUNDS);
    await db.execute({ sql: "UPDATE users SET password_hash = ? WHERE id = ?", args: [hash, row.user_id] });
    await db.execute({ sql: "UPDATE reset_tokens SET used = 1 WHERE token = ?", args: [token] });
    return res.json({ ok: true });
  } catch (err) {
    console.error("reset-password error:", err);
    return res.status(500).json({ error: "Could not reset password." });
  }
});

// ============================================================
//  Change username / password (logged-in user)
// ============================================================
router.post("/auth/change-username",   authLimiter, validateCsrf, async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: "Not logged in." });
  const { username } = req.body;
  if (!username || username.length < 3) return res.status(400).json({ error: "Username must be at least 3 characters." });
  if (!/^[a-z0-9_.-]+$/i.test(username)) return res.status(400).json({ error: "Only letters, numbers, _ . and - are allowed." });
  try {
    const existing = await db.execute({
      sql:  "SELECT id FROM users WHERE LOWER(username) = LOWER(?) AND id != ?",
      args: [username, req.session.userId],
    });
    if (existing.rows.length > 0) return res.status(400).json({ error: "That username is already taken." });
    await db.execute({ sql: "UPDATE users SET username = ? WHERE id = ?", args: [username.toLowerCase(), req.session.userId] });
    return res.json({ ok: true });
  } catch (err) {
    console.error("change-username error:", err);
    return res.status(500).json({ error: "Something went wrong." });
  }
});

router.post("/auth/change-password",   authLimiter, validateCsrf, async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: "Not logged in." });
  const { currentPassword, newPassword } = req.body;
  if (!currentPassword || !newPassword || newPassword.length < 8)
    return res.status(400).json({ error: "New password must be at least 8 characters." });
  try {
    const r    = await db.execute({ sql: "SELECT password_hash FROM users WHERE id = ?", args: [req.session.userId] });
    const user = r.rows[0];
    if (!user) return res.status(404).json({ error: "User not found." });
    const match = await bcrypt.compare(currentPassword, user.password_hash);
    if (!match) return res.status(400).json({ error: "Current password is incorrect." });
    const hash = await bcrypt.hash(newPassword, BCRYPT_ROUNDS);
    await db.execute({ sql: "UPDATE users SET password_hash = ? WHERE id = ?", args: [hash, req.session.userId] });
    return res.json({ ok: true });
  } catch (err) {
    console.error("change-password error:", err);
    return res.status(500).json({ error: "Something went wrong." });
  }
});


// ============================================================
//  GET /api/admin/analytics
//  Admin-only. Requires X-Admin-Secret header.
//  Returns aggregated metrics from analytics_events for the
//  last 30 days plus all-time totals.
// ============================================================
router.get("/admin/analytics", async (req, res) => {
  const secret = req.headers["x-admin-secret"];
  if (!secret || secret !== ADMIN_SECRET) {
    return res.status(403).json({ error: "Forbidden." });
  }

  try {
    // ── Daily event counts for the last 30 days ──────────────
    const daily = await db.execute(`
      SELECT
        substr(created_at, 1, 10) AS day,
        event,
        COUNT(*)                  AS cnt
      FROM analytics_events
      WHERE created_at >= datetime('now', '-30 days')
      GROUP BY day, event
      ORDER BY day ASC
    `);

    // ── Pro gate views by section (all time + last 30d) ──────
    const gatesBySection = await db.execute(`
      SELECT
        json_extract(properties, '$.section') AS section,
        COUNT(*)                               AS total,
        SUM(CASE WHEN created_at >= datetime('now', '-30 days') THEN 1 ELSE 0 END) AS last30
      FROM analytics_events
      WHERE event = 'pro_gate_viewed'
        AND json_extract(properties, '$.section') IS NOT NULL
      GROUP BY section
      ORDER BY total DESC
    `);

    // ── Upgrade modal source breakdown ───────────────────────
    const modalSources = await db.execute(`
      SELECT
        json_extract(properties, '$.source') AS source,
        COUNT(*)                              AS cnt
      FROM analytics_events
      WHERE event = 'upgrade_modal_opened'
      GROUP BY source
      ORDER BY cnt DESC
      LIMIT 20
    `);

    // ── All-time totals ───────────────────────────────────────
    const totals = await db.execute(`
      SELECT event, COUNT(*) AS cnt
      FROM analytics_events
      GROUP BY event
      ORDER BY cnt DESC
    `);

    // ── Total registered users + new last 30d ─────────────────
    const users = await db.execute(`
      SELECT
        COUNT(*)                                                               AS total,
        SUM(CASE WHEN created_at >= datetime('now', '-30 days') THEN 1 ELSE 0 END) AS last30,
        SUM(CASE WHEN plan = 'pro'   THEN 1 ELSE 0 END)                       AS pro_count,
        SUM(CASE WHEN plan = 'trial' THEN 1 ELSE 0 END)                       AS trial_count
      FROM users
    `);

    // ── Recent events (last 100) ──────────────────────────────
    const recent = await db.execute(`
      SELECT id, event, session_id, user_id, properties, created_at
      FROM analytics_events
      ORDER BY id DESC
      LIMIT 100
    `);

    res.json({
      daily:          daily.rows,
      gatesBySection: gatesBySection.rows,
      modalSources:   modalSources.rows,
      totals:         totals.rows,
      users:          users.rows[0] || {},
      recent:         recent.rows,
    });
  } catch (err) {
    console.error("[admin/analytics] error:", err);
    res.status(500).json({ error: "Query failed." });
  }
});


// ============================================================
//  GET /verify-email?token=...
//  Verifies the token, marks user email_verified=1
// ============================================================
router.get("/verify-email", async (req, res) => {
  const token = String(req.query.token || "").trim();
  if (!token) return res.redirect("/?verif=invalid");
  try {
    const r = await db.execute({
      sql:  "SELECT user_id, expires_at, used FROM email_verif_tokens WHERE token = ?",
      args: [token],
    });
    const row = r.rows[0];
    if (!row)              return res.redirect("/?verif=invalid");
    if (row.used)          return res.redirect("/?verif=already");
    if (Number(row.expires_at) < Date.now()) return res.redirect("/?verif=expired");

    await db.execute({
      sql:  "UPDATE users SET email_verified = 1 WHERE id = ?",
      args: [row.user_id],
    });
    await db.execute({
      sql:  "UPDATE email_verif_tokens SET used = 1 WHERE token = ?",
      args: [token],
    });
    // If this user is currently logged in, refresh their session info
    if (req.session.userId && Number(req.session.userId) === Number(row.user_id)) {
      // Session is live — redirect to app with success flag
    }
    return res.redirect("/?verif=ok");
  } catch (err) {
    console.error("[verif] verify-email error:", err);
    return res.redirect("/?verif=error");
  }
});

// ============================================================
//  POST /auth/resend-verification
//  Resend verification email. Rate-limited to 3/15min per user.
// ============================================================
const resendVerifLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 3,
  keyGenerator: (req) => String(req.session.userId || req.ip),
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many resend requests. Try again in 15 minutes." },
});

router.post("/auth/resend-verification", resendVerifLimiter, async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: "Login required." });
  try {
    const r = await db.execute({
      sql:  "SELECT email, email_verified FROM users WHERE id = ?",
      args: [req.session.userId],
    });
    const user = r.rows[0];
    if (!user)             return res.status(404).json({ error: "User not found." });
    if (user.email_verified) return res.json({ ok: true, message: "Already verified." });

    const token  = _verifToken();
    const expiry = Date.now() + 24 * 60 * 60 * 1000;
    // Invalidate old tokens for this user
    await db.execute({
      sql:  "UPDATE email_verif_tokens SET used = 1 WHERE user_id = ? AND used = 0",
      args: [req.session.userId],
    });
    await db.execute({
      sql:  "INSERT INTO email_verif_tokens (token, user_id, expires_at) VALUES (?, ?, ?)",
      args: [token, req.session.userId, expiry],
    });
    await _sendVerificationEmail(user.email, token);
    return res.json({ ok: true });
  } catch (err) {
    console.error("[verif] resend error:", err);
    return res.status(500).json({ error: "Could not send email." });
  }
});

module.exports = router;
