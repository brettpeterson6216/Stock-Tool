/* ═══════════════════════════════════════════════════════════════════════════
   Session state for the static pages (/lens-score, /about, /blog, /privacy,
   /terms, /data-sources, /research-process, /compound-calculator).

   These are separate documents from the SPA, so each one re-resolves the
   session on load. Three things went wrong with the previous version and all
   three read to a signed-in user as "this tab signed me out":

     1. It looked for `.il-static-main-nav`, which only exists on two of the
        eight static pages. On the other six it returned early and the guest
        links stayed up permanently for signed-in users.

     2. Where it did run, it hid the guest links with the `hidden` attribute.
        `#main-nav .btn-nav-outline { display:inline-flex !important }` in
        beauty-system.css is (0,1,1,0) and beats the `[hidden]` guard in
        site-shell.css at (0,0,3,0), so "Log in" stayed visible — next to the
        account chip that had just been appended. Both states at once.

     3. Even when it worked, the guest links painted first and were hidden only
        after a network round trip, so every page load flashed "Log in".

   This version owns one class on the nav — il-auth-in / il-auth-out — paints
   it synchronously from a cached result so the first frame is already right,
   and reconciles against the server afterwards. `hidden` is still set for
   assistive tech; the class is what CSS keys off.
   ═══════════════════════════════════════════════════════════════════════════ */
(function () {
  "use strict";

  var CACHE_KEY = "il-auth-hint";
  var PENDING_MS = 1000;

  var nav = document.querySelector(".il-global-nav") ||
            document.querySelector(".il-static-main-nav") ||
            document.getElementById("main-nav");
  if (!nav) return;

  /* ── cached hint so the first paint is already correct ─────────────────── */
  function readHint() {
    try {
      var raw = localStorage.getItem(CACHE_KEY);
      if (!raw) return null;
      var v = JSON.parse(raw);
      /* A stale hint is only a first-paint guess; the fetch below corrects it.
         Still, do not trust one older than a day. */
      if (!v || typeof v.in !== "boolean" || Date.now() - (v.at || 0) > 864e5) return null;
      return v;
    } catch (e) { return null; }
  }

  function writeHint(user) {
    try {
      localStorage.setItem(CACHE_KEY, JSON.stringify({
        in: !!user,
        at: Date.now(),
        label: user ? (user.username || user.email || "Account") : null,
        plan: user && user.plan && user.plan !== "free" ? String(user.plan).toUpperCase() : null
      }));
    } catch (e) { /* private mode — the fetch still resolves it */ }
  }

  function accountLabel(hint) {
    if (!hint || !hint.label) return "Account";
    return hint.plan ? hint.label + " · " + hint.plan : hint.label;
  }

  /* ── apply ─────────────────────────────────────────────────────────────── */
  function apply(signedIn, label) {
    nav.classList.remove("il-auth-pending");
    nav.classList.toggle("il-auth-in", !!signedIn);
    nav.classList.toggle("il-auth-out", !signedIn);

    nav.querySelectorAll(".il-global-login, .il-global-trial").forEach(function (el) {
      el.hidden = !!signedIn;
      /* Keep them out of the tab order while hidden — a display:none override
         somewhere else must not leave a focusable ghost behind. */
      if (signedIn) el.setAttribute("tabindex", "-1");
      else el.removeAttribute("tabindex");
    });

    nav.querySelectorAll(".il-static-account").forEach(function (el) {
      el.href = signedIn ? "/?view=tool&section=reports" : "/login";
      el.setAttribute("aria-label", signedIn ? "Open saved research" : "Log in");
    });

    var actions = nav.querySelector(".il-global-actions");
    if (!actions) return;
    var account = actions.querySelector(".il-global-account");

    if (!signedIn) {
      if (account) account.remove();
      return;
    }
    if (!account) {
      account = document.createElement("a");
      account.className = "btn-nav-outline il-global-account";
      account.href = "/?view=tool&section=reports";
      actions.appendChild(account);
    }
    account.textContent = label || "Account";
  }

  /* First paint: use the hint if we have one, otherwise hold the guest links
     back briefly rather than flashing them at a signed-in visitor. */
  var hint = readHint();
  if (hint) {
    apply(hint.in, accountLabel(hint));
  } else {
    nav.classList.add("il-auth-pending");
    setTimeout(function () { nav.classList.remove("il-auth-pending"); }, PENDING_MS);
  }

  /* ── reconcile against the server ──────────────────────────────────────── */
  fetch("/api/auth/me", {
    credentials: "same-origin",
    cache: "no-store",
    headers: { Accept: "application/json" }
  })
    .then(function (r) { return r.ok ? r.json() : { user: null }; })
    .then(function (d) {
      var user = d && d.user;
      writeHint(user);
      var label = user ? (user.username || user.email || "Account") : null;
      if (user && user.plan && user.plan !== "free") label += " · " + String(user.plan).toUpperCase();
      apply(!!user, label);
    })
    .catch(function () {
      /* Session detection unavailable — fall back to guest links rather than
         leaving the corner empty. */
      nav.classList.remove("il-auth-pending");
      if (!nav.classList.contains("il-auth-in")) apply(false, null);
    });
})();

/* ═══════════════════════════════════════════════════════════════════════════
   Carry the loaded symbol back into the app.

   Going app → LensScore keeps the ticker (navGoLensScore does that end). Going
   LensScore → Research dropped it, so the round trip reset you to whatever the
   app last had. Rewrite the workspace links on this page to carry whatever the
   lab is currently showing, so the two directions match.
   ═══════════════════════════════════════════════════════════════════════════ */
(function () {
  "use strict";

  function currentSymbol() {
    try {
      var p = new URLSearchParams(window.location.search);
      var fromUrl = p.get("ticker") || p.get("symbol");
      if (fromUrl) return fromUrl;
      var st = window.LensScoreState || window.__lensState;
      if (st && st.ticker) return st.ticker;
      var node = document.querySelector("[data-active-ticker]");
      if (node) return node.getAttribute("data-active-ticker");
    } catch (e) {}
    return "";
  }

  function decorate() {
    var sym = String(currentSymbol() || "").trim().toUpperCase()
      .replace(/[^A-Z0-9.\-^]/g, "").slice(0, 12);
    if (!sym) return;
    document.querySelectorAll('.il-global-links a[href*="view=tool"]').forEach(function (a) {
      var href = a.getAttribute("href") || "";
      if (/[?&](ticker|symbol)=/.test(href)) return;
      a.setAttribute("href", href + (href.indexOf("?") === -1 ? "?" : "&") + "ticker=" + encodeURIComponent(sym));
    });
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", decorate);
  else decorate();
  /* The lab resolves its ticker asynchronously; re-run once it has settled. */
  setTimeout(decorate, 1500);
})();
