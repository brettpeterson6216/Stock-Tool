/* ═══════════════════════════════════════════════════════════════════════════
   Account: plan, billing, username, password. /account

   These settings lived in a dialog inside the original app; the account menu
   in the site bar opens this page now.
   ═══════════════════════════════════════════════════════════════════════════ */
(function () {
  "use strict";
  var IL = window.IL, F = IL.fmt, h = IL.h;

  function planText(u) {
    var p = u.effectivePlan || u.plan || "free";
    if (p === "trial") return "Pro, free trial";
    if (p === "pro") return "Pro";
    return "Free";
  }
  function render(u) {
    var trial = (u.effectivePlan || u.plan) === "trial" && u.trial_ends_at;
    var pro = IL.isPro(u);
    document.getElementById("main").innerHTML =
      '<div class="dh"><div><h1 class="dh-t">Account</h1><p class="muted">Your plan, billing and sign-in details.</p></div></div>' +
      '<div class="grid-2">' +
        '<section class="card"><h2 class="card-t">Your account</h2><div>' +
          '<div class="stat"><span class="k">Email</span><span class="v" style="font-size:14px">' + h(u.email || "—") + (u.email_verified ? "" : ' <span class="tag">not verified</span>') + "</span></div>" +
          '<div class="stat"><span class="k">Username</span><span class="v" style="font-size:14px">' + h(u.username || "—") + "</span></div>" +
          '<div class="stat"><span class="k">Plan</span><span class="v" style="font-size:14px">' + h(planText(u)) + "</span></div>" +
          (trial ? '<div class="stat"><span class="k">Trial ends</span><span class="v" style="font-size:14px">' + h(F.date(u.trial_ends_at)) + "</span></div>" : "") +
          '<div class="stat"><span class="k">Member since</span><span class="v" style="font-size:14px">' + h(F.date(u.created_at)) + "</span></div>" +
        "</div>" +
        (u.email_verified ? "" : '<p class="note">Verify your email to get alerts and the weekly email. <button class="btn sm ghost" type="button" id="ac-resend">Send the link again</button></p>') +
        '<div class="row wrap" style="margin-top:14px">' + (pro ? '<button class="btn" type="button" id="ac-billing">Manage subscription and billing</button>' : '<a class="btn primary" href="/pricing">See Pro plans</a>') + "</div></section>" +
        '<section class="card"><h2 class="card-t">Change username</h2>' +
          '<label class="field">New username<input class="input" id="ac-un" autocomplete="username" autocapitalize="none" spellcheck="false" placeholder="letters, numbers, _ . -" value="' + h(u.username || "") + '"></label>' +
          '<p class="note" id="ac-un-msg" role="status"></p><div class="row"><button class="btn" type="button" id="ac-un-go">Update username</button></div>' +
          '<h2 class="card-t" style="margin-top:24px">Change password</h2>' +
          '<label class="field">Current password<input class="input" type="password" id="ac-pw0" autocomplete="current-password"></label>' +
          '<label class="field">New password, at least 8 characters<input class="input" type="password" id="ac-pw1" autocomplete="new-password"></label>' +
          '<label class="field">Confirm new password<input class="input" type="password" id="ac-pw2" autocomplete="new-password"></label>' +
          '<p class="note" id="ac-pw-msg" role="status"></p><div class="row"><button class="btn" type="button" id="ac-pw-go">Update password</button></div></section>' +
      "</div>" +
      '<section class="card" id="feedback"><h2 class="card-t">Help and feedback</h2><p class="muted">Questions, a bug, or an idea for the site? Write to us; a person reads every message.</p>' +
        '<div class="row wrap"><a class="btn" href="mailto:support@impliedlens.com?subject=ImpliedLens%20support">Contact support</a><a class="btn ghost" href="mailto:support@impliedlens.com?subject=ImpliedLens%20feedback">Send feedback</a><button class="btn ghost" type="button" id="ac-logout">Log out</button></div></section>';
    wire(u);
  }
  function wire(u) {
    var $ = function (id) { return document.getElementById(id); };
    if ($("ac-billing")) $("ac-billing").addEventListener("click", function () {
      IL.api("/api/stripe/portal", { method: "POST", body: {} }).then(function (res) {
        if (res.ok && res.data && res.data.url) location.href = res.data.url;
        else IL.toast((res.data && res.data.error) || "Billing is not available right now. Email support@impliedlens.com and we will help.");
      });
    });
    if ($("ac-resend")) $("ac-resend").addEventListener("click", function () {
      IL.api("/api/auth/resend-verification", { method: "POST", body: { email: u.email } }).then(function (res) {
        IL.toast(res.ok ? "Sent. Check your inbox." : (res.data && res.data.error) || "Could not send it right now.");
      });
    });
    $("ac-un-go").addEventListener("click", function () {
      var v = $("ac-un").value.trim().toLowerCase(), msg = $("ac-un-msg");
      if (!/^[a-z0-9_.\-]{3,24}$/.test(v)) { msg.textContent = "Use 3–24 letters, numbers, underscores, dots or hyphens."; return; }
      IL.api("/api/auth/change-username", { method: "POST", body: { username: v } }).then(function (res) {
        msg.textContent = res.ok ? "Username updated." : (res.data && res.data.error) || "Could not update the username.";
      });
    });
    $("ac-pw-go").addEventListener("click", function () {
      var a = $("ac-pw0").value, b = $("ac-pw1").value, c = $("ac-pw2").value, msg = $("ac-pw-msg");
      if (b.length < 8) { msg.textContent = "The new password needs at least 8 characters."; return; }
      if (b !== c) { msg.textContent = "The two new passwords do not match."; return; }
      IL.api("/api/auth/change-password", { method: "POST", body: { currentPassword: a, newPassword: b } }).then(function (res) {
        msg.textContent = res.ok ? "Password updated." : (res.data && res.data.error) || "Could not update the password.";
        if (res.ok) { $("ac-pw0").value = $("ac-pw1").value = $("ac-pw2").value = ""; }
      });
    });
    $("ac-logout").addEventListener("click", function () {
      IL.api("/api/auth/logout", { method: "POST", body: {} }).then(function () { location.href = "/"; });
    });
    if (location.hash === "#feedback") { var f = $("feedback"); if (f) f.scrollIntoView({ block: "start" }); }
  }
  function boot() {
    IL.shell("account");
    IL.me().then(function (u) {
      if (!u) { location.href = IL.loginHref ? IL.loginHref() : "/login"; return; }
      render(u);
    });
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", boot); else boot();
})();
