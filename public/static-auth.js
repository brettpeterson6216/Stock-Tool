(function () {
  "use strict";

  const nav = document.querySelector(".il-static-main-nav");
  if (!nav) return;

  fetch("/api/auth/me", {
    credentials: "same-origin",
    cache: "no-store",
    headers: { Accept: "application/json" },
  })
    .then((response) => (response.ok ? response.json() : { user: null }))
    .then(({ user }) => {
      if (!user) return;

      nav.querySelectorAll(".il-global-login, .il-global-trial").forEach((control) => {
        control.hidden = true;
      });

      nav.querySelectorAll(".il-static-account").forEach((control) => {
        control.href = "/?view=tool&section=reports";
        control.setAttribute("aria-label", "Open saved research");
      });

      const actions = nav.querySelector(".il-global-actions");
      if (!actions || actions.querySelector(".il-global-account")) return;

      const account = document.createElement("a");
      account.className = "btn-nav-outline il-global-account";
      account.href = "/?view=tool&section=reports";
      account.textContent = user.username || user.email || "Account";
      if (user.plan && user.plan !== "free") account.textContent += " · " + String(user.plan).toUpperCase();
      actions.appendChild(account);
    })
    .catch(() => {
      /* Guest links remain visible when session detection is unavailable. */
    });
})();
