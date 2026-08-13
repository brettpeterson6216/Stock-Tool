(function () {
  "use strict";

  const year = document.getElementById("year");
  const form = document.getElementById("login-form");
  const alertEl = document.getElementById("alert");
  const btn = document.getElementById("submit-btn");
  const query = new URLSearchParams(window.location.search);

  if (year) year.textContent = new Date().getFullYear();
  if (!form || !alertEl || !btn) return;

  function safeNext(value) {
    if (!value) return "/";
    try {
      const url = new URL(value, window.location.origin);
      if (url.origin !== window.location.origin) return "/";
      return url.pathname + url.search + url.hash;
    } catch (_) {
      return "/";
    }
  }

  const nextPath = safeNext(query.get("next"));
  const analytics = {
    source: query.get("source") || "direct",
    ticker: (query.get("ticker") || "").toUpperCase().replace(/[^A-Z0-9.\-^]/g, "").slice(0, 10),
    entry_path: "/login",
    return_path: nextPath.split("?")[0],
    utm_source: query.get("utm_source") || "",
    utm_medium: query.get("utm_medium") || "",
    utm_campaign: query.get("utm_campaign") || "",
  };

  function authLink(path) {
    const params = new URLSearchParams({ next: nextPath, source: analytics.source });
    if (analytics.ticker) params.set("ticker", analytics.ticker);
    ["utm_source", "utm_medium", "utm_campaign"].forEach((key) => {
      if (analytics[key]) params.set(key, analytics[key]);
    });
    return path + "?" + params.toString();
  }

  document.querySelectorAll('a[href="/signup"]').forEach((link) => {
    link.href = authLink("/signup");
  });

  fetch("/api/track", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ event: "login_page_viewed", properties: analytics }),
    keepalive: true,
  }).catch(() => {});

  function showAlert(message, kind) {
    alertEl.className = "alert show alert-" + (kind || "error");
    alertEl.textContent = message;
  }

  function clearAlert() {
    alertEl.className = "alert";
    alertEl.textContent = "";
  }

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    clearAlert();

    const identifier = document.getElementById("identifier").value.trim();
    const password = document.getElementById("password").value;
    if (!identifier || !password) {
      showAlert("Please enter your username/email and password.");
      return;
    }

    btn.disabled = true;
    btn.textContent = "Signing in…";
    try {
      const response = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ identifier, password, analytics }),
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.error || "Login failed.");

      showAlert("Signed in. Redirecting…", "success");
      window.setTimeout(() => {
        window.location.assign(nextPath);
      }, 400);
    } catch (error) {
      showAlert(error.message || "Login failed.");
      btn.disabled = false;
      btn.textContent = "Log in →";
    }
  });
})();
