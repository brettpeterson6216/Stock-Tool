(function () {
  "use strict";

  const year = document.getElementById("year");
  const form = document.getElementById("signup-form");
  const alertEl = document.getElementById("alert");
  const btn = document.getElementById("submit-btn");
  const pwInput = document.getElementById("password");
  const meter = document.getElementById("meter-fill");
  const meterLabel = document.getElementById("meter-label");
  const query = new URLSearchParams(window.location.search);

  if (year) year.textContent = new Date().getFullYear();
  if (!form || !alertEl || !btn || !pwInput) return;

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
    entry_path: "/signup",
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

  document.querySelectorAll('a[href="/login"]').forEach((link) => {
    link.href = authLink("/login");
  });

  fetch("/api/track", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ event: "signup_page_viewed", properties: analytics }),
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

  function scorePassword(password) {
    let score = 0;
    if (password.length >= 8) score++;
    if (password.length >= 12) score++;
    if (/[a-z]/.test(password) && /[A-Z]/.test(password)) score++;
    if (/\d/.test(password)) score++;
    if (/[^A-Za-z0-9]/.test(password)) score++;
    return score;
  }

  const strength = [
    { width: "0%", color: "#B83030", text: "—" },
    { width: "20%", color: "#B83030", text: "Very weak" },
    { width: "40%", color: "#B98A3D", text: "Weak" },
    { width: "60%", color: "#B98A3D", text: "Okay" },
    { width: "80%", color: "#1A7A4A", text: "Strong" },
    { width: "100%", color: "#1A7A4A", text: "Excellent" },
  ];

  pwInput.addEventListener("input", () => {
    const state = strength[scorePassword(pwInput.value)];
    if (meter) {
      meter.style.width = state.width;
      meter.style.background = state.color;
    }
    if (meterLabel) meterLabel.textContent = "Strength: " + state.text;
  });

  let submitting = false;
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (submitting) return;
    clearAlert();

    const username = document.getElementById("username").value.trim();
    const email = document.getElementById("email").value.trim();
    const password = pwInput.value;
    if (!username || !email || !password) {
      showAlert("Please fill out every field.");
      return;
    }
    if (password.length < 8) {
      showAlert("Password must be at least 8 characters.");
      return;
    }

    submitting = true;
    btn.disabled = true;
    btn.textContent = "Creating account…";
    try {
      const response = await fetch("/api/auth/signup", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, email, password, analytics }),
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.error || "Signup failed.");

      showAlert("Account created. Redirecting…", "success");
      window.setTimeout(() => window.location.assign(nextPath), 500);
    } catch (error) {
      showAlert(error.message || "Signup failed.");
      window.setTimeout(() => {
        submitting = false;
        btn.disabled = false;
        btn.textContent = "Create account →";
      }, 2000);
    }
  });
})();
