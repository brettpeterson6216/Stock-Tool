(function () {
  "use strict";

  const year = document.getElementById("year");
  const params = new URLSearchParams(window.location.search);
  const token = params.get("token");
  const requestCard = document.getElementById("card-request");
  const resetCard = document.getElementById("card-reset");
  const requestForm = document.getElementById("request-form");
  const requestBtn = document.getElementById("req-btn");
  const requestAlert = document.getElementById("alert-req");
  const resetForm = document.getElementById("reset-form");
  const resetBtn = document.getElementById("reset-btn");
  const resetAlert = document.getElementById("alert-reset");

  if (year) year.textContent = new Date().getFullYear();
  if (token && requestCard && resetCard) {
    requestCard.style.display = "none";
    resetCard.style.display = "block";
  }

  function showAlert(element, message, kind) {
    if (!element) return;
    element.className = "alert show alert-" + (kind || "error");
    element.textContent = message;
  }

  if (requestForm && requestBtn) {
    requestForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      const email = document.getElementById("email").value.trim();
      if (!email) {
        showAlert(requestAlert, "Please enter your email.");
        return;
      }

      requestBtn.disabled = true;
      requestBtn.textContent = "Sending…";
      try {
        await fetch("/api/auth/forgot-password", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ email }),
        });
        showAlert(requestAlert, "If an account exists with that email, a reset link has been sent. Check your inbox (and spam folder).", "success");
        requestBtn.textContent = "Sent ✓";
      } catch (_) {
        showAlert(requestAlert, "Something went wrong. Please try again.");
        requestBtn.disabled = false;
        requestBtn.textContent = "Send reset link →";
      }
    });
  }

  if (resetForm && resetBtn) {
    resetForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      const password = document.getElementById("new-password").value;
      const confirmation = document.getElementById("confirm-password").value;
      if (password.length < 8) {
        showAlert(resetAlert, "Password must be at least 8 characters.");
        return;
      }
      if (password !== confirmation) {
        showAlert(resetAlert, "Passwords do not match.");
        return;
      }

      resetBtn.disabled = true;
      resetBtn.textContent = "Saving…";
      try {
        const response = await fetch("/api/auth/reset-password", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ token, password }),
        });
        const data = await response.json().catch(() => ({}));
        if (!response.ok) throw new Error(data.error || "Could not reset password.");

        showAlert(resetAlert, "Password updated! Redirecting to login…", "success");
        window.setTimeout(() => window.location.assign("/login"), 1500);
      } catch (error) {
        showAlert(resetAlert, error.message || "Something went wrong. Please try again.");
        resetBtn.disabled = false;
        resetBtn.textContent = "Set new password →";
      }
    });
  }
})();
