(function () {
  "use strict";

  const KEYS = {
    onboarding: "il-onboarding-dismissed",
    checklist: "il-edu-checklist",
    markup: "il-chart-markup-v1",
  };
  let activeChartId = null;
  let redoItems = [];
  let restoringMarkup = false;

  function read(key, fallback) {
    try { return JSON.parse(localStorage.getItem(key) || JSON.stringify(fallback)); }
    catch (_) { return fallback; }
  }
  function write(key, value) {
    try { localStorage.setItem(key, JSON.stringify(value)); } catch (_) {}
  }
  function markupStore() { return read(KEYS.markup, {}); }
  function markupKey(chartId) {
    const ticker = window.IL_STATE?.ticker || "market";
    const range = window.IL_STATE?.range || "default";
    return `${ticker}:${range}:${chartId || "chart"}`;
  }
  function setSaveState(text) {
    const el = document.getElementById("cex-save-state");
    if (el) el.textContent = text;
  }
  function saveMarkup() {
    if (!activeChartId || !window._markup) return;
    const store = markupStore();
    const key = markupKey(activeChartId);
    if (_markup.items.length) store[key] = _markup.items;
    else delete store[key];
    write(KEYS.markup, store);
    setSaveState(_markup.items.length ? `${_markup.items.length} mark${_markup.items.length === 1 ? "" : "s"} saved` : "No saved marks");
  }
  function loadMarkup() {
    if (!activeChartId || !window._markup) return;
    const items = markupStore()[markupKey(activeChartId)] || [];
    _markup.items = JSON.parse(JSON.stringify(items));
    redoItems = [];
    if (typeof drawMarkup === "function") drawMarkup();
    setSaveState(items.length ? `${items.length} mark${items.length === 1 ? "" : "s"} restored` : "No saved marks");
  }
  function exportExpandedChart() {
    const base = document.getElementById("chart-expanded");
    const marks = document.getElementById("chart-markup");
    if (!base || !marks) return;
    const out = document.createElement("canvas");
    out.width = base.width;
    out.height = base.height;
    const ctx = out.getContext("2d");
    ctx.fillStyle = document.documentElement.dataset.theme === "dark" ? "#0e1114" : "#fcfbf8";
    ctx.fillRect(0, 0, out.width, out.height);
    ctx.drawImage(base, 0, 0, out.width, out.height);
    ctx.drawImage(marks, 0, 0, out.width, out.height);
    const link = document.createElement("a");
    link.download = `${window.IL_STATE?.ticker || "implied-lens"}-${activeChartId || "chart"}.png`;
    link.href = out.toDataURL("image/png");
    link.click();
    setSaveState("PNG exported");
  }

  function installChartPersistence() {
    if (typeof window.expandChart !== "function") return;
    const originalExpand = window.expandChart;
    window.expandChart = function (chartId, title) {
      activeChartId = chartId;
      restoringMarkup = true;
      originalExpand(chartId, title);
      restoringMarkup = false;
      setTimeout(loadMarkup, 0);
    };
    const originalClose = window.closeExpandModal;
    window.closeExpandModal = function () {
      saveMarkup();
      return originalClose();
    };
    const originalUndo = window.undoMarkup;
    window.undoMarkup = function () {
      if (_markup?.items?.length) redoItems.push(_markup.items[_markup.items.length - 1]);
      originalUndo();
      saveMarkup();
    };
    const originalClear = window.clearMarkup;
    window.clearMarkup = function () {
      if (_markup?.items?.length) redoItems = [..._markup.items];
      originalClear();
      if (!restoringMarkup) saveMarkup();
    };
    window.redoMarkup = function () {
      const item = redoItems.pop();
      if (!item) return;
      _markup.items.push(item);
      drawMarkup();
      saveMarkup();
    };
    window.exportExpandedChart = exportExpandedChart;
    const canvas = document.getElementById("chart-markup");
    if (canvas) {
      canvas.addEventListener("pointerup", () => setTimeout(saveMarkup, 0));
      canvas.addEventListener("pointerdown", () => {
        if (_markup?.tool !== "cursor") redoItems = [];
        setTimeout(saveMarkup, 0);
      });
    }
  }

  function provenanceLabel(p) {
    if (!p) return { source: "Aggregated market data", freshness: "Provider timing varies", warn: true };
    const age = Number(p.ageSeconds);
    let freshness = "Latest observation";
    if (Number.isFinite(age)) {
      const mins = Math.round(age / 60);
      const days = Math.floor(age / 86400);
      freshness = days >= 1 ? `${days}d since latest observation` : mins >= 1 ? `${mins}m since latest observation` : "Latest observation under 1m old";
    }
    if (p.delayed && !Number.isFinite(age)) freshness = "Provider timing varies";
    return { source: p.source || "Aggregated market data", freshness, warn: Boolean(p.delayed) };
  }
  function renderTrust(result) {
    const host = document.getElementById("r-time");
    if (!host) return;
    const p = provenanceLabel(result?.impliedLensProvenance);
    host.textContent = "Latest available market context";
    let row = document.getElementById("il-trust-row");
    if (!row) {
      row = document.createElement("div");
      row.id = "il-trust-row";
      row.className = "il-trust-row";
      host.parentElement.appendChild(row);
    }
    row.innerHTML = `<span class="il-trust-chip"><i class="ti ti-database"></i>${p.source}</span><span class="il-trust-chip ${p.warn ? "warn" : ""}"><i class="ti ti-clock"></i>${p.freshness}</span><a class="il-trust-chip" href="/data-sources"><i class="ti ti-external-link"></i>Methodology</a>`;
  }

  function installQuoteTrust() {
    if (typeof window.renderStock === "function") {
      const originalRender = window.renderStock;
      window.renderStock = function (result, ticker) {
        const output = originalRender(result, ticker);
        renderTrust(result);
        renderTickerGuidance(ticker);
        decorateMetricLearning();
        return output;
      };
    }
  }

  function renderTickerGuidance(ticker) {
    const host = document.getElementById("stock-result");
    if (!host || !ticker) return;
    let guide = document.getElementById("il-ticker-guidance");
    if (!guide) {
      guide = document.createElement("div");
      guide.id = "il-ticker-guidance";
      guide.className = "il-guidance";
      host.insertBefore(guide, host.firstChild);
    }
    guide.innerHTML = `<div class="il-guidance-copy"><strong>Build a complete ${ticker} decision, not just a price opinion.</strong><span>Start with the chart, then test business quality, valuation, and downside assumptions.</span></div><div class="il-guidance-actions"><button onclick="navGoTo('education');setTimeout(()=>openLesson(document.querySelector('[data-lesson=thesis]')),50)">Write thesis</button><button onclick="navGoTo('education');setTimeout(()=>openLesson(document.querySelector('[data-lesson=risk]')),50)">Define risk</button><button class="primary" onclick="saveAnalysis('price')">Save snapshot</button></div>`;
  }

  function decorateMetricLearning() {
    document.querySelectorAll("#metrics-grid .m-lbl").forEach((label) => {
      if (label.querySelector(".il-metric-learn")) return;
      const lesson = /RSI|MA 50|MA 200|Volatility/i.test(label.textContent) ? "chart" : /Market Cap|52W|Volume/i.test(label.textContent) ? "thesis" : "quality";
      const button = document.createElement("button");
      button.className = "il-metric-learn";
      button.title = "Learn how to use this metric";
      button.textContent = "?";
      button.onclick = () => {
        navGoTo("education");
        setTimeout(() => openLesson(document.querySelector(`[data-lesson=${lesson}]`)), 50);
      };
      label.appendChild(button);
    });
  }

  function installEducationContext() {
    const hero = document.querySelector("#body-education .edu-hero");
    if (hero && !document.getElementById("il-edu-context")) {
      const context = document.createElement("div");
      context.id = "il-edu-context";
      context.className = "il-guidance";
      hero.insertAdjacentElement("afterend", context);
    }
    const update = () => {
      const context = document.getElementById("il-edu-context");
      if (!context) return;
      const ticker = window.IL_STATE?.ticker;
      context.innerHTML = ticker
        ? `<div class="il-guidance-copy"><strong>Apply the Academy to ${ticker}</strong><span>Use each lesson against the live analysis you already loaded. Your ticker stays available as you move between tools.</span></div><div class="il-guidance-actions"><button onclick="openLesson(document.querySelector('[data-lesson=quality]'))">Quality</button><button onclick="openLesson(document.querySelector('[data-lesson=valuation]'))">Valuation</button><button class="primary" onclick="openLesson(document.querySelector('[data-lesson=review]'))">Review workflow</button></div>`
        : `<div class="il-guidance-copy"><strong>Learn with a real company.</strong><span>Load a ticker first, then return here to apply each framework to live market data.</span></div><div class="il-guidance-actions"><button class="primary" onclick="navGoTo('analyze')">Load a ticker</button></div>`;
    };
    update();
    document.querySelectorAll(".edu-checklist input").forEach((input, index) => {
      const stored = read(KEYS.checklist, []);
      input.checked = Boolean(stored[index]);
      input.addEventListener("change", () => write(KEYS.checklist, [...document.querySelectorAll(".edu-checklist input")].map(el => el.checked)));
    });
    if (typeof window.resetEduChecklist === "function") {
      const originalReset = window.resetEduChecklist;
      window.resetEduChecklist = function () { originalReset(); write(KEYS.checklist, []); };
    }
    if (typeof window.openSection === "function") {
      const originalOpen = window.openSection;
      window.openSection = function (id, skip) { const out = originalOpen(id, skip); if (id === "education") update(); return out; };
    }
  }

  function installOnboarding() {
    if (read(KEYS.onboarding, false)) return;
    const host = document.getElementById("tool-welcome");
    if (!host || document.getElementById("il-onboarding")) return;
    const box = document.createElement("div");
    box.id = "il-onboarding";
    box.className = "il-onboarding";
    box.innerHTML = `<div class="il-onboarding-top"><div><h3>Your first analysis, in three moves</h3><p>Use a real ticker and leave with a saved, reviewable investment snapshot.</p></div><button class="il-onboarding-close" aria-label="Dismiss onboarding">×</button></div><div class="il-onboarding-steps"><div class="il-onboarding-step"><strong>01 Load</strong>Search a company you understand.</div><div class="il-onboarding-step"><strong>02 Test</strong>Check trend, quality, valuation, and risk.</div><div class="il-onboarding-step"><strong>03 Save</strong>Keep the snapshot for your next review.</div></div>`;
    host.insertBefore(box, host.firstChild);
    box.querySelector(".il-onboarding-close").onclick = () => { write(KEYS.onboarding, true); box.remove(); };
  }

  async function installBuildBadge() {
    try {
      const response = await fetch("/api/version", { cache: "no-store" });
      if (!response.ok) return;
      const build = await response.json();
      const footer = document.querySelector(".f-copy");
      if (!footer) return;
      const badge = document.createElement("span");
      badge.className = "il-build";
      badge.title = `Version ${build.version}; started ${build.startedAt}`;
      badge.textContent = `Build ${build.shortCommit}`;
      footer.append(" · ", badge);
    } catch (_) {}
  }

  function installFeedbackPrompt() {
    if (document.getElementById("il-feedback-modal")) return;
    let rating = 0;
    const labels = [
      "",
      "We want to understand what fell short.",
      "Tell us what would make the experience more useful.",
      "Thank you. What would move Implied Lens forward?",
      "Great to hear. What should we refine next?",
      "Thank you. Tell us what is working especially well.",
    ];
    const modal = document.createElement("div");
    modal.id = "il-feedback-modal";
    modal.className = "il-feedback-modal";
    modal.setAttribute("role", "dialog");
    modal.setAttribute("aria-modal", "true");
    modal.setAttribute("aria-labelledby", "il-feedback-title");
    modal.innerHTML = `<div class="il-feedback-card">
      <div class="il-feedback-top"><div><div class="il-feedback-kicker">Member experience</div><h2 id="il-feedback-title">How is Implied Lens working for you?</h2><p>Your honest perspective helps us prioritize the right improvements.</p></div><button class="il-feedback-close" aria-label="Close feedback"><i class="ti ti-x"></i></button></div>
      <div class="il-feedback-stars" role="group" aria-label="Rate your experience">${[1,2,3,4,5].map(value => `<button class="il-feedback-star" data-rating="${value}" aria-label="${value} out of 5 stars" aria-pressed="false"><i class="ti ti-star-filled"></i></button>`).join("")}</div>
      <p class="il-feedback-label" id="il-feedback-label">Choose a rating to begin.</p>
      <textarea class="il-feedback-note" id="il-feedback-note" aria-label="Feedback details" placeholder="What is working well, and what should we improve?"></textarea>
      <div class="il-feedback-actions"><button class="il-feedback-action primary" id="il-feedback-email"><i class="ti ti-mail"></i> Email feedback</button><button class="il-feedback-action" id="il-feedback-share"><i class="ti ti-share-3"></i> Share your experience</button></div>
      <p class="il-feedback-policy">Honest feedback is always welcome. Any member thank-you offer applies regardless of rating or sentiment; public posts should disclose the offer.</p>
    </div>`;
    document.body.appendChild(modal);
    const label = modal.querySelector("#il-feedback-label");
    const note = modal.querySelector("#il-feedback-note");
    const close = () => modal.classList.remove("open");
    const open = () => {
      modal.classList.add("open");
      if (typeof window.track === "function") window.track("feedback_opened");
      setTimeout(() => modal.querySelector(".il-feedback-star")?.focus(), 0);
    };
    modal.querySelector(".il-feedback-close").onclick = close;
    modal.onclick = event => { if (event.target === modal) close(); };
    document.addEventListener("keydown", event => { if (event.key === "Escape" && modal.classList.contains("open")) close(); });
    modal.querySelectorAll("[data-rating]").forEach(button => button.onclick = () => {
      rating = Number(button.dataset.rating);
      modal.querySelectorAll("[data-rating]").forEach(star => {
        const active = Number(star.dataset.rating) <= rating;
        star.classList.toggle("active", active);
        star.setAttribute("aria-pressed", String(active));
      });
      label.textContent = labels[rating];
      if (typeof window.track === "function") window.track("feedback_rated", { rating });
    });
    modal.querySelector("#il-feedback-email").onclick = () => {
      const subject = `Implied Lens feedback${rating ? ` - ${rating}/5` : ""}`;
      const body = `${rating ? `Experience rating: ${rating}/5\n\n` : ""}${note.value.trim()}`;
      if (typeof window.track === "function") window.track("feedback_email_opened", { rating: rating || null });
      window.location.href = `mailto:support@impliedlens.com?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;
    };
    modal.querySelector("#il-feedback-share").onclick = async () => {
      const text = "My honest experience with Implied Lens:";
      if (typeof window.track === "function") window.track("feedback_shared", { rating: rating || null });
      if (navigator.share) {
        try { await navigator.share({ title: "Implied Lens", text, url: "https://impliedlens.com" }); return; } catch (_) {}
      }
      window.open(`https://twitter.com/intent/tweet?text=${encodeURIComponent(text)}&url=${encodeURIComponent("https://impliedlens.com")}`, "_blank", "noopener,noreferrer");
    };
    const footerLinks = document.querySelector(".f-links");
    if (footerLinks) {
      const button = document.createElement("button");
      button.className = "il-feedback-link";
      button.textContent = "Give feedback";
      button.onclick = open;
      footerLinks.appendChild(button);
    }
    const moreMenu = document.querySelector(".mmenu-grid");
    if (moreMenu) {
      const button = document.createElement("button");
      button.className = "mmenu-item il-feedback-link";
      button.innerHTML = '<i class="ti ti-message-star"></i><span>Feedback</span>';
      button.onclick = () => { window._toggleMobileMenu?.(); open(); };
      moreMenu.appendChild(button);
    }
    window.openFeedbackPrompt = open;
  }

  function improveUnavailableStates() {
    const indexChanges = ["ri-sp-c", "ri-nq-c", "ri-dj-c"]
      .map(id => document.getElementById(id)?.textContent || "")
      .filter(text => /[▲▼]/.test(text));
    if (indexChanges.length) {
      const advancing = indexChanges.filter(text => text.includes("▲")).length;
      const declining = indexChanges.filter(text => text.includes("▼")).length;
      const adv = document.getElementById("mo-advancing");
      const dec = document.getElementById("mo-declining");
      const advBar = document.getElementById("mo-adv-bar");
      const decBar = document.getElementById("mo-dec-bar");
      if (adv) adv.textContent = `${advancing}/${indexChanges.length}`;
      if (dec) dec.textContent = `${declining}/${indexChanges.length}`;
      if (advBar) advBar.style.width = `${advancing / indexChanges.length * 100}%`;
      if (decBar) decBar.style.width = `${declining / indexChanges.length * 100}%`;
    }
    ["mo-adv-pct", "mo-dec-pct"].forEach((id) => {
      const el = document.getElementById(id);
      if (el && /Dedicated feed required/i.test(el.textContent)) {
        el.textContent = "Index direction proxy";
        el.classList.add("il-source-unavailable");
      }
    });
    [
      ["mo-highs-sub", "52-week breadth"],
      ["mo-lows-sub", "52-week breadth"],
      ["mo-vol-sub", "NYSE volume breadth"],
    ].forEach(([id, text]) => {
      const el = document.getElementById(id);
      if (el && !/unavailable/i.test(el.textContent)) el.textContent = text;
    });
  }

  function init() {
    installChartPersistence();
    installQuoteTrust();
    installEducationContext();
    installOnboarding();
    installBuildBadge();
    installFeedbackPrompt();
    improveUnavailableStates();
    setInterval(improveUnavailableStates, 1500);
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
}());
