(function () {
  "use strict";

  const CALL_NOTES = "il-call-scorecards-v1";
  let wealthChart = null;
  let callsLoadedTicker = null;

  function esc(value) {
    return String(value ?? "").replace(/[&<>"']/g, char => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[char]));
  }
  function read(key, fallback) { try { return JSON.parse(localStorage.getItem(key) || JSON.stringify(fallback)); } catch (_) { return fallback; } }
  function write(key, value) { try { localStorage.setItem(key, JSON.stringify(value)); } catch (_) {} }
  function ticker() { return String(window.IL_STATE?.ticker || document.getElementById("main-ticker")?.value || "").trim().toUpperCase().replace(/[^A-Z0-9.^-]/g, "").slice(0, 15); }
  function money(value) { return Number(value).toLocaleString("en-US", { style: "currency", currency: "USD", maximumFractionDigits: 0 }); }
  function dateLabel(value) {
    if (!value) return "Date unavailable";
    const numeric = Number(value);
    const date = Number.isFinite(numeric) ? new Date(numeric > 100000000000 ? numeric : numeric * 1000) : new Date(value);
    return Number.isNaN(date.getTime()) ? "Date unavailable" : date.toLocaleDateString();
  }
  function trackEvent(event, properties) { if (typeof window.track === "function") window.track(event, properties || {}); }
  function toastMsg(message, kind) { if (typeof window.toast === "function") window.toast(message, kind); }

  function injectNavigation() {
    // (Market-page sidebar mirrors removed 2026-07-13 — each top tab owns its own left panel.)
    const earnings = document.querySelector('.app-sidebar .sb-item[data-sec="earnings"]');
    if (earnings && !document.querySelector('.app-sidebar .sb-item[data-sec="calls"]')) {
      earnings.insertAdjacentHTML("afterend", `<div class="sb-item" data-sec="calls"><i class="ti ti-headphones sb-item-icon" aria-hidden="true"></i><span class="sb-item-label">Earnings Releases</span></div>`);
    }
    const dcf = document.querySelector('.app-sidebar .sb-item[data-sec="dcf"]');
    if (dcf && !document.querySelector('.app-sidebar .sb-item[data-sec="wealth"]')) {
      dcf.insertAdjacentHTML("afterend", `<div class="sb-item" data-sec="wealth"><i class="ti ti-chart-dots-3 sb-item-icon" aria-hidden="true"></i><span class="sb-item-label">Wealth Planner</span></div>`);
    }
    const mobileTabs = document.getElementById("mobile-sec-tabs");
    if (mobileTabs && !mobileTabs.querySelector('[data-sec="wealth"]')) {
      mobileTabs.insertAdjacentHTML("beforeend", `<button class="mst-btn" data-sec="calls">Releases</button><button class="mst-btn" data-sec="wealth">Wealth</button>`);
    }
    const more = document.querySelector(".mmenu-grid");
    if (more && !more.querySelector('[data-il-nav="calls"]')) {
      more.insertAdjacentHTML("beforeend", `<a href="#" class="mmenu-item" data-il-nav="calls" onclick="navGoTo('calls');_setMobileNav('calls');_toggleMobileMenu();return false;"><i class="ti ti-headphones"></i><span>Releases</span></a><a href="#" class="mmenu-item" data-il-nav="wealth" onclick="navGoTo('wealth');_setMobileNav('wealth');_toggleMobileMenu();return false;"><i class="ti ti-chart-dots-3"></i><span>Wealth</span></a>`);
    }
  }

  function callsHtml() {
    return `<div class="app-section" id="sec-calls"><div class="acc-body" id="body-calls" style="display:none"><div class="il-research-shell">
      <div class="il-research-hero"><div><div class="il-research-kicker">Earnings releases</div><h2>Listen for changes, not confidence.</h2><p>Every quarter's results release as the company filed it with the SEC, the numbers beside it, and your own before-and-after scorecard.</p></div><div class="il-research-actions"><button class="il-research-btn primary" id="il-load-calls"><i class="ti ti-refresh"></i>Load current ticker</button></div></div>
      <div class="il-research-grid">
        <section class="il-research-panel"><h3 id="il-call-title">Recent results</h3><p id="il-call-sub">Load a ticker to begin.</p><div class="il-call-links" id="il-call-links"></div><div class="il-call-list" id="il-call-list"><div class="il-call-empty">Search a company in Analyze, then return here to read its results releases.</div></div><div class="il-transcript-reader" id="il-transcript-reader"></div></section>
        <section class="il-research-panel"><h3>Results scorecard</h3><p>Write what you expect before the release, then record what changed. Saved on this device by ticker.</p><div class="il-scorecard">
          <div class="il-score-field"><label for="il-call-expectation">Before the results: what must be true?</label><textarea id="il-call-expectation" data-call-note="expectation"></textarea></div>
          <div class="il-score-field"><label for="il-call-demand">Demand and revenue change</label><textarea id="il-call-demand" data-call-note="demand"></textarea></div>
          <div class="il-score-field"><label for="il-call-margin">Margins and cash flow change</label><textarea id="il-call-margin" data-call-note="margin"></textarea></div>
          <div class="il-score-field"><label for="il-call-guidance">Guidance and management credibility</label><textarea id="il-call-guidance" data-call-note="guidance"></textarea></div>
          <div class="il-score-field"><label for="il-call-risks">New risks or thesis breaks</label><textarea id="il-call-risks" data-call-note="risks"></textarea></div>
          <div class="il-score-field"><label for="il-call-next">Next evidence to check</label><textarea id="il-call-next" data-call-note="next"></textarea></div>
          <div class="il-score-save"><button class="il-research-btn primary" id="il-save-call-score"><i class="ti ti-device-floppy"></i>Save scorecard</button><span class="il-score-status" id="il-score-status">No ticker loaded</span></div>
        </div></section>
      </div>
    </div></div></div>`;
  }

  function wealthHtml() {
    return `<div class="app-section" id="sec-wealth"><div class="acc-body" id="body-wealth" style="display:none"><div class="il-research-shell">
      <div class="il-research-hero"><div><div class="il-research-kicker">Wealth planner</div><h2>Model the range, not a fantasy.</h2><p>Compare low, base, and high compounding paths, separate contributions from investment growth, and show purchasing power after inflation.</p></div><div class="il-research-actions"><button class="il-research-btn" id="il-share-wealth"><i class="ti ti-share-3"></i>Share plan</button><a class="il-research-btn" href="/research-process"><i class="ti ti-route"></i>Research process</a></div></div>
      <div class="il-wealth-layout">
        <section class="il-research-panel"><h3>Assumptions</h3><p>Returns are hypothetical and should be tested against realistic base rates.</p><div class="il-wealth-inputs">
          <div class="il-wealth-field"><label for="il-w-principal">Starting portfolio</label><input id="il-w-principal" type="number" min="0" step="1000" value="30000"></div>
          <div class="il-wealth-field"><label for="il-w-monthly">Monthly contribution</label><input id="il-w-monthly" type="number" min="0" step="100" value="1500"></div>
          <div class="il-wealth-field"><label for="il-w-years">Years</label><input id="il-w-years" type="number" min="1" max="60" step="1" value="15"></div>
          <div class="il-wealth-field"><label for="il-w-return">Base annual return %</label><input id="il-w-return" type="number" min="-99" max="100" step=".1" value="10"></div>
          <div class="il-wealth-field"><label for="il-w-variance">Scenario range +/- %</label><input id="il-w-variance" type="number" min="0" max="50" step=".1" value="3"></div>
          <div class="il-wealth-field"><label for="il-w-inflation">Inflation %</label><input id="il-w-inflation" type="number" min="-10" max="30" step=".1" value="2.5"></div>
          <div class="il-wealth-field"><label for="il-w-fee">Annual fees %</label><input id="il-w-fee" type="number" min="0" max="20" step=".05" value=".25"></div>
          <div class="il-wealth-field"><label for="il-w-tax">Annual tax drag %</label><input id="il-w-tax" type="number" min="0" max="50" step=".1" value="0"></div>
        </div><div class="il-score-save"><button class="il-research-btn primary" id="il-run-wealth"><i class="ti ti-calculator"></i>Run scenarios</button></div><div class="il-wealth-note">The model compounds monthly, deducts optional annual fee and tax drag from each scenario return, and assumes contributions arrive at month end. It does not model withdrawals or changing return sequences.</div></section>
        <section class="il-research-panel"><div class="il-wealth-results" id="il-wealth-results"></div><div class="il-wealth-chart"><canvas id="il-wealth-chart" role="img" aria-label="Low, base, high, and contribution wealth scenarios over time"></canvas></div></section>
      </div>
    </div></div></div>`;
  }

  function injectSections() {
    const content = document.querySelector(".app-content-scroll");
    if (!content || document.getElementById("sec-calls")) return;
    const secFilings = document.getElementById("sec-secfilings");
    const reports = document.getElementById("sec-reports");
    if (secFilings) secFilings.insertAdjacentHTML("beforebegin", callsHtml());
    else content.insertAdjacentHTML("beforeend", callsHtml());
    if (reports) reports.insertAdjacentHTML("beforebegin", wealthHtml());
    else content.insertAdjacentHTML("beforeend", wealthHtml());

    if (typeof PRO_SECTIONS !== "undefined" && !PRO_SECTIONS.includes("calls")) PRO_SECTIONS.push("calls");
    if (typeof PRO_GATE_CONFIG !== "undefined") {
      PRO_GATE_CONFIG.calls = {
        title: "Earnings releases",
        bullets: [
          "Every quarterly results release, as filed with the SEC",
          "Revenue, net income and EPS for each quarter, with the change from a year earlier",
          "One click to the 10-Q or 10-K that followed",
          "A before-and-after scorecard per ticker, so you record what changed",
        ],
        preview: null,
      };
    }
    if (window.SECTION_META) {
      window.SECTION_META.calls = { icon: "ti-headphones", title: "Earnings Releases" };
      window.SECTION_META.wealth = { icon: "ti-chart-dots-3", title: "Wealth Planner" };
    } else if (typeof SECTION_META !== "undefined") {
      SECTION_META.calls = { icon: "ti-headphones", title: "Earnings Releases" };
      SECTION_META.wealth = { icon: "ti-chart-dots-3", title: "Wealth Planner" };
    }
  }

  function loadCallNotes() {
    const current = ticker();
    const notes = read(CALL_NOTES, {})[current] || {};
    document.querySelectorAll("[data-call-note]").forEach(field => { field.value = notes[field.dataset.callNote] || ""; });
    const status = document.getElementById("il-score-status");
    if (status) status.textContent = current ? (notes.updatedAt ? `Saved ${new Date(notes.updatedAt).toLocaleDateString()}` : `Ready for ${current}`) : "No ticker loaded";
  }

  function saveCallScorecard() {
    const current = ticker();
    if (!current) return toastMsg("Load a ticker before saving the scorecard", "red");
    const store = read(CALL_NOTES, {});
    const notes = {};
    document.querySelectorAll("[data-call-note]").forEach(field => { notes[field.dataset.callNote] = field.value.trim(); });
    store[current] = { ...notes, updatedAt: new Date().toISOString() };
    write(CALL_NOTES, store);
    loadCallNotes();
    trackEvent("call_scorecard_saved", { ticker: current });
    toastMsg(`${current} call scorecard saved`, "ok");
  }

  function renderCallLinks(data) {
    const links = document.getElementById("il-call-links");
    if (!links) return;
    const items = [
      [data.links?.website, "Company site", "ti-building"],
      [data.links?.sec, "All 8-K filings", "ti-file-text"],
    ].filter(item => item[0]);
    links.innerHTML = items.map(([url, label, icon]) => `<a class="il-research-btn" href="${esc(url)}" target="_blank" rel="noopener noreferrer"><i class="ti ${icon}"></i>${label}</a>`).join("");
  }

  function bigMoney(v) {
    if (v == null || !Number.isFinite(Number(v))) return "\u2014";
    const a = Math.abs(v), sign = v < 0 ? "-" : "";
    return a >= 1e9 ? `${sign}$${(a / 1e9).toFixed(a >= 1e11 ? 0 : 1)}B` : a >= 1e6 ? `${sign}$${(a / 1e6).toFixed(0)}M` : `${sign}$${Math.round(a).toLocaleString("en-US")}`;
  }
  function change(v) {
    if (v == null || !Number.isFinite(Number(v))) return "";
    return `<em class="${v >= 0 ? "is-gain" : "is-drop"}">${v >= 0 ? "+" : ""}${v.toFixed(Math.abs(v) >= 100 ? 0 : 1)}% y/y</em>`;
  }
  function releaseDate(d) {
    const t = Date.parse(`${d}T12:00:00Z`);
    return Number.isFinite(t) ? new Date(t).toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric", timeZone: "UTC" }) : "";
  }

  async function loadCallResearch(force) {
    const current = ticker();
    const list = document.getElementById("il-call-list");
    const title = document.getElementById("il-call-title");
    const sub = document.getElementById("il-call-sub");
    if (!list) return;
    loadCallNotes();
    if (!current) {
      list.innerHTML = `<div class="il-call-empty">Search a company in Analyze, then return here to read its results releases.</div>`;
      return;
    }
    if (!force && (
      (callsLoadedTicker === current && list.dataset.loaded === current) ||
      list.dataset.loading === current
    )) return;
    callsLoadedTicker = current;
    list.dataset.loading = current;
    if (title) title.textContent = `${current} recent results`;
    if (sub) sub.textContent = "Loading results releases from SEC filings\u2026";
    list.innerHTML = `<div class="il-call-empty">Loading ${esc(current)} results releases\u2026</div>`;
    try {
      const response = await fetch(`/api/calls/${encodeURIComponent(current)}`, { credentials: "same-origin" });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.error || "Results releases are unavailable.");
      renderCallLinks(data);
      const rows = data.releases || [];
      if (data.unavailable) {
        if (sub) sub.textContent = data.error || "SEC filings are temporarily unavailable.";
        list.innerHTML = `<div class="il-call-empty">${esc(data.error || "SEC filings are temporarily unavailable.")} Your scorecard still works.</div>`;
        return;
      }
      if (sub) sub.textContent = rows.length
        ? `${rows.length} quarterly results releases filed with the SEC (Form 8-K, Item 2.02). Numbers are as the company reported them in XBRL.`
        : "No results releases found in this company's recent SEC filings.";
      list.innerHTML = rows.length ? rows.map(r => {
        const q = r.quarter;
        const nums = q ? `<div class="il-rel-nums">
            <span><small>Revenue</small><b>${bigMoney(q.revenue)}</b>${change(q.revenueYoY)}</span>
            <span><small>Net income</small><b>${bigMoney(q.netIncome)}</b>${change(q.netIncomeYoY)}</span>
            <span><small>EPS (diluted)</small><b>${q.eps != null ? (q.eps < 0 ? "-$" : "$") + Math.abs(q.eps).toFixed(2) : "\u2014"}</b>${change(q.epsYoY)}</span>
          </div>` : `<div class="il-rel-pending">The numbers appear here once the company files its 10-Q or 10-K, usually within a few weeks of the release. The release itself is ready to read.</div>`;
        return `<div class="il-call-row il-rel-row"><div class="il-call-period">${esc(q ? q.label : "Release")}</div><div class="il-call-title">${esc(r.title)}<span>Released ${esc(releaseDate(r.date))}</span>${nums}</div><div class="il-rel-actions"><button class="il-research-btn" data-release-id="${esc(r.id)}"><i class="ti ti-file-description"></i>Read release</button>${r.report ? `<a class="il-research-btn" href="${esc(r.report.url)}" target="_blank" rel="noopener noreferrer"><i class="ti ti-file-text"></i>${esc(r.report.form)}</a>` : ""}</div></div>`;
      }).join("") : `<div class="il-call-empty">No results releases are in this company's recent SEC filings. Foreign companies often file theirs on Form 6-K, which is not covered yet.</div>`;
      list.dataset.loaded = current;
      list.querySelectorAll("[data-release-id]").forEach(button => button.onclick = () => openCallTranscript(button.dataset.releaseId));
      trackEvent("call_research_loaded", { ticker: current, releases: rows.length });
    } catch (error) {
      list.innerHTML = `<div class="il-call-empty">${esc(error.message)}</div>`;
    } finally {
      if (list.dataset.loading === current) delete list.dataset.loading;
    }
  }

  /* The results release itself, as the company filed it (Exhibit 99.1). */
  async function openCallTranscript(id) {
    const current = ticker();
    const reader = document.getElementById("il-transcript-reader");
    if (!reader || !current || !id) return;
    reader.classList.add("open");
    reader.innerHTML = `<div class="il-call-empty">Loading the release from the SEC\u2026</div>`;
    try {
      const response = await fetch(`/api/calls/${encodeURIComponent(current)}/${encodeURIComponent(id)}`, { credentials: "same-origin" });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.error || "This release is unavailable.");
      const paras = data.paragraphs || [];
      reader.innerHTML = `<div class="il-transcript-head"><div><div class="il-research-kicker">Results release \u00b7 ${esc(releaseDate(data.date))}</div><h3>${esc(current)}: what the company said</h3></div><div class="il-rel-actions"><a class="il-research-btn" href="${esc(data.url)}" target="_blank" rel="noopener noreferrer"><i class="ti ti-external-link"></i>Full release on SEC.gov</a><button class="il-research-btn" id="il-close-transcript"><i class="ti ti-x"></i>Close</button></div></div>
        <p class="il-rel-note">The company's own words, unedited. Financial tables are left out here; the numbers above come from its XBRL data.</p>
        <div class="il-transcript-copy">${paras.length ? paras.map(p => `<p class="il-rel-p">${esc(p)}</p>`).join("") : `<div class="il-call-empty">This release has no readable text. Open it on SEC.gov.</div>`}</div>`;
      document.getElementById("il-close-transcript").onclick = () => { reader.classList.remove("open"); reader.innerHTML = ""; };
      reader.scrollIntoView({ behavior: "smooth", block: "start" });
      trackEvent("earnings_release_opened", { ticker: current });
    } catch (error) {
      reader.innerHTML = `<div class="il-call-empty">${esc(error.message)}</div>`;
    }
  }

  function wealthInput() {
    return {
      principal: Number(document.getElementById("il-w-principal")?.value),
      monthlyContribution: Number(document.getElementById("il-w-monthly")?.value),
      years: Number(document.getElementById("il-w-years")?.value),
      baseReturn: Number(document.getElementById("il-w-return")?.value) / 100,
      variance: Number(document.getElementById("il-w-variance")?.value) / 100,
      inflation: Number(document.getElementById("il-w-inflation")?.value) / 100,
      annualFee: Number(document.getElementById("il-w-fee")?.value) / 100,
      taxDrag: Number(document.getElementById("il-w-tax")?.value) / 100,
    };
  }

  function chartTheme() {
    const style = getComputedStyle(document.documentElement);
    return {
      text: style.getPropertyValue("--text4").trim() || "#747a80",
      grid: style.getPropertyValue("--border2").trim() || "rgba(120,120,120,.18)",
      gold: style.getPropertyValue("--brand-gold").trim() || "#8b6527",
      positive: style.getPropertyValue("--positive").trim() || "#247757",
      negative: style.getPropertyValue("--negative").trim() || "#a94f55",
    };
  }

  function renderWealthChart(result) {
    const canvas = document.getElementById("il-wealth-chart");
    if (!canvas || typeof Chart === "undefined") return;
    if (wealthChart) wealthChart.destroy();
    const theme = chartTheme();
    const labels = result.base.path.map(point => `Year ${Math.round(point.month / 12)}`);
    wealthChart = new Chart(canvas, {
      type: "line",
      data: {
        labels,
        datasets: [
          { label: "High", data: result.high.path.map(point => point.value), borderColor: theme.positive, borderWidth: 1.5, pointRadius: 0, tension: .2 },
          { label: "Base", data: result.base.path.map(point => point.value), borderColor: theme.gold, borderWidth: 2.3, pointRadius: 0, tension: .2 },
          { label: "Low", data: result.low.path.map(point => point.value), borderColor: theme.negative, borderWidth: 1.5, pointRadius: 0, tension: .2 },
          { label: "Contributions", data: result.base.path.map(point => point.contributions), borderColor: theme.text, borderDash: [4, 4], borderWidth: 1, pointRadius: 0, tension: .2 },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        interaction: { intersect: false, mode: "index" },
        plugins: { legend: { labels: { color: theme.text, boxWidth: 10, boxHeight: 2, font: { size: 10 } } }, tooltip: { callbacks: { label: context => `${context.dataset.label}: ${money(context.raw)}` } } },
        scales: {
          x: { ticks: { color: theme.text, maxRotation: 0, autoSkip: true, maxTicksLimit: 8, font: { size: 9 } }, grid: { display: false }, border: { color: theme.grid } },
          y: { ticks: { color: theme.text, callback: value => money(value), font: { size: 9 } }, grid: { color: theme.grid }, border: { color: theme.grid } },
        },
      },
    });
  }

  function runWealthPlanner() {
    const results = document.getElementById("il-wealth-results");
    if (!results || !window.ImpliedLensMath) return;
    const input = wealthInput();
    const output = window.ImpliedLensMath.compoundScenarios(input);
    if (!output.ok) {
      results.innerHTML = `<div class="il-call-empty" style="grid-column:1/-1">${esc(output.error)}</div>`;
      return;
    }
    results.innerHTML = [
      ["Low case", output.low.value, ""],
      ["Base case", output.base.value, "base"],
      ["High case", output.high.value, ""],
      ["Base in today's dollars", output.realValue, ""],
    ].map(([label, value, cls]) => `<div class="il-wealth-result ${cls}"><span>${label}</span><strong>${money(value)}</strong></div>`).join("");
    renderWealthChart(output);
    trackEvent("wealth_plan_run", { years: input.years, base_return: input.baseReturn });
  }

  async function shareWealthPlan() {
    const input = wealthInput();
    const output = window.ImpliedLensMath?.compoundScenarios(input);
    if (!output?.ok) return runWealthPlanner();
    const text = `ImpliedLens wealth plan: ${money(input.principal)} starting balance + ${money(input.monthlyContribution)}/month for ${input.years} years. Base scenario: ${money(output.base.value)} at ${(input.baseReturn * 100).toFixed(1)}%. Hypothetical, not investment advice.`;
    trackEvent("wealth_plan_shared", { years: input.years });
    if (navigator.share) {
      try { await navigator.share({ title: "ImpliedLens Wealth Plan", text, url: "https://impliedlens.com/?view=tool&section=wealth" }); return; } catch (_) {}
    }
    try { await navigator.clipboard.writeText(text); toastMsg("Plan summary copied", "ok"); } catch (_) { toastMsg("Could not copy plan summary", "red"); }
  }

  function wire() {
    document.getElementById("il-load-calls").onclick = () => loadCallResearch(true);
    document.getElementById("il-save-call-score").onclick = saveCallScorecard;
    document.getElementById("il-run-wealth").onclick = runWealthPlanner;
    document.getElementById("il-share-wealth").onclick = shareWealthPlan;
    const originalOpen = window.openSection;
    window.openSection = function (id, skip) {
      const result = originalOpen(id, skip);
      if (id === "calls" && (typeof isPro !== "function" || isPro())) loadCallResearch();
      if (id === "wealth") setTimeout(runWealthPlanner, 0);
      return result;
    };
    window.loadCallResearch = loadCallResearch;
    window.runWealthPlanner = runWealthPlanner;
  }

  function init() {
    injectNavigation();
    injectSections();
    wire();
    loadCallNotes();
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
}());
