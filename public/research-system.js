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
    const homeAnalyze = document.querySelector(".hs-sidebar .hsb-section:first-of-type");
    if (homeAnalyze && !homeAnalyze.querySelector('[data-il-nav="calls"]')) {
      homeAnalyze.insertAdjacentHTML("beforeend", `<a class="hsb-item" data-il-nav="calls" href="/?view=tool&amp;section=calls" onclick="navGoTo('calls');return false;"><i class="ti ti-headphones"></i><span>Call Research</span></a>`);
    }
    const homeTools = [...document.querySelectorAll(".hs-sidebar .hsb-section")].find(section => section.querySelector(".hsb-label")?.textContent.trim() === "Tools");
    if (homeTools && !homeTools.querySelector('[data-il-nav="wealth"]')) {
      homeTools.insertAdjacentHTML("beforeend", `<a class="hsb-item" data-il-nav="wealth" href="/?view=tool&amp;section=wealth" onclick="navGoTo('wealth');return false;"><i class="ti ti-chart-dots-3"></i><span>Wealth Planner</span></a>`);
    }
    const earnings = document.querySelector('.app-sidebar .sb-item[data-sec="earnings"]');
    if (earnings && !document.querySelector('.app-sidebar .sb-item[data-sec="calls"]')) {
      earnings.insertAdjacentHTML("afterend", `<div class="sb-item" data-sec="calls"><i class="ti ti-headphones sb-item-icon" aria-hidden="true"></i><span class="sb-item-label">Call Research</span></div>`);
    }
    const dcf = document.querySelector('.app-sidebar .sb-item[data-sec="dcf"]');
    if (dcf && !document.querySelector('.app-sidebar .sb-item[data-sec="wealth"]')) {
      dcf.insertAdjacentHTML("afterend", `<div class="sb-item" data-sec="wealth"><i class="ti ti-chart-dots-3 sb-item-icon" aria-hidden="true"></i><span class="sb-item-label">Wealth Planner</span></div>`);
    }
    const mobileTabs = document.getElementById("mobile-sec-tabs");
    if (mobileTabs && !mobileTabs.querySelector('[data-sec="wealth"]')) {
      mobileTabs.insertAdjacentHTML("beforeend", `<button class="mst-btn" data-sec="calls">Calls</button><button class="mst-btn" data-sec="wealth">Wealth</button>`);
    }
    const more = document.querySelector(".mmenu-grid");
    if (more && !more.querySelector('[data-il-nav="calls"]')) {
      more.insertAdjacentHTML("beforeend", `<a href="#" class="mmenu-item" data-il-nav="calls" onclick="navGoTo('calls');_setMobileNav('calls');_toggleMobileMenu();return false;"><i class="ti ti-headphones"></i><span>Calls</span></a><a href="#" class="mmenu-item" data-il-nav="wealth" onclick="navGoTo('wealth');_setMobileNav('wealth');_toggleMobileMenu();return false;"><i class="ti ti-chart-dots-3"></i><span>Wealth</span></a>`);
    }
  }

  function callsHtml() {
    return `<div class="app-section" id="sec-calls"><div class="acc-body" id="body-calls" style="display:none"><div class="il-research-shell">
      <div class="il-research-hero"><div><div class="il-research-kicker">Earnings-call research</div><h2>Listen for changes, not confidence.</h2><p>Review transcripts, official filings, and your own expectations in one repeatable scorecard. Transcript availability depends on the connected data provider.</p></div><div class="il-research-actions"><button class="il-research-btn primary" id="il-load-calls"><i class="ti ti-refresh"></i>Load current ticker</button></div></div>
      <div class="il-research-grid">
        <section class="il-research-panel"><h3 id="il-call-title">Recent calls</h3><p id="il-call-sub">Load a ticker to begin.</p><div class="il-call-links" id="il-call-links"></div><div class="il-call-list" id="il-call-list"><div class="il-call-empty">Search a company in Analyze, then return here to review its calls.</div></div><div class="il-transcript-reader" id="il-transcript-reader"></div></section>
        <section class="il-research-panel"><h3>Call scorecard</h3><p>Write expectations before the call, then record what changed. Saved on this device by ticker.</p><div class="il-scorecard">
          <div class="il-score-field"><label for="il-call-expectation">Before the call: what must be true?</label><textarea id="il-call-expectation" data-call-note="expectation"></textarea></div>
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
        title: "Earnings-Call Research Center",
        bullets: [
          "Review available earnings-call transcripts without leaving the workflow",
          "Keep a repeatable pre-call and post-call scorecard by ticker",
          "Move directly between calls, SEC filings, earnings, and your investment thesis",
          "Record what changed instead of reacting to management confidence",
        ],
        preview: null,
      };
    }
    if (window.SECTION_META) {
      window.SECTION_META.calls = { icon: "ti-headphones", title: "Earnings-Call Research" };
      window.SECTION_META.wealth = { icon: "ti-chart-dots-3", title: "Wealth Planner" };
    } else if (typeof SECTION_META !== "undefined") {
      SECTION_META.calls = { icon: "ti-headphones", title: "Earnings-Call Research" };
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
      [data.companyWebsite, "Company site", "ti-building"],
      [data.links?.sec, "SEC filings", "ti-file-text"],
      [data.links?.investorRelationsSearch, "Find investor relations", "ti-search"],
      [data.links?.earnings, "Earnings history", "ti-chart-bar"],
    ].filter(item => item[0]);
    links.innerHTML = items.map(([url, label, icon]) => `<a class="il-research-btn" href="${esc(url)}" target="_blank" rel="noopener noreferrer"><i class="ti ${icon}"></i>${label}</a>`).join("");
  }

  async function loadCallResearch(force) {
    const current = ticker();
    const list = document.getElementById("il-call-list");
    const title = document.getElementById("il-call-title");
    const sub = document.getElementById("il-call-sub");
    if (!list) return;
    loadCallNotes();
    if (!current) {
      list.innerHTML = `<div class="il-call-empty">Search a company in Analyze, then return here to review its calls.</div>`;
      return;
    }
    if (!force && callsLoadedTicker === current && list.dataset.loaded === current) return;
    callsLoadedTicker = current;
    if (title) title.textContent = `${current} recent calls`;
    if (sub) sub.textContent = "Loading transcript availability and official research links.";
    list.innerHTML = `<div class="il-call-empty">Loading ${esc(current)} call research...</div>`;
    try {
      const response = await fetch(`/api/calls/${encodeURIComponent(current)}`, { credentials: "same-origin" });
      if (!response.ok) {
        const body = await response.json().catch(() => ({}));
        throw new Error(body.error || "Call research is unavailable.");
      }
      const data = await response.json();
      renderCallLinks(data);
      if (sub) sub.textContent = data.transcripts?.length ? `${data.transcripts.length} available transcript records from ${data.transcriptProvider}.` : "No transcript records are available from the connected provider. Official research links remain available.";
      list.innerHTML = data.transcripts?.length ? data.transcripts.map(row => {
        const period = row.year && row.quarter ? `Q${row.quarter} ${row.year}` : row.year || "Call";
        const date = dateLabel(row.time);
        return `<div class="il-call-row"><div class="il-call-period">${esc(period)}</div><div class="il-call-title">${esc(row.title)}<span>${esc(date)}</span></div><button class="il-research-btn" data-transcript-id="${esc(row.id)}"><i class="ti ti-file-description"></i>Read</button></div>`;
      }).join("") : `<div class="il-call-empty">No transcript is available through the current provider. Use the official links above, then save what changed in the scorecard.</div>`;
      list.dataset.loaded = current;
      list.querySelectorAll("[data-transcript-id]").forEach(button => button.onclick = () => openCallTranscript(button.dataset.transcriptId));
      trackEvent("call_research_loaded", { ticker: current, transcripts: data.transcripts?.length || 0 });
    } catch (error) {
      list.innerHTML = `<div class="il-call-empty">${esc(error.message)}</div>`;
    }
  }

  async function openCallTranscript(id) {
    const current = ticker();
    const reader = document.getElementById("il-transcript-reader");
    if (!reader || !current || !id) return;
    reader.classList.add("open");
    reader.innerHTML = `<div class="il-call-empty">Loading transcript...</div>`;
    try {
      const response = await fetch(`/api/calls/${encodeURIComponent(current)}/${encodeURIComponent(id)}`, { credentials: "same-origin" });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.error || "Transcript is unavailable.");
      const heading = data.year && data.quarter ? `${current} Q${data.quarter} ${data.year}` : `${current} transcript`;
      reader.innerHTML = `<div class="il-transcript-head"><div><div class="il-research-kicker">Transcript</div><h3>${esc(heading)}</h3></div><button class="il-research-btn" id="il-close-transcript"><i class="ti ti-x"></i>Close</button></div>${data.audio ? `<audio controls preload="none" src="${esc(data.audio)}" style="width:100%;margin-bottom:10px"></audio>` : ""}<div class="il-transcript-copy">${data.transcript?.length ? data.transcript.map(block => `<div class="il-transcript-block"><strong>${esc(block.name)}</strong><p>${esc(block.speech)}</p></div>`).join("") : `<div class="il-call-empty">The provider returned metadata without transcript text.</div>`}</div>`;
      document.getElementById("il-close-transcript").onclick = () => { reader.classList.remove("open"); reader.innerHTML = ""; };
      reader.scrollIntoView({ behavior: "smooth", block: "start" });
      trackEvent("call_transcript_opened", { ticker: current });
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
    const text = `Implied Lens wealth plan: ${money(input.principal)} starting balance + ${money(input.monthlyContribution)}/month for ${input.years} years. Base scenario: ${money(output.base.value)} at ${(input.baseReturn * 100).toFixed(1)}%. Hypothetical, not investment advice.`;
    trackEvent("wealth_plan_shared", { years: input.years });
    if (navigator.share) {
      try { await navigator.share({ title: "Implied Lens Wealth Plan", text, url: "https://impliedlens.com/?view=tool&section=wealth" }); return; } catch (_) {}
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
