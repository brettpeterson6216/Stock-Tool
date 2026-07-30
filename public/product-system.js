(function () {
  "use strict";

  const KEYS = {
    onboarding: "il-onboarding-dismissed",
    workshop: "il-learn-thesis-workshop-v1",
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
    ctx.fillStyle = document.documentElement.dataset.theme === "dark" ? "#12100D" : "#fcfbf8";
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
    const interval = String(p.interval || "").toLowerCase();
    let freshness = "Latest observation";
    if (Number.isFinite(age)) {
      const mins = Math.round(age / 60);
      const days = Math.floor(age / 86400);
      if (interval === "1d" && age < 4 * 86400) freshness = "Latest daily bar";
      else if (interval === "1wk" && age < 14 * 86400) freshness = "Latest weekly bar";
      else if (interval === "1mo" && age < 45 * 86400) freshness = "Latest monthly bar";
      else freshness = days >= 1 ? `${days}d since latest observation` : mins >= 1 ? `${mins}m since latest observation` : "Latest observation under 1m old";
    }
    if (p.delayed && !Number.isFinite(age)) freshness = "Provider timing varies";
    if (p.delayStatus === "provider-dependent" && !Number.isFinite(age)) freshness = "Provider timing varies";
    return {
      source: p.source || "Aggregated market data",
      freshness,
      warn: Boolean(p.delayed || p.fallback),
    };
  }
  function escapeHtml(value) {
    return String(value ?? "").replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[char]));
  }
  function trustDateLabel(value, fallback) {
    if (!value) return fallback;
    const date = typeof value === "number" ? new Date(value * 1000) : new Date(value);
    if (Number.isNaN(date.getTime())) return fallback;
    return date.toLocaleString([], { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" });
  }
  function trustField(label, value) {
    return `<div class="il-trust-field"><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong></div>`;
  }
  function fmtMoney(value) {
    const number = Number(value);
    if (!Number.isFinite(number)) return "Unavailable";
    if (Math.abs(number) >= 1e12) return `$${(number / 1e12).toFixed(2)}T`;
    if (Math.abs(number) >= 1e9) return `$${(number / 1e9).toFixed(2)}B`;
    if (Math.abs(number) >= 1e6) return `$${(number / 1e6).toFixed(1)}M`;
    return `$${number.toFixed(number >= 100 ? 0 : 2)}`;
  }
  function fmtNum(value, suffix = "") {
    const number = Number(value);
    return Number.isFinite(number) ? `${number.toFixed(Math.abs(number) >= 100 ? 0 : 2)}${suffix}` : "Unavailable";
  }
  function currentTickerContext() {
    const result = window.IL_STATE?.data;
    const meta = result?.meta || {};
    const price = meta.regularMarketPrice ?? meta.chartPreviousClose;
    // Yahoo's chartPreviousClose can represent the first comparison point for
    // the requested range. Prefer the true prior session close for "current move".
    const prev = meta.previousClose ?? window.IL_STATE?.previousClose ?? meta.chartPreviousClose;
    const change = Number.isFinite(Number(price)) && Number.isFinite(Number(prev)) ? Number(price) - Number(prev) : null;
    const changePct = change !== null && prev ? change / Number(prev) * 100 : null;
    const p = provenanceLabel(result?.impliedLensProvenance);
    return {
      ticker: window.IL_STATE?.ticker || "",
      name: meta.longName || meta.shortName || "",
      exchange: meta.fullExchangeName || meta.exchangeName || meta.exchange || "",
      price,
      change,
      changePct,
      marketCap: meta.marketCap,
      pe: meta.trailingPE || meta.forwardPE,
      eps: meta.epsTrailingTwelveMonths || meta.trailingEps || (Number(price) && Number(meta.trailingPE) ? Number(price) / Number(meta.trailingPE) : null),
      source: p.source,
      freshness: p.freshness,
      warn: p.warn,
      provenance: result?.impliedLensProvenance || null,
    };
  }
  function notesKey() {
    return `il-notes-${(window.IL_STATE?.ticker || "workspace").toUpperCase()}`;
  }
  function readNote() {
    try { return JSON.parse(localStorage.getItem(notesKey()) || "{}"); } catch (_) { return {}; }
  }
  function writeNote(note) {
    try { localStorage.setItem(notesKey(), JSON.stringify(note)); } catch (_) {}
  }
  function sourceRows() {
    const ctx = currentTickerContext();
    const p = ctx.provenance || {};
    return [
      ["Price source", ctx.source || "Aggregated market data"],
      ["Data freshness", ctx.freshness || "Provider timing varies"],
      ["Latest bar", trustDateLabel(p.latestTimestamp, "Unavailable")],
      ["Retrieved", trustDateLabel(p.retrievedAt, "This session")],
      ["Range", p.range ? String(p.range).toUpperCase() : "Current chart range"],
      ["Interval", p.interval || "Provider default"],
      ["Limitation", p.delayed ? "Delayed or end-of-day provider context." : "Latest available provider context."],
    ];
  }
  function openResearchDrawer(kind) {
    const drawer = document.getElementById("il-research-drawer");
    if (!drawer) return;
    const title = drawer.querySelector("#il-drawer-title");
    const body = drawer.querySelector("#il-drawer-body");
    if (kind === "sources") {
      title.textContent = "Sources and Freshness";
      body.innerHTML = `<div class="il-drawer-grid">${sourceRows().map(([label, value]) => `<div><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong></div>`).join("")}</div><p>Provider coverage can differ by symbol, exchange, range, and account state. Missing data is shown as unavailable instead of estimated.</p><a href="/data-sources">Open full methodology</a>`;
    } else if (kind === "projection-help") {
      title.textContent = "Projection Help";
      body.innerHTML = `<p>Projection is an assumption model, not a prediction. Observed data anchors the starting point; user assumptions drive the range.</p><ul><li><strong>EPS growth</strong> compounds starting earnings.</li><li><strong>Exit P/E</strong> is the terminal market multiple.</li><li><strong>Dilution/buyback</strong> adjusts per-share economics.</li><li><strong>Probabilities</strong> must total 100%.</li></ul>`;
    } else {
      title.textContent = "Analyze Help";
      body.innerHTML = `<p>Analyze is the command center for a ticker. Start with the snapshot, then move through price action, fundamentals, valuation, filings, projection, and thesis notes.</p><ul><li>Use sources to check freshness.</li><li>Use Projection only after reviewing assumptions.</li><li>Save a thesis when your view changes.</li></ul>`;
    }
    drawer.classList.add("open");
    drawer.querySelector(".il-drawer-close")?.focus();
  }
  function closeResearchDrawer() {
    document.getElementById("il-research-drawer")?.classList.remove("open");
  }
  function openNotesPanel() {
    const panel = document.getElementById("il-notes-panel");
    if (!panel) return;
    const note = readNote();
    panel.querySelector("#il-note-bull").value = note.bull || "";
    panel.querySelector("#il-note-bear").value = note.bear || "";
    panel.querySelector("#il-note-risk").value = note.risk || "";
    panel.querySelector("#il-note-watch").value = note.watch || "";
    panel.querySelector("#il-note-review").value = note.review || "";
    panel.classList.add("open");
    panel.querySelector("textarea")?.focus();
  }
  function saveNotesPanel() {
    writeNote({
      bull: document.getElementById("il-note-bull")?.value || "",
      bear: document.getElementById("il-note-bear")?.value || "",
      risk: document.getElementById("il-note-risk")?.value || "",
      watch: document.getElementById("il-note-watch")?.value || "",
      review: document.getElementById("il-note-review")?.value || "",
      updatedAt: new Date().toISOString(),
    });
    const status = document.getElementById("il-note-status");
    if (status) status.textContent = "Notes saved for this ticker.";
    if (typeof window.toast === "function") window.toast("Ticker notes saved", "ok");
  }
  function updateShellContext() {
    const ctx = currentTickerContext();
    document.querySelectorAll("[data-il-current-ticker]").forEach(el => { el.textContent = ctx.ticker || "No ticker selected"; });
    document.querySelectorAll("[data-il-current-name]").forEach(el => { el.textContent = ctx.name || "Load a company to start."; });
    document.querySelectorAll("[data-il-current-exchange]").forEach(el => { el.textContent = ctx.exchange || "Exchange unavailable"; });
    document.querySelectorAll("[data-il-current-price]").forEach(el => { el.textContent = fmtMoney(ctx.price); });
    document.querySelectorAll("[data-il-current-move]").forEach(el => {
      el.textContent = ctx.change === null ? "Move unavailable" : `${ctx.change >= 0 ? "+" : ""}${fmtNum(ctx.change)} (${ctx.changePct >= 0 ? "+" : ""}${fmtNum(ctx.changePct, "%")})`;
      el.classList.toggle("up", Number(ctx.change) >= 0);
      el.classList.toggle("dn", Number(ctx.change) < 0);
    });
    document.querySelectorAll("[data-il-current-cap]").forEach(el => { el.textContent = fmtMoney(ctx.marketCap); });
    document.querySelectorAll("[data-il-current-pe]").forEach(el => { el.textContent = fmtNum(ctx.pe, "x"); });
    document.querySelectorAll("[data-il-current-eps]").forEach(el => { el.textContent = fmtMoney(ctx.eps); });
    document.querySelectorAll("[data-il-current-freshness]").forEach(el => { el.textContent = ctx.freshness || "Provider timing varies"; });
    document.querySelectorAll("[data-il-current-source]").forEach(el => { el.textContent = ctx.source || "Source pending"; });
    document.querySelectorAll(".il-shell-status").forEach(el => {
      el.textContent = ctx.ticker ? (ctx.warn ? "Delayed" : "Latest") : "No ticker";
      el.classList.toggle("warn", Boolean(ctx.warn));
    });
    document.querySelectorAll(".il-needs-ticker").forEach(el => el.classList.toggle("has-ticker", Boolean(ctx.ticker)));
  }
  function shellHtml(kind) {
    const isProjection = kind === "projection";
    return `<div class="il-tool-shell" data-il-shell="${kind}">
      <div class="il-shell-top">
        <div><span>${isProjection ? "Projection" : "Analyze"}</span><strong>${isProjection ? "Projection builder" : "Ticker workspace"}</strong></div>
        <div class="il-shell-search"><input type="text" aria-label="Search ticker or company" placeholder="Search ticker or company"><button type="button">Analyze</button></div>
        <div class="il-shell-actions">
          <button type="button" data-il-drawer="${isProjection ? "projection-help" : "analyze-help"}" aria-label="Open help"><i class="ti ti-help-circle"></i><span>Help</span></button>
          <button type="button" data-il-drawer="sources" aria-label="Open sources"><i class="ti ti-database"></i><span>Sources</span></button>
          <button type="button" data-il-notes aria-label="Open notes"><i class="ti ti-notes"></i><span>Notes</span></button>
          <button type="button" data-il-save aria-label="Save"><i class="ti ti-bookmark"></i><span>Save</span></button>
        </div>
      </div>
      <div class="il-shell-ticker">
        <div><span data-il-current-ticker>No ticker selected</span><strong data-il-current-name>Load a company to start.</strong><em data-il-current-exchange>Exchange unavailable</em></div>
        <div><span>Price</span><strong data-il-current-price>Unavailable</strong><em data-il-current-move>Move unavailable</em></div>
        <div><span>Market cap</span><strong data-il-current-cap>Unavailable</strong><em>Observed</em></div>
        <div><span>P/E</span><strong data-il-current-pe>Unavailable</strong><em>Observed when available</em></div>
        <div><span>EPS TTM</span><strong data-il-current-eps>Unavailable</strong><em>Observed or derived</em></div>
        <button type="button" class="il-shell-status">No ticker</button>
      </div>
      <div class="il-shell-preview il-needs-ticker">
        <div><i class="ti ${isProjection ? "ti-adjustments-horizontal" : "ti-search"}"></i><strong>${isProjection ? "Load a ticker first" : "Search a ticker"}</strong><span>${isProjection ? "Then review assumptions and calculate." : "Then use only the controls this tool needs."}</span></div>
      </div>
    </div>`;
  }
  function installResearchDrawerAndNotes() {
    if (!document.getElementById("il-research-drawer")) {
      const drawer = document.createElement("div");
      drawer.id = "il-research-drawer";
      drawer.className = "il-research-drawer";
      drawer.setAttribute("role", "dialog");
      drawer.setAttribute("aria-modal", "true");
      drawer.innerHTML = `<div class="il-drawer-card"><div class="il-drawer-head"><h2 id="il-drawer-title">Sources</h2><button type="button" class="il-drawer-close" aria-label="Close drawer"><i class="ti ti-x"></i></button></div><div id="il-drawer-body"></div></div>`;
      document.body.appendChild(drawer);
      drawer.querySelector(".il-drawer-close").onclick = closeResearchDrawer;
      drawer.onclick = event => { if (event.target === drawer) closeResearchDrawer(); };
    }
    if (!document.getElementById("il-notes-panel")) {
      const panel = document.createElement("div");
      panel.id = "il-notes-panel";
      panel.className = "il-notes-panel";
      panel.innerHTML = `<div class="il-notes-card"><div class="il-drawer-head"><h2>Ticker Notes</h2><button type="button" aria-label="Close notes" onclick="document.getElementById('il-notes-panel').classList.remove('open')"><i class="ti ti-x"></i></button></div><label>Bull case<textarea id="il-note-bull"></textarea></label><label>Bear case<textarea id="il-note-bear"></textarea></label><label>Key risk<textarea id="il-note-risk"></textarea></label><div class="il-notes-two"><label>Watch level<input id="il-note-watch" type="text"></label><label>Review date<input id="il-note-review" type="date"></label></div><div class="il-notes-actions"><button type="button" id="il-note-save">Save Notes</button><span id="il-note-status"></span></div></div>`;
      document.body.appendChild(panel);
      panel.querySelector("#il-note-save").onclick = saveNotesPanel;
    }
  }
  function installToolShells() {
    installResearchDrawerAndNotes();
    const analyze = document.getElementById("body-analyze");
    if (analyze && !document.querySelector('[data-il-shell="analyze"]')) analyze.insertAdjacentHTML("afterbegin", shellHtml("analyze"));
    const projection = document.getElementById("body-projection");
    // Projection section now hosts the Projection Lab; skip the legacy research shell.
    if (projection && !document.getElementById("il-projlab-mount") && !document.querySelector('[data-il-shell="projection"]')) projection.insertAdjacentHTML("afterbegin", shellHtml("projection"));
    document.querySelectorAll(".il-shell-search").forEach(search => {
      const input = search.querySelector("input");
      const button = search.querySelector("button");
      const run = () => {
        const symbol = input.value.trim().toUpperCase();
        if (!symbol) return;
        const main = document.getElementById("main-ticker");
        if (main) {
          main.value = symbol;
          main.dispatchEvent(new Event("input", { bubbles: true }));
        }
        // Make sure the analyze section is open before loading.
        if (typeof window.openSection === "function") window.openSection("analyze");
        if (typeof window.fetchAndRender === "function") {
          window.fetchAndRender();
        } else if (typeof window.quickLoad === "function") {
          window.quickLoad(symbol);
        }
      };
      button.onclick = run;
      input.onkeydown = event => { if (event.key === "Enter") run(); };
    });
    document.querySelectorAll("[data-il-drawer]").forEach(button => button.onclick = () => openResearchDrawer(button.dataset.ilDrawer));
    document.querySelectorAll("[data-il-notes]").forEach(button => button.onclick = openNotesPanel);
    document.querySelectorAll("[data-il-save]").forEach(button => button.onclick = () => window.saveAnalysis?.(window.IL_STATE?.ticker ? "price" : "note"));
    updateShellContext();
  }
  function syncToolUrl(section, mode) {
    try {
      const url = new URL(window.location.href);
      if (section && section !== "home") {
        url.searchParams.set("view", "tool");
        url.searchParams.set("section", section);
      }
      const ticker = window.IL_STATE?.ticker || document.getElementById("main-ticker")?.value?.trim()?.toUpperCase();
      if (ticker) url.searchParams.set("symbol", ticker);
      else url.searchParams.delete("symbol");
      if (mode) url.searchParams.set("mode", mode);
      const next = `${url.pathname}${url.search}${url.hash}`;
      const current = `${window.location.pathname}${window.location.search}${window.location.hash}`;
      if (next !== current) window.history.replaceState({}, "", next);
    } catch (_) {}
  }
  function installUrlState() {
    if (window.__ilUrlStateInstalled) return;
    window.__ilUrlStateInstalled = true;
    if (typeof window.navGoTo === "function") {
      const original = window.navGoTo;
      window.navGoTo = function (section, attempt) {
        const output = original.call(this, section, attempt);
        if (!attempt && section !== "home") syncToolUrl(section);
        return output;
      };
    }
    const params = new URLSearchParams(window.location.search);
    const symbol = params.get("symbol");
    if (symbol && !window.IL_STATE?.ticker) {
      const input = document.getElementById("main-ticker");
      if (input) input.value = symbol.toUpperCase();
    }
  }
  function renderTrust(result) {
    const host = document.getElementById("r-time");
    if (!host) return;
    const provenance = result?.impliedLensProvenance || null;
    const p = provenanceLabel(provenance);
    const range = provenance?.range ? String(provenance.range).toUpperCase() : "Current range";
    const interval = provenance?.interval || "Provider default";
    const latest = trustDateLabel(provenance?.latestTimestamp, "Latest observation unavailable");
    const retrieved = trustDateLabel(provenance?.retrievedAt, "Retrieved in this session");
    host.textContent = `Provider observation · ${latest}`;
    let row = document.getElementById("il-trust-row");
    if (!row) {
      row = document.createElement("div");
      row.id = "il-trust-row";
      row.className = "il-trust-row";
      host.parentElement.appendChild(row);
    }
    row.innerHTML = `<span class="il-trust-chip"><i class="ti ti-database"></i>${escapeHtml(p.source)}</span><span class="il-trust-chip ${p.warn ? "warn" : ""}"><i class="ti ti-clock"></i>${escapeHtml(p.freshness)}</span><a class="il-trust-chip" href="/data-sources"><i class="ti ti-external-link"></i>Methodology</a>`;
    let panel = document.getElementById("il-trust-panel");
    if (!panel) {
      panel = document.createElement("div");
      panel.id = "il-trust-panel";
      panel.className = "il-trust-panel";
      const header = document.querySelector("#stock-result .result-header");
      header?.insertAdjacentElement("afterend", panel);
    }
    if (panel) {
      panel.innerHTML = `<div class="il-trust-panel-head"><span><i class="ti ti-shield-check"></i>Evidence quality</span><a href="/data-sources">Data methodology</a></div><div class="il-trust-grid">${trustField("Source", p.source)}${trustField("Freshness", p.freshness)}${trustField("Latest bar", latest)}${trustField("Retrieved", retrieved)}${trustField("Range", range)}${trustField("Interval", interval)}</div><div class="il-trust-note">Use this as latest available context, not a real-time trading signal. Review the source, range, and interval before saving a thesis.</div>`;
    }
  }

  function installQuoteTrust() {
    if (typeof window.renderStock === "function") {
      const originalRender = window.renderStock;
      window.renderStock = function (result, ticker) {
        const output = originalRender(result, ticker);
        renderTrust(result);
        updateShellContext();
        syncToolUrl(window.IL_STATE?.section || new URLSearchParams(window.location.search).get("section") || "analyze");
        renderProjectionWorkspace();
        installResearchTrail();
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
    guide.innerHTML = `<div class="il-guidance-copy"><strong>Build a complete ${ticker} decision, not just a price opinion.</strong><span>Start with the chart, then write down the operating evidence and failure conditions behind your view.</span></div><div class="il-guidance-actions"><button onclick="navGoTo('education');setTimeout(()=>openLesson(document.querySelector('[data-lesson=thesis]')),50)">Learn to write a thesis</button><button onclick="shareTickerResearch('${ticker}')"><i class="ti ti-share-3"></i> Share research</button><button class="primary" onclick="saveAnalysis('price')">Save snapshot</button></div>`;
  }

  async function shareTickerResearch(ticker) {
    const symbol = String(ticker || window.IL_STATE?.ticker || "").toUpperCase().replace(/[^A-Z0-9.^-]/g, "").slice(0, 15);
    if (!symbol) return;
    const url = `https://impliedlens.com/stock/${encodeURIComponent(symbol)}`;
    const text = `Research ${symbol} with source-aware market context, valuation tools, and a reviewable decision process on Implied Lens.`;
    if (typeof window.track === "function") window.track("research_shared", { ticker: symbol });
    if (navigator.share) {
      try { await navigator.share({ title: `${symbol} research | Implied Lens`, text, url }); return; } catch (_) {}
    }
    try {
      await navigator.clipboard.writeText(url);
      if (typeof window.toast === "function") window.toast(`${symbol} research link copied`, "ok");
    } catch (_) {
      window.open(`https://twitter.com/intent/tweet?text=${encodeURIComponent(text)}&url=${encodeURIComponent(url)}`, "_blank", "noopener,noreferrer");
    }
  }

  function decorateMetricLearning() {
    document.querySelectorAll("#metrics-grid .m-lbl").forEach((label) => {
      if (label.querySelector(".il-metric-learn")) return;
      const button = document.createElement("button");
      button.className = "il-metric-learn";
      button.title = "Learn how to use this metric";
      button.setAttribute("aria-label", "Learn how to use this metric");
      button.innerHTML = '<i class="ti ti-school" aria-hidden="true"></i>';
      button.onclick = () => {
        navGoTo("education");
        setTimeout(() => openLesson(document.querySelector("[data-lesson=thesis]")), 50);
      };
      label.appendChild(button);
    });
  }

  const DECISION_PATH = [
    { key: "search", icon: "ti-search", label: "Search", detail: "Load the company context.", section: "analyze" },
    { key: "evidence", icon: "ti-file-search", label: "Evidence", detail: "Read filings, calls, and metrics.", section: "financials" },
    { key: "model", icon: "ti-calculator", label: "Model", detail: "Test assumptions and valuation ranges.", section: "projection" },
    { key: "thesis", icon: "ti-pencil", label: "Thesis", detail: "Write what would prove you wrong.", section: "education" },
    { key: "review", icon: "ti-calendar-check", label: "Review", detail: "Save the decision and revisit it.", section: "workspace" },
  ];

  function decisionPathHtml(compact = false) {
    return `<div class="il-decision-path ${compact ? "compact" : ""}" aria-label="Implied Lens decision workflow">
      ${DECISION_PATH.map((step, index) => `<button type="button" class="il-decision-step" data-il-spine="${step.section}">
        <span class="il-decision-num">${String(index + 1).padStart(2, "0")}</span>
        <i class="ti ${step.icon}" aria-hidden="true"></i>
        <strong>${step.label}</strong>
        <em>${step.detail}</em>
      </button>`).join("")}
    </div>`;
  }

  function bindDecisionPath(host) {
    host.querySelectorAll("[data-il-spine]").forEach(button => {
      button.onclick = () => {
        const section = button.dataset.ilSpine;
        if (typeof window.track === "function") window.track("decision_spine_clicked", { section });
        if (typeof window.navGoTo === "function") window.navGoTo(section);
      };
    });
  }

  function installDecisionSpine() {
    const heroSearch = document.querySelector(".home-hero .hh-search");
    if (heroSearch && !document.getElementById("il-home-decision-path")) {
      const wrap = document.createElement("div");
      wrap.id = "il-home-decision-path";
      wrap.innerHTML = decisionPathHtml(true);
      heroSearch.insertAdjacentElement("afterend", wrap);
      bindDecisionPath(wrap);
    }
    const welcome = document.getElementById("tool-welcome");
    if (welcome && !document.getElementById("il-tool-decision-path")) {
      const wrap = document.createElement("div");
      wrap.id = "il-tool-decision-path";
      wrap.className = "il-tool-decision-wrap";
      wrap.innerHTML = `<div class="il-tool-decision-head"><span>Decision path</span><strong>Turn a ticker into a reviewable investment record.</strong></div>${decisionPathHtml(false)}`;
      welcome.insertBefore(wrap, welcome.firstChild);
      bindDecisionPath(wrap);
    }
  }

  const learnDefaults = { step: 0, ticker: "", company: "", price: null, quiz: "", quizCorrect: false, driver: "", variant: "", evidence: "", failure: "", reviewDate: "", completed: false };
  let learnState = { ...learnDefaults, ...read(KEYS.workshop, {}) };
  const safe = value => String(value ?? "").replace(/[&<>"']/g, char => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[char]));
  const learnSteps = ["Choose company", "Test the idea", "Business driver", "Market disagreement", "Evidence and risk", "Review and save"];

  function saveLearnState() { write(KEYS.workshop, learnState); }
  function learnFieldReady(field) { return String(learnState[field] || "").trim().length >= 12; }
  function updateLearnProgress() {
    const thesisCard = document.querySelector('.edu-path[data-lesson="thesis"]');
    if (thesisCard) thesisCard.classList.toggle("done", learnState.completed);
    if (typeof window.updateEduProgress === "function") window.updateEduProgress();
  }
  function learnCompanyCard() {
    if (!learnState.ticker) return "";
    const price = Number.isFinite(Number(learnState.price)) ? `$${Number(learnState.price).toFixed(2)}` : "Example company";
    return `<div class="il-learn-company"><div><span>Workshop company</span><strong>${safe(learnState.ticker)} · ${safe(learnState.company || learnState.ticker)}</strong></div><em>${price}</em><button type="button" data-learn-change>Change</button></div>`;
  }
  function learnNav(canContinue = true, final = false) {
    return `<div class="il-learn-nav">${learnState.step > 0 ? `<button type="button" data-learn-back>Back</button>` : `<button type="button" data-learn-reset>Reset</button>`}<span>${learnSteps[learnState.step]}</span>${final ? `<button type="button" class="primary" data-learn-save>Save thesis and complete</button>` : `<button type="button" class="primary" data-learn-next ${canContinue ? "" : "disabled"}>Continue</button>`}</div>`;
  }
  function renderLearnWorkshop() {
    const host = document.getElementById("edu-workshop");
    if (!host) return;
    updateLearnProgress();
    if (learnState.completed) {
      host.innerHTML = `<div class="il-learn-complete"><i class="ti ti-rosette-discount-check"></i><div><span>Module complete</span><h3>Your ${safe(learnState.ticker)} thesis is saved.</h3><p>You created a reviewable argument with an operating driver, variant view, supporting evidence, failure condition, and review date.</p></div><button type="button" data-learn-reset>Build another thesis</button></div>${renderLearnPreview()}`;
      bindLearnWorkshop();
      return;
    }
    let body = "";
    if (learnState.step === 0) {
      const current = window.IL_STATE?.ticker;
      body = `<div class="il-learn-intro"><div class="il-learn-kicker">Step 1 · Choose a company</div><h3>Start here without leaving Learn.</h3><p>Use the guided Apple example, continue with a company already loaded, or enter any supported ticker.</p><div class="il-learn-examples"><button type="button" data-learn-example="AAPL"><i class="ti ti-brand-apple"></i><strong>Use Apple example</strong><span>No search required</span></button>${current ? `<button type="button" data-learn-current="${safe(current)}"><i class="ti ti-history"></i><strong>Use ${safe(current)}</strong><span>Currently loaded</span></button>` : ""}</div><form class="il-learn-search" id="il-learn-search"><label for="il-learn-ticker">Or enter a ticker</label><div><input id="il-learn-ticker" maxlength="15" placeholder="MSFT, NVDA, JPM…" autocomplete="off" spellcheck="false"><button type="submit">Use ticker</button></div><small id="il-learn-search-status">The company loads here. You stay inside the module.</small></form></div>`;
    } else if (learnState.step === 1) {
      const options = [
        ["opinion", "The stock should rise because the company has a strong brand."],
        ["testable", "Services mix should lift margin within four quarters; the thesis fails if mix and margin stall."],
        ["rating", "Most analysts rate the stock a buy, so it is a good investment."],
      ];
      body = `${learnCompanyCard()}<div class="il-learn-kicker">Step 2 · Quick knowledge check</div><h3>Which statement is a falsifiable thesis?</h3><p class="il-learn-copy">Choose the statement that contains operating evidence, a time frame, and a condition that could prove it wrong.</p><div class="il-learn-quiz">${options.map(([id, text]) => `<button type="button" data-learn-quiz="${id}" class="${learnState.quiz === id ? "selected" : ""}">${safe(text)}</button>`).join("")}</div>${learnState.quiz ? `<div class="il-learn-feedback ${learnState.quizCorrect ? "correct" : "wrong"}"><i class="ti ${learnState.quizCorrect ? "ti-check" : "ti-x"}"></i>${learnState.quizCorrect ? "Correct. A useful thesis can be tested against future evidence." : "Not quite. Look for a measurable operating claim and a failure condition."}</div>` : ""}${learnNav(learnState.quizCorrect)}`;
    } else if (learnState.step === 2) {
      body = `${learnCompanyCard()}<div class="il-learn-kicker">Step 3 · Business driver</div><h3>What operating engine matters most?</h3><p class="il-learn-copy">Name the driver behind revenue, margins, cash flow, or per-share value—not the stock price.</p>${learnTextarea("driver", "Business driver", "Example: recurring services revenue grows faster than hardware revenue.", "Focus on something the company reports or that you can verify.")}${learnNav(learnFieldReady("driver"))}`;
    } else if (learnState.step === 3) {
      body = `${learnCompanyCard()}<div class="il-learn-kicker">Step 4 · Variant view</div><h3>What might the market be missing?</h3><p class="il-learn-copy">Explain how your expectation differs from what appears priced in. Avoid “the stock is cheap” unless you state why expectations are wrong.</p>${learnTextarea("variant", "Your market disagreement", "Example: investors underestimate how quickly the higher-margin business will become a larger share of sales.", "State the disagreement in one or two direct sentences.")}${learnNav(learnFieldReady("variant"))}`;
    } else if (learnState.step === 4) {
      body = `${learnCompanyCard()}<div class="il-learn-kicker">Step 5 · Evidence and failure</div><h3>Decide what would strengthen—or break—the thesis.</h3><div class="il-learn-two">${learnTextarea("evidence", "Supporting evidence", "Example: services growth remains above 12% and gross margin expands for two consecutive quarters.", "Use measurable evidence.")}${learnTextarea("failure", "Failure condition", "Example: services growth falls below 8% while gross margin contracts for two quarters.", "Do not move this line just because the price falls.")}</div><label class="il-learn-date"><span>Review date</span><input type="date" data-learn-field="reviewDate" value="${safe(learnState.reviewDate)}"><small>Choose when you will compare the thesis with new evidence.</small></label>${learnNav(learnFieldReady("evidence") && learnFieldReady("failure") && Boolean(learnState.reviewDate))}`;
    } else {
      body = `${learnCompanyCard()}<div class="il-learn-kicker">Step 6 · Review</div><h3>Read the argument as one decision.</h3><p class="il-learn-copy">If any part sounds vague, go back and make it measurable before saving.</p>${renderLearnPreview()}${learnNav(true, true)}`;
    }
    host.innerHTML = `<div class="il-learn-stepper">${learnSteps.map((name, index) => `<span class="${index < learnState.step ? "done" : index === learnState.step ? "active" : ""}"><i>${index < learnState.step ? "✓" : index + 1}</i>${name}</span>`).join("")}</div><div class="il-learn-card">${body}</div>`;
    bindLearnWorkshop();
  }
  function learnTextarea(field, label, placeholder, hint) {
    return `<label class="il-learn-field"><span>${label}</span><textarea data-learn-field="${field}" placeholder="${safe(placeholder)}">${safe(learnState[field])}</textarea><small>${hint} <b>${String(learnState[field] || "").trim().length} characters</b></small></label>`;
  }
  function renderLearnPreview() {
    return `<article class="il-learn-preview"><header><div><span>Investment thesis</span><h3>${safe(learnState.ticker)} · ${safe(learnState.company)}</h3></div><em>Review ${safe(learnState.reviewDate)}</em></header><div><span>Operating driver</span><p>${safe(learnState.driver)}</p></div><div><span>Variant view</span><p>${safe(learnState.variant)}</p></div><div><span>Evidence to watch</span><p>${safe(learnState.evidence)}</p></div><div class="risk"><span>Invalidated when</span><p>${safe(learnState.failure)}</p></div></article>`;
  }
  async function chooseLearnTicker(ticker, example = false) {
    const symbol = String(ticker || "").trim().toUpperCase().replace(/[^A-Z0-9.^-]/g, "").slice(0, 15);
    const status = document.getElementById("il-learn-search-status");
    if (!symbol) return;
    if (status) status.textContent = example ? "Opening the guided example…" : `Finding ${symbol}…`;
    try {
      let company = symbol, price = null;
      if (example) {
        company = "Apple Inc.";
      } else {
        if (typeof window.yahooFetch !== "function") throw new Error("Search is temporarily unavailable.");
        const result = await window.yahooFetch(symbol, "1y");
        const meta = result?.meta || {};
        company = meta.longName || meta.shortName || symbol;
        price = meta.regularMarketPrice ?? meta.chartPreviousClose ?? null;
        window.IL_STATE.ticker = symbol;
        window.IL_STATE.data = result;
      }
      learnState = { ...learnDefaults, ticker: symbol, company, price, step: 1 };
      saveLearnState();
      renderLearnWorkshop();
      if (typeof window.track === "function") window.track("learn_company_selected", { ticker: symbol, example });
    } catch (error) {
      if (status) status.textContent = error.message === "TICKER_NOT_FOUND" ? `Could not find "${symbol}". Check the ticker and try again.` : "We could not load that company right now. Try again in a moment.";
    }
  }
  async function saveLearnThesis() {
    const button = document.querySelector("[data-learn-save]");
    if (button) { button.disabled = true; button.textContent = "Saving…"; }
    const core = `${learnState.variant} Driver: ${learnState.driver}`;
    const body = { status: "watching", thesis: core, catalysts: [learnState.evidence], risks: [learnState.failure], sell_conditions: [learnState.failure], review_date: learnState.reviewDate, conviction: 3 };
    try {
      if (window.IL_STATE?.loggedIn) {
        const response = await fetch(`/api/workspace/theses/${encodeURIComponent(learnState.ticker)}`, { method: "PUT", credentials: "same-origin", headers: { "Content-Type": "application/json", "X-CSRF-Token": window.IL_STATE.csrfToken || "" }, body: JSON.stringify(body) });
        if (!response.ok) throw new Error((await response.json().catch(() => ({}))).error || "Could not save thesis.");
      } else {
        const workspace = read("il-workspace-v1", { theses: [], positions: [], watchlist: [] });
        const item = { ...body, ticker: learnState.ticker, updated_at: new Date().toISOString(), created_at: new Date().toISOString() };
        workspace.theses = [item, ...(workspace.theses || []).filter(row => row.ticker !== learnState.ticker)];
        write("il-workspace-v1", workspace);
      }
      learnState.completed = true;
      saveLearnState();
      const completed = new Set(read("il-edu-complete", [])); completed.add("thesis"); write("il-edu-complete", [...completed]);
      renderLearnWorkshop();
      if (typeof window.track === "function") window.track("learn_module_completed", { ticker: learnState.ticker, synced: Boolean(window.IL_STATE?.loggedIn) });
      if (typeof window.toast === "function") window.toast(`${learnState.ticker} thesis saved`, "ok");
    } catch (error) {
      if (typeof window.toast === "function") window.toast(error.message || "Could not save thesis", "err");
      if (button) { button.disabled = false; button.textContent = "Save thesis and complete"; }
    }
  }
  function bindLearnWorkshop() {
    const host = document.getElementById("edu-workshop");
    if (!host) return;
    host.querySelector("#il-learn-search")?.addEventListener("submit", event => { event.preventDefault(); chooseLearnTicker(document.getElementById("il-learn-ticker")?.value); });
    host.querySelectorAll("[data-learn-example]").forEach(button => button.onclick = () => chooseLearnTicker(button.dataset.learnExample, true));
    host.querySelectorAll("[data-learn-current]").forEach(button => button.onclick = () => chooseLearnTicker(button.dataset.learnCurrent));
    host.querySelectorAll("[data-learn-quiz]").forEach(button => button.onclick = () => { learnState.quiz = button.dataset.learnQuiz; learnState.quizCorrect = learnState.quiz === "testable"; saveLearnState(); renderLearnWorkshop(); });
    host.querySelectorAll("[data-learn-field]").forEach(field => field.addEventListener("input", () => {
      learnState[field.dataset.learnField] = field.value;
      saveLearnState();
      const count = field.closest(".il-learn-field")?.querySelector("small b");
      if (count) count.textContent = `${field.value.trim().length} characters`;
      const next = host.querySelector("[data-learn-next]");
      if (next) {
        const ready = learnState.step === 2 ? learnFieldReady("driver") : learnState.step === 3 ? learnFieldReady("variant") : learnState.step === 4 ? learnFieldReady("evidence") && learnFieldReady("failure") && Boolean(learnState.reviewDate) : true;
        next.disabled = !ready;
      }
    }));
    host.querySelector("[data-learn-next]")?.addEventListener("click", () => { learnState.step = Math.min(5, learnState.step + 1); saveLearnState(); renderLearnWorkshop(); host.scrollIntoView({ behavior: "smooth", block: "start" }); });
    host.querySelector("[data-learn-back]")?.addEventListener("click", () => { learnState.step = Math.max(0, learnState.step - 1); saveLearnState(); renderLearnWorkshop(); });
    host.querySelector("[data-learn-change]")?.addEventListener("click", () => { learnState.step = 0; saveLearnState(); renderLearnWorkshop(); });
    host.querySelectorAll("[data-learn-reset]").forEach(button => button.onclick = () => { learnState = { ...learnDefaults }; saveLearnState(); renderLearnWorkshop(); });
    host.querySelector("[data-learn-save]")?.addEventListener("click", saveLearnThesis);
  }
  function installEducationContext() {
    window.openLearnWorkshop = () => { const host = document.getElementById("edu-workshop"); renderLearnWorkshop(); host?.scrollIntoView({ behavior: "smooth", block: "start" }); };
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

  function installToolGuidance() {
    const guides = {
      financials: ["Read the trend before the latest number.", "Advanced check: reconcile earnings with cash flow, debt, and diluted shares."],
      advmetrics: ["Start with margins, returns on capital, and leverage.", "Advanced check: compare the company with its own history and a relevant peer group."],
      earnings: ["Look for the direction and consistency of estimate surprises.", "Advanced check: separate one-time beats from durable estimate revisions."],
      secfilings: ["10-K is annual, 10-Q is quarterly, and 8-K reports material events.", "Advanced check: inspect risk factors, share count, segment results, and footnotes."],
      institutional: ["Use ownership and FINRA OTC activity as context, not a trading signal.", "Advanced check: compare changes across reporting periods and verify the filing date."],
      compare: ["Choose companies with similar business models before comparing ratios.", "Advanced check: treat the radar as relative ranking, then verify the underlying figures."],
      reports: ["Save a snapshot when your thesis or assumptions change.", "Advanced check: compare each new review with the prior decision record."],
    };
    Object.entries(guides).forEach(([id, copy]) => {
      const body = document.getElementById(`body-${id}`);
      if (!body || body.querySelector(".il-tool-guide")) return;
      const guide = document.createElement("div");
      guide.className = "il-tool-guide compact";
      guide.innerHTML = `<button type="button" class="il-tool-guide-toggle" aria-expanded="false"><i class="ti ti-info-circle"></i><span>Guide</span></button><div class="il-tool-guide-body" hidden><div><span>Start here</span><strong>${copy[0]}</strong></div><div><span>Research check</span><strong>${copy[1]}</strong></div></div>`;
      const toggle = guide.querySelector(".il-tool-guide-toggle");
      const panel = guide.querySelector(".il-tool-guide-body");
      toggle?.addEventListener("click", () => {
        const open = toggle.getAttribute("aria-expanded") === "true";
        toggle.setAttribute("aria-expanded", String(!open));
        if (panel) panel.hidden = open;
      });
      body.insertBefore(guide, body.firstChild);
    });
  }

  function projectionScenarioKeys() {
    return ["bear", "base", "bull"];
  }
  function projectionInputFromForm(reviewed = false) {
    const ctx = currentTickerContext();
    const scenarios = {};
    projectionScenarioKeys().forEach(key => {
      scenarios[key] = {
        key,
        name: key[0].toUpperCase() + key.slice(1),
        growth: Number(document.getElementById(`adv-g-${key}`)?.value),
        exitPE: Number(document.getElementById(`adv-pe-${key}`)?.value),
        dividendYield: Number(document.getElementById(`adv-div-${key}`)?.value),
        dividendGrowth: Number(document.getElementById(`adv-div-g-${key}`)?.value),
        annualDilution: Number(document.getElementById(`adv-dil-${key}`)?.value),
        probability: Number(document.getElementById(`adv-prob-${key}`)?.value),
      };
    });
    return {
      ticker: ctx.ticker,
      currentPrice: Number(document.getElementById("adv-price")?.value || ctx.price),
      currentEps: Number(document.getElementById("il-proj-eps-override")?.value || ctx.eps),
      currentPE: Number(document.getElementById("adv-pe-now")?.value || ctx.pe),
      years: Number(document.getElementById("adv-years")?.value || 5),
      reviewed,
      scenarios,
    };
  }
  function checklistHtml(validation) {
    return `<div class="il-assumption-checklist">${validation.items.map(item => `<div class="${item.ok ? "ok" : "missing"}"><i class="ti ${item.ok ? "ti-check" : "ti-alert-circle"}"></i><span>${escapeHtml(item.label)}</span></div>`).join("")}</div>`;
  }
  function sensitivityHtml(sensitivity) {
    if (!sensitivity?.ok) return `<div class="il-result-note">Sensitivity unavailable until price, EPS, P/E, and base assumptions are valid.</div>`;
    return `<div class="il-sensitivity-table"><table><thead><tr><th>Growth / P/E</th>${sensitivity.peSteps.map(pe => `<th>${pe.toFixed(1)}x</th>`).join("")}</tr></thead><tbody>${sensitivity.rows.map(row => `<tr><th>${(row.growth * 100).toFixed(1)}%</th>${row.cells.map(cell => `<td class="${cell.current ? "current" : ""}">${cell.value === null ? "--" : fmtMoney(cell.value)}</td>`).join("")}</tr>`).join("")}</tbody></table>${sensitivity.conclusionFlips ? `<p>Warning: small growth or multiple changes can reverse the conclusion.</p>` : ""}</div>`;
  }
  function renderProjectionWorkspace(result) {
    const body = document.getElementById("body-projection");
    if (!body) return;
    if (document.getElementById("il-projlab-mount")) return;  // Projection Lab replaces the legacy projection workspace
    let workspace = document.getElementById("il-projection-builder");
    if (!workspace) {
      workspace = document.createElement("div");
      workspace.id = "il-projection-builder";
      workspace.className = "il-projection-builder";
      const intro = body.querySelector(".tool-intro");
      (intro || body.firstChild)?.insertAdjacentElement("afterend", workspace);
    }
    const ctx = currentTickerContext();
    const validation = window.ImpliedLensMath?.validateProjectionContext ? window.ImpliedLensMath.validateProjectionContext(projectionInputFromForm(false)) : null;
    const note = readNote();
    workspace.innerHTML = `<div class="il-proj-grid">
      <section class="il-proj-evidence"><div class="il-proj-head"><span>Evidence Panel</span><strong>${ctx.ticker || "No ticker loaded"}</strong></div>
        <div class="il-evidence-grid">
          ${trustField("Current price", fmtMoney(ctx.price))}
          ${trustField("Current P/E", fmtNum(ctx.pe, "x"))}
          ${trustField("EPS TTM", fmtMoney(ctx.eps))}
          ${trustField("Market cap", fmtMoney(ctx.marketCap))}
          ${trustField("Freshness", ctx.freshness || "Provider timing varies")}
          ${trustField("Source", ctx.source || "Source pending")}
        </div>
        <label class="il-manual-eps"><span>User assumption</span> Starting EPS override<input type="number" id="il-proj-eps-override" step="0.01" placeholder="Use normalized EPS if provider EPS is unavailable"></label>
        <div class="il-observed-note"><span>Observed</span> Values above come from loaded provider context when available. The EPS override is a user assumption and is only used when filled.</div>
      </section>
      <section class="il-proj-review"><div class="il-proj-head"><span>Assumption Review Gate</span><strong>${validation?.ok ? "Ready after confirmation" : "Needs review"}</strong></div>
        ${validation ? checklistHtml(validation) : ""}
        <label class="il-review-check"><input type="checkbox" id="il-assumptions-reviewed"> I reviewed these assumptions.</label>
        <button type="button" id="il-calc-projection" class="il-primary-action">Calculate Projection</button>
      </section>
    </div>
    <div class="il-template-row"><span>Templates are starting points, not recommendations.</span>${[
      ["conservative", "Conservative", 3, 16, 35, 8, 22, 45, 14, 28, 20],
      ["base", "Base", 2, 18, 25, 10, 24, 50, 18, 30, 25],
      ["optimistic", "Optimistic", 4, 20, 20, 14, 28, 45, 24, 38, 35],
    ].map(t => `<button type="button" data-il-template="${t.slice(0,1)}" data-values="${t.slice(2).join(",")}">${t[1]}</button>`).join("")}</div>
    <div id="il-projection-explain" class="il-projection-explain">${note.updatedAt ? `<div class="il-result-note">Ticker notes last updated ${trustDateLabel(note.updatedAt, "recently")}.</div>` : `<div class="il-result-note">Attach projection notes from the Notes panel.</div>`}</div>`;
    workspace.querySelectorAll("[data-il-template]").forEach(button => button.onclick = () => {
      const values = button.dataset.values.split(",").map(Number);
      const fields = [
        "adv-g-bear", "adv-pe-bear", "adv-prob-bear",
        "adv-g-base", "adv-pe-base", "adv-prob-base",
        "adv-g-bull", "adv-pe-bull", "adv-prob-bull",
      ];
      fields.forEach((id, index) => {
        const field = document.getElementById(id);
        if (field) {
          field.value = values[index];
          field.dataset.userEdited = "true";
        }
      });
      renderProjectionWorkspace();
      const explain = document.getElementById("il-projection-explain");
      if (explain) explain.innerHTML = `<div class="il-result-note">Template applied. Changed: growth, exit P/E, and probabilities for bear/base/bull. Review before calculating.</div>`;
    });
    const calc = workspace.querySelector("#il-calc-projection");
    calc.onclick = () => {
      const reviewed = Boolean(document.getElementById("il-assumptions-reviewed")?.checked);
      const built = window.ImpliedLensMath?.buildProjection?.(projectionInputFromForm(reviewed));
      if (!built?.ok) {
        const explain = document.getElementById("il-projection-explain");
        if (explain) explain.innerHTML = `<div class="il-result-error"><strong>Projection prerequisites not met.</strong>${built?.checklist ? checklistHtml({ items: built.checklist }) : ""}${built?.warnings?.length ? `<p>${built.warnings.map(escapeHtml).join(" ")}</p>` : ""}</div>`;
        return;
      }
      window.runAdvancedProjection?.();
      const explain = document.getElementById("il-projection-explain");
      if (explain) explain.innerHTML = `<div class="il-result-summary"><div><span>Probability-weighted value</span><strong>${fmtMoney(built.probabilityWeightedValue)}</strong><em>${(built.upsideDownsidePercent * 100).toFixed(1)}% vs current price</em></div><div><span>What drove the result</span><p>${escapeHtml(built.explanation.drivers)}</p></div><div><span>Most sensitive assumption</span><p>${escapeHtml(built.explanation.mostSensitive)}</p></div><div><span>What could break it</span><p>${escapeHtml(built.explanation.breakpoints)}</p></div></div>${sensitivityHtml(built.sensitivity)}${built.warnings.length ? `<div class="il-result-note">${built.warnings.map(escapeHtml).join(" ")}</div>` : ""}`;
    };
  }

  function installResearchTrail() {
    const stock = document.getElementById("stock-result");
    if (!stock || document.getElementById("il-research-trail")) return;
    const trail = document.createElement("div");
    trail.id = "il-research-trail";
    trail.className = "il-research-trail";
    trail.innerHTML = [
      ["price", "Price action", ".chart-wrap"],
      ["quality", "Business quality", "#metrics-grid"],
      ["valuation", "Valuation", ".dash-sidebar"],
      ["earnings", "Earnings", "#sec-earnings"],
      ["ownership", "Ownership / filings", "#sec-institutional"],
      ["projection", "Projection", "#il-projection-builder"],
      ["notes", "Thesis notes", "#il-notes-panel"],
    ].map(([key, label, target]) => `<button type="button" data-target="${escapeHtml(target)}"><span>${escapeHtml(key)}</span><strong>${escapeHtml(label)}</strong></button>`).join("");
    stock.insertBefore(trail, stock.querySelector(".metrics-grid"));
    trail.querySelectorAll("button").forEach(button => button.onclick = () => {
      const target = document.querySelector(button.dataset.target);
      if (button.dataset.target === "#il-notes-panel") openNotesPanel();
      else if (target) target.scrollIntoView({ behavior: "smooth", block: "start" });
    });
  }

  function improveControlSemantics() {
    document.querySelectorAll("#view-tool button:not([type])").forEach(button => button.type = "button");
    document.querySelectorAll("#view-tool label:not([for])").forEach(label => {
      const control = label.querySelector("input,select,textarea") || label.parentElement?.querySelector("input[id],select[id],textarea[id]");
      if (control?.id) label.htmlFor = control.id;
    });
  }

  function init() {
    installChartPersistence();
    installQuoteTrust();
    installDecisionSpine();
    installToolShells();
    installUrlState();
    renderProjectionWorkspace();
    installEducationContext();
    installOnboarding();
    installBuildBadge();
    installFeedbackPrompt();
    installToolGuidance();
    improveControlSemantics();
    window.refreshToolEnhancements = () => {
      installToolGuidance();
      improveControlSemantics();
      installToolShells();
      renderProjectionWorkspace();
    };
    const toolView = document.getElementById("view-tool");
    if (toolView) new MutationObserver(improveControlSemantics).observe(toolView, { childList: true, subtree: true });
    improveUnavailableStates();
    window.shareTickerResearch = shareTickerResearch;
    setInterval(improveUnavailableStates, 1500);
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
}());
