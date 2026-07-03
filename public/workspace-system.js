(function () {
  "use strict";

  const STORE = "il-workspace-v1";
  const LAYOUTS = "il-chart-layouts-v1";
  const state = { tab: "thesis", theses: [], positions: [], watchlist: [], prices: {}, priceRequested: new Set(), providers: null, summary: null, portfolioProfile: null, conviction: 3, activationTracked: false };

  function read(key, fallback) { try { return JSON.parse(localStorage.getItem(key) || JSON.stringify(fallback)); } catch (_) { return fallback; } }
  function write(key, value) { try { localStorage.setItem(key, JSON.stringify(value)); } catch (_) {} }
  function symbol(value) { return String(value || "").trim().toUpperCase().replace(/[^A-Z0-9.^-]/g, "").slice(0, 15); }
  function esc(value) { return String(value ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])); }
  function money(value) { return value !== null && value !== "" && Number.isFinite(Number(value)) ? Number(value).toLocaleString("en-US", { style: "currency", currency: "USD", maximumFractionDigits: 2 }) : "—"; }
  function relativeAge(value) {
    if (!value) return "Not observed yet";
    const seconds = Math.max(0, Math.round((Date.now() - new Date(value).getTime()) / 1000));
    if (!Number.isFinite(seconds)) return "Observation time unavailable";
    if (seconds < 60) return "Checked under 1m ago";
    if (seconds < 3600) return `Checked ${Math.round(seconds / 60)}m ago`;
    if (seconds < 86400) return `Checked ${Math.round(seconds / 3600)}h ago`;
    return `Checked ${Math.round(seconds / 86400)}d ago`;
  }
  function lines(value) { return String(value || "").split(/\r?\n/).map(v => v.trim()).filter(Boolean); }
  function currentTicker() { return symbol(window.IL_STATE?.ticker || document.getElementById("main-ticker")?.value || ""); }
  function localData() { return read(STORE, { theses: [], positions: [], watchlist: [] }); }
  function saveLocal() { write(STORE, { theses: state.theses, positions: state.positions, watchlist: state.watchlist }); }
  function toastMsg(message, kind) { if (typeof window.toast === "function") window.toast(message, kind); }
  function track(event, properties = {}) { if (typeof window.track === "function") window.track(event, properties); }

  async function api(path, options = {}) {
    const headers = { "Content-Type": "application/json", ...(options.headers || {}) };
    if (options.method && options.method !== "GET") headers["X-CSRF-Token"] = window.IL_STATE?.csrfToken || "";
    return fetch(path, { credentials: "same-origin", ...options, headers, body: options.body ? JSON.stringify(options.body) : undefined });
  }

  async function loadWorkspace() {
    // Wait for auth to be determined so we don't render a stale "logged out"
    // state (e.g. offering "Create free account") while the user is actually Pro.
    try { if (window.IL_AUTH_READY) await window.IL_AUTH_READY; } catch (_) {}
    const local = localData();
    if (!window.IL_STATE?.loggedIn) {
      Object.assign(state, local);
      renderAll();
      return;
    }
    try {
      const [t, p, w, s, profile] = await Promise.all([
        ...["theses", "positions", "watchlist"].map(type => api(`/api/workspace/${type}`)),
        api("/api/workspace/summary"),
        api("/api/workspace/portfolio-profile"),
      ]);
      if ([t, p, w, s, profile].some(r => !r.ok)) throw new Error("sync unavailable");
      [state.theses, state.positions, state.watchlist, state.summary, state.portfolioProfile] = await Promise.all([t.json(), p.json(), w.json(), s.json(), profile.json()]);
      renderAll();
    } catch (_) {
      Object.assign(state, local);
      renderAll();
    }
  }

  async function refreshMemberSummary() {
    if (!window.IL_STATE?.loggedIn) return;
    try {
      const response = await api("/api/workspace/summary");
      if (response.ok) state.summary = await response.json();
      renderActivation();
    } catch (_) {}
  }

  function syncLabel() { return window.IL_STATE?.loggedIn ? "Cloud synced" : "Saved on this device"; }
  async function persist(type, ticker, body) {
    const plural = type === "thesis" ? "theses" : type === "position" ? "positions" : "watchlist";
    if (window.IL_STATE?.loggedIn) {
      const response = await api(`/api/workspace/${plural}/${ticker}`, { method: "PUT", body });
      if (!response.ok) throw new Error((await response.json().catch(() => ({}))).error || "Could not save");
      return response.json();
    }
    const key = plural;
    const item = { ...body, ticker, updated_at: new Date().toISOString(), created_at: new Date().toISOString() };
    const index = state[key].findIndex(row => row.ticker === ticker);
    if (index >= 0) state[key][index] = { ...state[key][index], ...item };
    else state[key].unshift(item);
    saveLocal();
    return item;
  }
  async function remove(type, ticker) {
    const plural = type === "thesis" ? "theses" : type === "position" ? "positions" : "watchlist";
    if (window.IL_STATE?.loggedIn) {
      const response = await api(`/api/workspace/${plural}/${ticker}`, { method: "DELETE" });
      if (!response.ok) throw new Error("Could not remove");
    }
    state[plural] = state[plural].filter(row => row.ticker !== ticker);
    saveLocal();
  }

  function injectShell() {
    if (document.getElementById("sec-workspace")) return;
    const reports = document.querySelector('.app-sidebar .sb-item[data-sec="reports"]');
    if (reports) reports.insertAdjacentHTML("beforebegin", `<div class="sb-item" data-sec="workspace"><i class="ti ti-briefcase sb-item-icon" aria-hidden="true"></i><span class="sb-item-label">Workspace</span></div>`);
    // Mirror into the Market page sidebar so both navs match exactly.
    const homeReports = document.querySelector('.hs-sidebar .hsb-item[onclick*="reports"]');
    if (homeReports && !document.querySelector('.hs-sidebar [data-il-nav="workspace"]')) {
      homeReports.insertAdjacentHTML("beforebegin", `<a class="hsb-item" data-il-nav="workspace" href="/?view=tool&amp;section=workspace" onclick="navGoTo('workspace');return false;"><i class="ti ti-briefcase"></i><span>Workspace</span></a>`);
    }
    const mobile = document.getElementById("mobile-sec-tabs");
    if (mobile) mobile.insertAdjacentHTML("beforeend", `<button class="mst-btn" data-sec="workspace">Workspace</button>`);
    const scroll = document.querySelector(".app-content-scroll");
    if (!scroll) return;
    scroll.insertAdjacentHTML("beforeend", `<div class="app-section" id="sec-workspace"><div class="acc-body" id="body-workspace" style="display:none"><div class="il-ws-shell">
      <div class="il-ws-hero"><div class="il-ws-intro"><div class="il-ws-kicker">Decision dashboard</div><h2>Turn research into a reviewable decision.</h2><p>Continue the work that matters: test a thesis, understand exposure, and revisit decisions on schedule.</p></div><div class="il-ws-stat accent-blue"><span>Theses</span><strong id="il-ws-thesis-count">0</strong></div><div class="il-ws-stat accent-green"><span>Positions</span><strong id="il-ws-position-count">0</strong></div><div class="il-ws-stat accent-gold"><span>Cost basis</span><strong id="il-ws-invested">$0</strong></div><div class="il-ws-stat accent-red"><span>Reviews due</span><strong id="il-ws-review-count">0</strong></div></div>
      <div id="il-ws-activation"></div>
      <div class="il-ws-tabs"><button class="il-ws-tab active" data-tab="thesis"><i class="ti ti-notes"></i>Thesis</button><button class="il-ws-tab" data-tab="portfolio"><i class="ti ti-chart-donut-3"></i>Portfolio</button><button class="il-ws-tab" data-tab="guide"><i class="ti ti-sparkles"></i>AI Portfolio Guide</button><button class="il-ws-tab" data-tab="watchlist"><i class="ti ti-star"></i>Watchlist</button><button class="il-ws-tab" data-tab="trust"><i class="ti ti-shield-check"></i>Data trust</button></div>
      <div class="il-ws-panel active" data-panel="thesis"></div><div class="il-ws-panel" data-panel="portfolio"></div><div class="il-ws-panel" data-panel="guide"></div><div class="il-ws-panel" data-panel="watchlist"></div><div class="il-ws-panel" data-panel="trust"></div>
    </div></div></div>`);
    document.querySelector(".il-ws-tabs").addEventListener("click", event => {
      const tab = event.target.closest("[data-tab]")?.dataset.tab;
      if (!tab) return;
      state.tab = tab;
      document.querySelectorAll(".il-ws-tab").forEach(el => el.classList.toggle("active", el.dataset.tab === tab));
      document.querySelectorAll(".il-ws-panel").forEach(el => el.classList.toggle("active", el.dataset.panel === tab));
      if (tab === "guide") track("portfolio_guide_viewed", { has_profile: Boolean(state.portfolioProfile) });
    });
    if (window.SECTION_META) window.SECTION_META.workspace = { icon: "ti-briefcase", title: "Investment Workspace" };
    const originalOpen = window.openSection;
    window.openSection = function (id, skip) {
      const out = originalOpen(id, skip);
      if (id === "workspace") {
        const title = document.getElementById("ash-title"); const icon = document.getElementById("ash-icon");
        if (title) title.textContent = "Investment Workspace";
        if (icon) icon.className = "ti ti-briefcase ash-icon";
        loadWorkspace();
      }
      return out;
    };
    window.openWorkspaceWatchlist = function () {
      state.tab = "watchlist";
      if (typeof window.navGoTo === "function") window.navGoTo("workspace");
      const tab = document.querySelector('.il-ws-tab[data-tab="watchlist"]');
      if (tab) tab.click();
    };
    window.openPortfolioGuide = function () {
      state.tab = "guide";
      if (typeof window.navGoTo === "function") window.navGoTo("workspace");
      setTimeout(() => document.querySelector('.il-ws-tab[data-tab="guide"]')?.click(), 0);
    };
  }

  function renderAll() {
    const invested = state.positions.reduce((sum, row) => sum + Number(row.shares || 0) * Number(row.cost_basis || 0), 0);
    document.getElementById("il-ws-thesis-count").textContent = state.theses.length;
    document.getElementById("il-ws-position-count").textContent = state.positions.length;
    document.getElementById("il-ws-invested").textContent = money(invested);
    document.getElementById("il-ws-review-count").textContent = Number(state.summary?.dueReviews || 0);
    renderActivation(); renderThesis(); renderPortfolio(); renderGuide(); renderWatchlist(); renderTrust(); renderHomeWatchlist();
  }

  function renderActivation() {
    const host = document.getElementById("il-ws-activation");
    if (!host) return;
    if (!window.IL_STATE?.loggedIn) {
      host.innerHTML = `<div class="il-ws-activation"><div><div class="il-ws-kicker">Member workflow</div><h3>Sync your decisions and build your portfolio guide.</h3><p>Create a free account to keep this workspace across devices.</p></div><button class="il-ws-btn primary" id="il-ws-join">Create free account</button></div>`;
      host.querySelector("#il-ws-join").onclick = () => typeof window.startGuestSignup === "function" ? window.startGuestSignup("workspace_activation") : window.location.assign("/signup");
      return;
    }
    const activation = state.summary?.activation || {};
    const items = [
      ["analyzed", "Run an analysis", "analyze"],
      ["thesis", "Save a thesis", "thesis"],
      ["watchlist", "Add a watch item", "watchlist"],
      ["portfolioProfile", "Build portfolio guide", "guide"],
      ["reviewScheduled", "Schedule a review", "thesis"],
    ];
    host.innerHTML = `<div class="il-ws-activation"><div><div class="il-ws-kicker">Activation path</div><h3>${state.summary?.activationCompleted || 0} of ${state.summary?.activationTotal || items.length} decision habits set up</h3><p>Finish the loop once, then use it whenever your evidence changes.</p></div><div class="il-ws-checks">${items.map(([key, label, target]) => `<button class="${activation[key] ? "done" : ""}" data-activation-target="${target}"><i class="ti ${activation[key] ? "ti-check" : "ti-arrow-right"}"></i>${esc(label)}</button>`).join("")}</div></div>`;
    host.querySelectorAll("[data-activation-target]").forEach(button => button.onclick = () => {
      const target = button.dataset.activationTarget;
      if (target === "analyze") return typeof window.openSection === "function" && window.openSection("analyze");
      document.querySelector(`.il-ws-tab[data-tab="${target}"]`)?.click();
    });
    if (!state.activationTracked) {
      state.activationTracked = true;
      track("activation_checklist_viewed", { completed: Number(state.summary?.activationCompleted || 0) });
    }
  }

  function renderThesis() {
    const ticker = currentTicker();
    const item = state.theses.find(row => row.ticker === ticker) || {};
    state.conviction = Number(item.conviction || 3);
    const panel = document.querySelector('[data-panel="thesis"]');
    panel.innerHTML = `<div class="il-ws-grid"><div class="il-ws-block"><h3>${ticker ? `${esc(ticker)} investment thesis` : "Investment thesis"}</h3><p>Write the argument before the market writes it for you.</p><div class="il-ws-fields">
      <div class="il-ws-field"><label>Ticker</label><input id="il-thesis-ticker" value="${esc(ticker)}" placeholder="AAPL"></div><div class="il-ws-field"><label>Status</label><select id="il-thesis-status">${["watching","owned","review","passed"].map(v => `<option ${item.status === v ? "selected" : ""}>${v}</option>`).join("")}</select></div>
      <div class="il-ws-field wide"><label>Core thesis</label><textarea id="il-thesis-copy" placeholder="What does the market misunderstand?">${esc(item.thesis)}</textarea></div>
      <div class="il-ws-field"><label>Catalysts, one per line</label><textarea id="il-thesis-catalysts">${esc((item.catalysts || []).join("\n"))}</textarea></div><div class="il-ws-field"><label>Risks, one per line</label><textarea id="il-thesis-risks">${esc((item.risks || []).join("\n"))}</textarea></div>
      <div class="il-ws-field wide"><label>Sell or invalidate when</label><textarea id="il-thesis-sell">${esc((item.sell_conditions || []).join("\n"))}</textarea></div>
      <div class="il-ws-field"><label>Bear price</label><input id="il-thesis-bear" type="number" step=".01" value="${esc(item.bear_price)}"></div><div class="il-ws-field"><label>Target price</label><input id="il-thesis-target" type="number" step=".01" value="${esc(item.target_price)}"></div>
      <div class="il-ws-field"><label>Review date</label><input id="il-thesis-review" type="date" value="${esc(item.review_date)}"></div><div class="il-ws-field"><label>Conviction</label><div class="il-ws-conviction">${[1,2,3,4,5].map(v => `<button class="${state.conviction === v ? "active" : ""}" data-conviction="${v}">${v}</button>`).join("")}</div></div>
      </div><div class="il-ws-actions"><button class="il-ws-btn primary" id="il-save-thesis"><i class="ti ti-device-floppy"></i>Save thesis</button>${item.ticker ? `<button class="il-ws-btn danger" data-remove="thesis" data-ticker="${esc(item.ticker)}"><i class="ti ti-trash"></i>Remove</button>` : ""}<span class="il-ws-sync">${syncLabel()}</span></div></div>
      <div class="il-ws-block"><h3>Thesis library</h3><p>Open a prior decision to review it against new evidence.</p><div class="il-ws-list">${state.theses.length ? state.theses.map(row => `<button class="il-ws-btn" data-open-thesis="${esc(row.ticker)}"><strong>${esc(row.ticker)}</strong>&nbsp;${esc(row.status || "watching")}</button>`).join("") : `<div class="il-ws-empty il-ws-empty-rich"><i class="ti ti-notes"></i><strong>Start with a decision you may need to defend.</strong><span>Load a company, write what the market may misunderstand, and schedule the next evidence review.</span><button class="il-ws-btn" data-empty-action="analyze">Analyze a company</button></div>`}</div></div></div>`;
    panel.querySelectorAll("[data-conviction]").forEach(button => button.onclick = () => { state.conviction = Number(button.dataset.conviction); renderThesis(); });
    panel.querySelector("#il-save-thesis").onclick = saveThesis;
    panel.querySelectorAll("[data-open-thesis]").forEach(button => button.onclick = () => openTicker(button.dataset.openThesis, "thesis"));
    panel.querySelector("[data-empty-action='analyze']")?.addEventListener("click", () => window.openSection?.("analyze"));
    wireRemoves(panel);
  }

  async function saveThesis() {
    const ticker = symbol(document.getElementById("il-thesis-ticker").value);
    if (!ticker) return toastMsg("Enter a ticker first", "red");
    const body = { status: document.getElementById("il-thesis-status").value, thesis: document.getElementById("il-thesis-copy").value,
      catalysts: lines(document.getElementById("il-thesis-catalysts").value), risks: lines(document.getElementById("il-thesis-risks").value),
      sell_conditions: lines(document.getElementById("il-thesis-sell").value), bear_price: document.getElementById("il-thesis-bear").value,
      target_price: document.getElementById("il-thesis-target").value, review_date: document.getElementById("il-thesis-review").value, conviction: state.conviction };
    try { const saved = await persist("thesis", ticker, body); state.theses = [saved, ...state.theses.filter(v => v.ticker !== ticker)]; saveLocal(); track("thesis_saved", { ticker, has_review_date: Boolean(body.review_date) }); await refreshMemberSummary(); renderAll(); toastMsg(`${ticker} thesis saved`, "ok"); } catch (e) { toastMsg(e.message, "red"); }
  }

  function formBlock(kind) {
    const portfolio = kind === "position";
    return `<div class="il-ws-block"><h3>${portfolio ? "Add or update position" : "Add to watchlist"}</h3><p>${portfolio ? "Track exposure and unrealized return." : "Keep the reason and price level attached."}</p><div class="il-ws-fields">
      <div class="il-ws-field"><label>Ticker</label><input id="il-${kind}-ticker" value="${esc(currentTicker())}" placeholder="AAPL"></div>
      ${portfolio ? `<div class="il-ws-field"><label>Shares</label><input id="il-position-shares" type="number" step=".0001"></div><div class="il-ws-field"><label>Cost basis / share</label><input id="il-position-cost" type="number" step=".01"></div><div class="il-ws-field"><label>Sector</label><input id="il-position-sector" placeholder="Technology"></div><div class="il-ws-field wide"><label>Notes</label><textarea id="il-position-notes"></textarea></div>` : `<div class="il-ws-field"><label>Target price</label><input id="il-watchlist-target" type="number" step=".01"></div><div class="il-ws-field wide"><label>Reason to watch</label><textarea id="il-watchlist-note"></textarea></div>`}
      </div><div class="il-ws-actions"><button class="il-ws-btn primary" id="il-save-${kind}"><i class="ti ti-plus"></i>${portfolio ? "Save position" : "Add to watchlist"}</button><span class="il-ws-sync">${syncLabel()}</span></div></div>`;
  }

  function renderPortfolio() {
    const panel = document.querySelector('[data-panel="portfolio"]');
    const totalValue = state.positions.reduce((sum, row) => sum + (state.prices[row.ticker] || row.cost_basis) * row.shares, 0);
    const weights = state.positions.map(row => {
      const value = row.shares * (state.prices[row.ticker] || row.cost_basis);
      return { ticker: row.ticker, value, weight: totalValue ? value / totalValue * 100 : 0 };
    }).sort((a, b) => b.weight - a.weight);
    const largest = weights[0]?.weight || 0;
    const overview = state.positions.length ? `<div class="il-ws-portfolio-overview"><div><div class="il-ws-kicker">Concentration view</div><strong>${largest.toFixed(1)}%</strong><span>largest position${largest > 35 ? " · review concentration risk" : " · within a diversified range"}</span></div><div class="il-ws-weight-bars">${weights.slice(0, 5).map(row => `<div><span>${esc(row.ticker)}</span><i><b style="width:${Math.min(100, row.weight)}%"></b></i><strong>${row.weight.toFixed(1)}%</strong></div>`).join("")}</div></div>` : `<div class="il-ws-sample"><div class="il-ws-kicker">Example concentration view</div><div class="il-ws-weight-bars"><div><span>CORE</span><i><b style="width:48%"></b></i><strong>48%</strong></div><div><span>GROWTH</span><i><b style="width:32%;background:#7d91b6"></b></i><strong>32%</strong></div><div><span>RESERVE</span><i><b style="width:20%;background:#8aa381"></b></i><strong>20%</strong></div></div><p>Add positions to replace this preview with your actual concentration and return view.</p></div>`;
    panel.innerHTML = `<div class="il-ws-grid">${formBlock("position")}<div class="il-ws-block"><h3>Portfolio intelligence</h3><p>Weights and returns refresh from the latest available price.</p>${overview}<div class="il-ws-list">${state.positions.length ? state.positions.map(row => {
      const price = state.prices[row.ticker]; const cost = row.shares * row.cost_basis; const value = row.shares * (price || row.cost_basis); const gain = value - cost; const pct = cost ? gain / cost * 100 : 0; const weight = totalValue ? value / totalValue * 100 : 0;
      return `<div class="il-ws-item"><div><strong>${esc(row.ticker)}</strong><span>${esc(row.sector || "Unclassified")}</span></div><div class="il-ws-num">${money(value)}<span>${weight.toFixed(1)}% weight</span></div><div class="il-ws-num ${gain >= 0 ? "pos" : "neg"}">${gain >= 0 ? "+" : ""}${money(gain)}<span>${pct.toFixed(1)}% return</span></div><div class="il-ws-num">${row.shares} shares<span>${money(row.cost_basis)} basis</span></div><button class="il-ws-btn danger" data-remove="position" data-ticker="${esc(row.ticker)}"><i class="ti ti-trash"></i></button></div>`;
    }).join("") : ""}</div></div></div>`;
    panel.querySelector("#il-save-position").onclick = savePosition; wireRemoves(panel); refreshPrices(state.positions.map(v => v.ticker));
  }

  async function savePosition() {
    const ticker = symbol(document.getElementById("il-position-ticker").value);
    const shares = Number(document.getElementById("il-position-shares").value);
    const costBasis = Number(document.getElementById("il-position-cost").value);
    if (!ticker) return toastMsg("Enter a ticker first", "red");
    if (!Number.isFinite(shares) || shares <= 0) return toastMsg("Shares must be above zero", "red");
    if (!Number.isFinite(costBasis) || costBasis < 0) return toastMsg("Cost basis cannot be negative", "red");
    const body = { shares, cost_basis: costBasis, sector: document.getElementById("il-position-sector").value, notes: document.getElementById("il-position-notes").value };
    try { const saved = await persist("position", ticker, body); state.positions = [saved, ...state.positions.filter(v => v.ticker !== ticker)]; saveLocal(); track("position_saved", { ticker }); await refreshMemberSummary(); renderAll(); toastMsg(`${ticker} position saved`, "ok"); } catch (e) { toastMsg(e.message, "red"); }
  }

  function guideOptions(values, selected) {
    return values.map(([value, label]) => `<option value="${value}" ${selected === value ? "selected" : ""}>${label}</option>`).join("");
  }

  function renderGuide() {
    const panel = document.querySelector('[data-panel="guide"]');
    if (!panel) return;
    if (!window.IL_STATE?.loggedIn) {
      panel.innerHTML = `<div class="il-ws-block il-ws-guide-intro"><div class="il-ws-kicker">Optional member tool</div><h3>Build a transparent AI Portfolio Guide.</h3><p>Answer seven short questions to create an educational model allocation. No individual stock picks, no black box, and no changes to your holdings.</p><button class="il-ws-btn primary" id="il-guide-join">Create free account</button></div>`;
      panel.querySelector("#il-guide-join").onclick = () => typeof window.startGuestSignup === "function" ? window.startGuestSignup("portfolio_guide") : window.location.assign("/signup");
      return;
    }
    const profile = state.portfolioProfile || {};
    const model = profile.model || null;
    const due = Number(state.summary?.dueReviews || 0);
    panel.innerHTML = `<div class="il-ws-guide-head"><div><div class="il-ws-kicker">Transparent questionnaire model</div><h3>AI Portfolio Guide</h3><p>Use a short questionnaire to create a broad, educational allocation model you can revisit as life changes.</p></div><span class="il-ws-disclosure">Educational only, not investment advice</span></div>
      <div class="il-ws-grid il-ws-guide-grid"><div class="il-ws-block"><h3>${model ? "Update your answers" : "Build your model"}</h3><p>Your answers stay in your member workspace.</p><div class="il-ws-fields">
        <div class="il-ws-field"><label>Primary goal</label><select id="il-guide-goal">${guideOptions([["retirement","Retirement"],["growth","Long-term growth"],["income","Income"],["capital_preservation","Capital preservation"]], profile.goal || "retirement")}</select></div>
        <div class="il-ws-field"><label>Time horizon (years)</label><input id="il-guide-horizon" type="number" min="1" max="50" value="${esc(profile.horizon_years || 10)}"></div>
        <div class="il-ws-field"><label>Risk reaction</label><select id="il-guide-risk">${guideOptions([["conservative","Protect against large declines"],["balanced","Accept moderate declines"],["aggressive","Accept large declines for growth"]], profile.risk_tolerance || "balanced")}</select></div>
        <div class="il-ws-field"><label>Near-term liquidity need</label><select id="il-guide-liquidity">${guideOptions([["low","Low"],["medium","Medium"],["high","High"]], profile.liquidity_need || "medium")}</select></div>
        <div class="il-ws-field"><label>Investing experience</label><select id="il-guide-experience">${guideOptions([["new","New"],["intermediate","Intermediate"],["experienced","Experienced"]], profile.experience || "intermediate")}</select></div>
        <div class="il-ws-field"><label>Income stability</label><select id="il-guide-income">${guideOptions([["variable","Variable"],["stable","Stable"],["very_stable","Very stable"]], profile.income_stability || "stable")}</select></div>
        <div class="il-ws-field wide"><label>Management preference</label><select id="il-guide-preference">${guideOptions([["passive","Mostly passive"],["blended","Blended"],["active","Active research sleeve"]], profile.preference || "passive")}</select></div>
      </div><div class="il-ws-actions"><button class="il-ws-btn primary" id="il-save-guide"><i class="ti ti-sparkles"></i>${model ? "Update guide" : "Build my guide"}</button><span class="il-ws-sync">Optional and private to your account</span></div></div>
      <div class="il-ws-block"><h3>Review rhythm</h3><p>${due ? `${due} thesis review${due === 1 ? "" : "s"} overdue or coming up within 7 days.` : "Schedule thesis review dates to build a repeatable decision habit."}</p><button class="il-ws-btn ${due ? "primary" : ""}" id="il-email-reviews" ${due ? "" : "disabled"}><i class="ti ti-mail"></i>Email my review list</button><span class="il-ws-sync">At most one digest per day</span></div></div>
      ${model ? renderGuideModel(model) : renderGuideModel({ archetype: "Balanced preview", allocations: [{ asset: "US equity", percent: 45 }, { asset: "International equity", percent: 20 }, { asset: "Investment-grade bonds", percent: 25 }, { asset: "Short-term reserves", percent: 10 }], rationale: ["Your questionnaire answers will explain why the model changes."], guardrails: ["Revisit after major income, family, debt, or time-horizon changes."], disclosure: "Preview only. Complete the questionnaire to build your educational model." }, true)}`;
    panel.querySelector("#il-save-guide").onclick = saveGuide;
    panel.querySelector("#il-email-reviews").onclick = emailReviews;
    if (!model) panel.querySelector(".il-ws-fields").addEventListener("change", () => track("portfolio_questionnaire_started", {}), { once: true });
  }

  function renderGuideModel(model, preview = false) {
    const allocations = Array.isArray(model.allocations) ? model.allocations : [];
    return `<div class="il-ws-block il-ws-guide-model ${preview ? "preview" : ""}"><div class="il-ws-model-title"><div><div class="il-ws-kicker">${preview ? "Example output" : "Illustrative allocation"}</div><h3>${esc(model.archetype || "Portfolio")} model</h3></div><strong>${allocations.reduce((sum, row) => sum + Number(row.percent || 0), 0)}%</strong></div>
      <div class="il-ws-allocations">${allocations.map(row => `<div class="il-ws-allocation"><div><span>${esc(row.asset)}</span><strong>${Number(row.percent || 0)}%</strong></div><div class="il-ws-allocation-bar"><i style="width:${Math.max(0, Math.min(100, Number(row.percent || 0)))}%"></i></div></div>`).join("")}</div>
      <div class="il-ws-guide-notes"><div><h4>Why this model</h4><ul>${(model.rationale || []).map(item => `<li>${esc(item)}</li>`).join("")}</ul></div><div><h4>Guardrails</h4><ul>${(model.guardrails || []).map(item => `<li>${esc(item)}</li>`).join("")}</ul></div></div>
      <p class="il-ws-disclosure">${esc(model.disclosure || "")}</p></div>`;
  }

  async function saveGuide() {
    const body = {
      goal: document.getElementById("il-guide-goal").value,
      horizon_years: Number(document.getElementById("il-guide-horizon").value),
      risk_tolerance: document.getElementById("il-guide-risk").value,
      liquidity_need: document.getElementById("il-guide-liquidity").value,
      experience: document.getElementById("il-guide-experience").value,
      income_stability: document.getElementById("il-guide-income").value,
      preference: document.getElementById("il-guide-preference").value,
    };
    try {
      const response = await api("/api/workspace/portfolio-profile", { method: "PUT", body });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Could not build guide");
      state.portfolioProfile = data;
      await refreshMemberSummary();
      renderGuide();
      toastMsg("Portfolio guide saved", "ok");
    } catch (error) { toastMsg(error.message, "red"); }
  }

  async function emailReviews() {
    try {
      const response = await api("/api/workspace/review-reminder", { method: "POST", body: {} });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Could not send review list");
      toastMsg(data.alreadySent ? "Today's review list was already sent" : `Review list sent for ${data.count} decision${data.count === 1 ? "" : "s"}`, "ok");
    } catch (error) { toastMsg(error.message, "red"); }
  }

  function renderWatchlist() {
    const panel = document.querySelector('[data-panel="watchlist"]');
    panel.innerHTML = `<div class="il-ws-grid">${formBlock("watchlist")}<div class="il-ws-block"><h3>Watchlist intelligence</h3><p>See how far the latest price sits from your level.</p><div class="il-ws-list">${state.watchlist.length ? state.watchlist.map(row => {
      const price = state.prices[row.ticker]; const gap = price && row.target_price ? (row.target_price - price) / price * 100 : null;
      return `<div class="il-ws-item"><button class="il-ws-btn" data-open-ticker="${esc(row.ticker)}"><strong>${esc(row.ticker)}</strong></button><div class="il-ws-num">${money(price)}<span>latest price</span></div><div class="il-ws-num ${gap == null ? "" : gap >= 0 ? "pos" : "neg"}">${gap == null ? "—" : `${gap >= 0 ? "+" : ""}${gap.toFixed(1)}%`}<span>to ${money(row.target_price)}</span></div><div><span>${esc(row.note || "No note")}</span></div><button class="il-ws-btn danger" data-remove="watchlist" data-ticker="${esc(row.ticker)}"><i class="ti ti-trash"></i></button></div>`;
    }).join("") : `<div class="il-ws-empty il-ws-empty-rich"><i class="ti ti-star"></i><strong>Track the reason, not only the ticker.</strong><span>Add a company with the price level or evidence that would make it worth revisiting.</span><button class="il-ws-btn" data-empty-focus="watchlist">Add the first watch item</button></div>`}</div></div></div>`;
    panel.querySelector("#il-save-watchlist").onclick = saveWatchlist; panel.querySelectorAll("[data-open-ticker]").forEach(button => button.onclick = () => openTicker(button.dataset.openTicker)); wireRemoves(panel); refreshPrices(state.watchlist.map(v => v.ticker));
    panel.querySelector("[data-empty-focus='watchlist']")?.addEventListener("click", () => document.getElementById("il-watchlist-ticker")?.focus());
  }

  async function saveWatchlist() {
    const ticker = symbol(document.getElementById("il-watchlist-ticker").value);
    const rawTarget = document.getElementById("il-watchlist-target").value;
    const targetPrice = rawTarget === "" ? null : Number(rawTarget);
    if (!ticker) return toastMsg("Enter a ticker first", "red");
    if (targetPrice !== null && (!Number.isFinite(targetPrice) || targetPrice <= 0)) return toastMsg("Target price must be above zero", "red");
    const body = { target_price: targetPrice, note: document.getElementById("il-watchlist-note").value };
    try { const saved = await persist("watchlist", ticker, body); state.watchlist = [saved, ...state.watchlist.filter(v => v.ticker !== ticker)]; saveLocal(); track("watchlist_saved", { ticker }); await refreshMemberSummary(); renderAll(); toastMsg(`${ticker} added to watchlist`, "ok"); } catch (e) { toastMsg(e.message, "red"); }
  }

  function wireRemoves(host) {
    host.querySelectorAll("[data-remove]").forEach(button => button.onclick = async () => {
      try { await remove(button.dataset.remove, button.dataset.ticker); renderAll(); toastMsg(`${button.dataset.ticker} removed`, "ok"); } catch (e) { toastMsg(e.message, "red"); }
    });
  }
  function openTicker(ticker, tab) {
    const input = document.getElementById("main-ticker"); if (input) input.value = ticker;
    if (typeof window.fetchAndRender === "function") window.fetchAndRender();
    if (tab) { state.tab = tab; renderAll(); } else if (typeof window.openSection === "function") window.openSection("analyze");
  }
  async function refreshPrices(tickers) {
    const missing = [...new Set(tickers)].filter(t => !state.priceRequested.has(t)).slice(0, 20);
    if (!missing.length) return;
    missing.forEach(ticker => state.priceRequested.add(ticker));
    await Promise.all(missing.map(async ticker => {
      try {
        const r = await fetch(`/api/quote/${ticker}?range=5d&preview=1`); const data = await r.json();
        const price = Number(data?.chart?.result?.[0]?.meta?.regularMarketPrice || data?.meta?.regularMarketPrice);
        state.prices[ticker] = Number.isFinite(price) ? price : null;
      } catch (_) { state.prices[ticker] = null; }
    }));
    renderPortfolio(); renderWatchlist();
  }
  function renderHomeWatchlist() {
    const host = document.getElementById("home-watchlist-body");
    if (!host) return;
    if (!state.watchlist.length) {
      host.innerHTML = `<tr><td colspan="5"><div class="il-home-watch-empty"><strong>Build a decision watchlist</strong><span>Keep the reason and level attached to each company.</span><button onclick="openWorkspaceWatchlist()">Add watch item</button></div></td></tr>`;
      return;
    }
    host.innerHTML = state.watchlist.slice(0, 5).map(row => {
      const price = state.prices[row.ticker]; const gap = price && row.target_price ? (row.target_price - price) / price * 100 : null;
      return `<tr><td><div class="wl-sym">${esc(row.ticker)}</div><div class="wl-co">${esc(row.note || "Your watchlist")}</div></td><td class="wl-price">${money(price)}</td><td class="wl-pct ${gap == null ? "" : gap >= 0 ? "up" : "dn"}">${gap == null ? "—" : `${gap >= 0 ? "+" : ""}${gap.toFixed(1)}%`}</td><td class="wl-spark"><span style="color:var(--text5);font-size:.6rem;">to ${money(row.target_price)}</span></td><td><span class="wl-star lit" title="Tracked">★</span></td></tr>`;
    }).join("");
  }
  function renderTrust() {
    const panel = document.querySelector('[data-panel="trust"]');
    if (!panel) return;
    const providers = state.providers?.providers || [];
    const providerStale = Boolean(state.providers?.stale);
    const message = state.providers?.message || "Live status reflects providers observed by this running service.";
    panel.innerHTML = `<div class="il-ws-grid"><div class="il-ws-block"><h3>Provider observations</h3><p>${esc(message)}</p><div class="il-ws-health">${providers.length ? providers.map(p => {
      const status = providerStale && p.status === "operational" ? "stale" : p.status;
      return `<div class="il-ws-health-row"><span><i class="il-ws-dot ${status === "degraded" ? "degraded" : ""}" ${status === "stale" ? 'style="background:var(--brand-gold)"' : ""}></i>${esc(p.name)}</span><span><b class="il-ws-status ${esc(status)}">${esc(status)}</b>${esc(relativeAge(p.checkedAt))} · ${p.latencyMs ?? "—"}ms</span></div>`;
    }).join("") : `<div class="il-ws-empty il-ws-empty-rich"><i class="ti ti-radar"></i><strong>No provider request observed yet.</strong><span>Load a ticker and this panel will show the providers, freshness, latency, and latest outcome observed by this running service.</span><button class="il-ws-btn" data-empty-action="analyze">Analyze a company</button></div>`}</div></div><div class="il-ws-block"><h3>How to read the signal</h3><p>Operational means a recent request completed. Stale means the last observation is older than 15 minutes. Degraded means the latest observed request failed or returned no usable data.</p><div class="il-ws-freshness"><i class="ti ti-clock"></i>${esc(relativeAge(state.providers?.latestObservation))}</div><a class="il-ws-btn" href="/data-sources"><i class="ti ti-external-link"></i>Data methodology</a></div></div>`;
    panel.querySelector("[data-empty-action='analyze']")?.addEventListener("click", () => window.openSection?.("analyze"));
  }
  async function loadProviders() { try { const r = await fetch("/api/providers/health", { cache: "no-store" }); state.providers = await r.json(); renderTrust(); } catch (_) {} }

  function installChartWorkspace() {
    const toolbar = document.getElementById("app-chart-toolbar");
    if (!toolbar || document.getElementById("il-chart-workspace")) return;
    const host = document.createElement("div"); host.id = "il-chart-workspace"; host.className = "il-chart-workspace";
    host.innerHTML = `<span class="il-compare-group" title="Enter a ticker, then press Compare"><input id="il-compare-ticker" aria-label="Comparison ticker" placeholder="vs TICKER" maxlength="8"><button class="act-btn" id="il-run-compare" title="Compare current ticker"><i class="ti ti-arrows-diff"></i>Compare</button></span><button class="act-btn" id="il-save-layout" title="Save chart layout"><i class="ti ti-device-floppy"></i>Layout</button><button class="act-btn" id="il-restore-layout" title="Restore chart layout" aria-label="Restore chart layout"><i class="ti ti-history"></i></button>`;
    toolbar.querySelector(".act-right")?.before(host);
    document.getElementById("il-run-compare").onclick = () => {
      const first = currentTicker(), second = symbol(document.getElementById("il-compare-ticker").value);
      if (!first || !second) return toastMsg("Load a ticker and enter one to compare", "red");
      document.getElementById("cmp1").value = first; document.getElementById("cmp2").value = second; window.openSection("compare"); window.runCompare();
    };
    document.getElementById("il-save-layout").onclick = () => {
      if (!currentTicker()) return toastMsg("Load a ticker first", "red");
      const layouts = read(LAYOUTS, {}); layouts[currentTicker()] = { chartType: window.IL_STATE.chartType, range: window.IL_STATE.range, inds: window.IL_STATE.inds }; write(LAYOUTS, layouts); toastMsg("Chart layout saved", "ok");
    };
    document.getElementById("il-restore-layout").onclick = () => {
      const layout = read(LAYOUTS, {})[currentTicker()]; if (!layout) return toastMsg("No saved layout for this ticker", "red");
      window.IL_STATE.inds = { ...window.IL_STATE.inds, ...layout.inds };
      const typeButton = document.getElementById(`ct-${layout.chartType}`); window.setChartType(layout.chartType, typeButton);
      const rangeButton = [...document.querySelectorAll(".tf-pill")].find(el => (el.getAttribute("onclick") || "").includes(`'${layout.range}'`)); if (rangeButton) window.changeRange(layout.range, rangeButton);
      ["ma50","ma200","bb"].forEach(ind => {
        const button = document.getElementById(`ind-${ind}-btn`);
        if (!button) return;
        const selected = Boolean(window.IL_STATE.inds[ind]);
        button.classList.toggle("on", selected);
        button.setAttribute("aria-pressed", String(selected));
      });
      toastMsg("Chart layout restored", "ok");
    };
  }

  function installGuidanceShortcut() {
    const observer = new MutationObserver(() => {
      const actions = document.querySelector("#il-ticker-guidance .il-guidance-actions");
      if (actions && !actions.querySelector("[data-workspace-shortcut]")) actions.insertAdjacentHTML("afterbegin", `<button data-workspace-shortcut onclick="openSection('workspace')">Open workspace</button>`);
    });
    observer.observe(document.body, { childList: true, subtree: true });
  }

  function init() {
    injectShell(); installChartWorkspace(); installGuidanceShortcut(); loadWorkspace(); loadProviders();
    setInterval(loadProviders, 30000);
    setTimeout(loadWorkspace, 1200);
    if (window.__initialWorkspaceTab === "guide" || new URLSearchParams(window.location.search).get("workspace_tab") === "guide") {
      setTimeout(() => window.openPortfolioGuide?.(), 0);
    }
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init); else init();
}());

/* ── Live modeling: models recalculate as assumptions change ──────────────────
   After the first manual Calculate, every input change re-runs the model
   (debounced), so projections behave like a real modeling tool. Also adds
   "/" to jump to ticker search from anywhere in the tool. */
(function () {
  function debounce(fn, ms) { let t; return function () { clearTimeout(t); t = setTimeout(fn, ms); }; }
  const MODELS = [
    { sel: "#qdcf-eps,#qdcf-wacc,#qdcf-g1,#qdcf-g2,#qdcf-tg",
      ready: () => (document.getElementById("qdcf-output")?.innerHTML || "").trim(),
      run: () => window.runQuickDCF?.() },
    { sel: "#proj-years,#proj-pe-now,#proj-g-bear,#proj-pe-bear,#proj-g-base,#proj-pe-base,#proj-g-bull,#proj-pe-bull",
      ready: () => { const r = document.getElementById("proj-results"); return r && r.style.display !== "none"; },
      run: () => window.runProjection?.() },
    { sel: "#adv-years,#adv-price,#adv-pe-now,[id^='adv-g-'],[id^='adv-pe-'],[id^='adv-div-'],[id^='adv-dil-'],[id^='adv-prob-bear'],[id^='adv-prob-base'],[id^='adv-prob-bull']",
      ready: () => (document.getElementById("adv-scenario-cards")?.innerHTML || "").trim(),
      run: () => window.runAdvancedProjection?.() },
    { sel: "#dcf-eps,#dcf-g1,#dcf-g2,#dcf-tg,#dcf-wacc,#dcf-price",
      ready: () => (document.getElementById("dcf-output")?.innerHTML || "").trim(),
      run: () => window.runDCF?.() },
  ];
  function wire() {
    MODELS.forEach((m) => {
      const handler = debounce(() => { try { if (m.ready()) m.run(); } catch (_) {} }, 450);
      document.querySelectorAll(m.sel).forEach((el) => {
        if (el.dataset.ilLive) return;
        el.dataset.ilLive = "1";
        el.addEventListener("input", handler);
        el.addEventListener("change", handler);
      });
    });
  }
  document.addEventListener("keydown", (e) => {
    if (e.key !== "/" || e.ctrlKey || e.metaKey || e.altKey) return;
    const t = e.target;
    if (t && (t.tagName === "INPUT" || t.tagName === "TEXTAREA" || t.tagName === "SELECT" || t.isContentEditable)) return;
    const input = document.getElementById("main-ticker");
    if (!input) return;
    e.preventDefault();
    if (window.openSection) window.openSection("analyze");
    input.focus(); input.select();
  });
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", wire); else wire();
  setInterval(wire, 4000); // pro-gated sections re-render their bodies; re-wire quietly
}());

/* ── Dock chart controls inside the Price Chart card (desktop) ────────────────
   The page chrome keeps a single tab bar; chart type, overlays, ranges, and
   scale toggles live where they act — in the chart card, TradingView-style. */
(function () {
  function dock() {
    if (window.innerWidth < 961) return;
    const card = document.querySelector("#body-analyze .dash-main > .chart-wrap");
    const toolbar = document.getElementById("app-chart-toolbar");
    const strip = document.getElementById("app-tf-strip");
    if (!card || !toolbar || !strip || toolbar.dataset.docked) return;
    toolbar.dataset.docked = "1";
    const host = document.createElement("div");
    host.id = "il-chart-dock";
    const header = card.querySelector(".chart-header");
    if (header) header.after(host); else card.prepend(host);
    host.append(toolbar, strip);
    document.body.classList.add("il-controls-docked");
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", dock); else dock();
}());

/* ── Progressive disclosure: five core tabs, the rest under "More" ────────────
   Beginners see Chart, Financials, Value, Compare, Screener. Everything else
   lives in a More menu; when one of those sections is active its name shows
   on the More button. Desktop only. */
(function () {
  const CORE = new Set(["analyze", "financials", "dcf", "compare", "screener"]);
  function setup() {
    if (window.innerWidth < 961) return;
    const bar = document.getElementById("mobile-sec-tabs");
    if (!bar || bar.dataset.ilMore) return;
    const extras = [...bar.querySelectorAll(":scope > .mst-btn")].filter(b => !CORE.has(b.dataset.sec));
    if (extras.length < 2) return;
    bar.dataset.ilMore = "1";
    const wrap = document.createElement("div"); wrap.className = "il-more-tabs";
    const btn = document.createElement("button");
    btn.type = "button"; btn.className = "mst-btn il-more-btn";
    btn.setAttribute("aria-haspopup", "true"); btn.setAttribute("aria-expanded", "false");
    btn.innerHTML = `<span>More</span> <i class="ti ti-chevron-down" aria-hidden="true"></i>`;
    const menu = document.createElement("div"); menu.className = "il-more-menu"; menu.setAttribute("role", "menu");
    extras.forEach(b => menu.appendChild(b));
    wrap.append(btn, menu); bar.appendChild(wrap);
    btn.addEventListener("click", (e) => {
      e.stopPropagation();
      const open = wrap.classList.toggle("open");
      btn.setAttribute("aria-expanded", String(open));
    });
    document.addEventListener("click", () => { wrap.classList.remove("open"); btn.setAttribute("aria-expanded", "false"); });
    menu.addEventListener("click", () => { wrap.classList.remove("open"); });
    const label = btn.querySelector("span");
    const sync = () => {
      const active = menu.querySelector(".mst-btn.active");
      btn.classList.toggle("active", Boolean(active));
      label.textContent = active ? active.textContent : "More";
    };
    new MutationObserver(sync).observe(bar, { subtree: true, attributes: true, attributeFilter: ["class"] });
    sync();
  }
  // workspace shell injects its own tab shortly after load — retry briefly
  function init() { setup(); setTimeout(setup, 600); setTimeout(setup, 2000); }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init); else init();
}());

/* ── Source provenance notes: every data tab names its providers ─────────────── */
(function () {
  const SOURCES = {
    financials:    "SEC EDGAR XBRL (statements) · Finnhub (ratios)",
    advmetrics:    "Finnhub fundamentals",
    earnings:      "Finnhub EPS estimates & surprises",
    secfilings:    "SEC EDGAR — links open official filings",
    institutional: "Finnhub ownership · FINRA OTC weekly data",
    screener:      "Finnhub + exchange reference data",
    compare:       "Yahoo Finance charts · Finnhub fundamentals",
  };
  function inject() {
    Object.entries(SOURCES).forEach(([sec, label]) => {
      const body = document.getElementById("body-" + sec);
      if (!body || body.querySelector(".il-source-note")) return;
      const note = document.createElement("div");
      note.className = "il-source-note";
      note.innerHTML = `<i class="ti ti-database" aria-hidden="true"></i> Sources: ${label} · <a href="/data-sources">methodology</a>`;
      body.appendChild(note);
    });
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", inject); else inject();
  setInterval(inject, 5000); // pro-gated bodies re-render; re-add quietly
}());

/* ── Expanded-chart power features ────────────────────────────────────────────
   1. Wheel-zoom-out at full view loads older history (1M → 3M → 6M → …) so you
      never have to leave the chart to see more months.
   2. The expanded price chart gets the FULL control set on one screen:
      chart type, overlays, and every range — wired to the same state as the
      inline controls, and the modal re-renders automatically on any change. */
(function () {
  const RANGES = [["1d","1D"],["5d","5D"],["1mo","1M"],["3mo","3M"],["6mo","6M"],["ytd","YTD"],["1y","1Y"],["2y","2Y"],["5y","5Y"],["max","Max"]];
  const TYPES  = [["candle","Candle","ti-chart-candle"],["line","Line","ti-chart-line"],["area","Area","ti-chart-area"]];
  const INDS   = [["ma50","50D Avg"],["ma200","200D Avg"],["bb","Bands"]];

  function renderControls(chartId) {
    const modal = document.getElementById("chart-expand-modal");
    if (!modal) return;
    let host = document.getElementById("il-cex-controls");
    if (!host) {
      host = document.createElement("div");
      host.id = "il-cex-controls";
      modal.querySelector(".cex-toolbar")?.before(host);
    }
    if (chartId !== "price-chart") { host.innerHTML = ""; host.style.display = "none"; return; }
    const S = window.IL_STATE || {};
    const inds = S.inds || {};
    const btn = (attr, on, label, icon) =>
      `<button type="button" class="il-cexc${on ? " on" : ""}" ${attr}>${icon ? `<i class="ti ${icon}" aria-hidden="true"></i> ` : ""}${label}</button>`;
    host.style.display = "";
    host.innerHTML =
      TYPES.map(([t, l, i]) => btn(`data-cexc-type="${t}"`, (S.chartType || "candle") === t, l, i)).join("") +
      `<span class="il-cexc-sep"></span>` +
      INDS.map(([k, l]) => btn(`data-cexc-ind="${k}"`, Boolean(inds[k]), l)).join("") +
      `<span class="il-cexc-sep"></span>` +
      RANGES.map(([r, l]) => btn(`data-cexc-range="${r}"`, (S.range || "1y") === r, l)).join("");
    host.querySelectorAll("[data-cexc-type]").forEach(b => b.onclick = () => {
      window.setChartType?.(b.dataset.cexcType, document.getElementById("ct-" + b.dataset.cexcType));
    });
    host.querySelectorAll("[data-cexc-ind]").forEach(b => b.onclick = () => {
      const k = b.dataset.cexcInd;
      window.toggleInd?.(document.querySelector(`[data-ind=${k}]`), k);
    });
    host.querySelectorAll("[data-cexc-range]").forEach(b => b.onclick = () => {
      const r = b.dataset.cexcRange;
      const pill = [...document.querySelectorAll(".tf-pill")].find(el => (el.getAttribute("onclick") || "").includes(`'${r}'`));
      window.changeRange?.(r, pill || null);
    });
  }

  function install() {
    if (window.__ilCexWrapped || typeof window.expandChart !== "function") return;
    window.__ilCexWrapped = true;

    const _expand = window.expandChart;
    window.expandChart = function (chartId, title) {
      _expand(chartId, title);
      renderControls(chartId);
      attachWheelLoader();
    };

    // any price-chart rebuild (type/overlay/range/new data) refreshes the modal
    const _build = window.buildPriceChart;
    if (typeof _build === "function") {
      window.buildPriceChart = function () {
        const out = _build.apply(this, arguments);
        const modal = document.getElementById("chart-expand-modal");
        if (modal?.classList.contains("open") && modal.dataset.chartId === "price-chart") {
          setTimeout(() => window.expandChart("price-chart", modal.dataset.chartTitle || "Price Chart"), 30);
        }
        return out;
      };
    }
  }

  let wheelCooldown = 0;
  function attachWheelLoader() {
    const canvas = document.getElementById("chart-expanded");
    if (!canvas || canvas.dataset.ilWheel) return;
    canvas.dataset.ilWheel = "1";
    canvas.addEventListener("wheel", (e) => {
      if (e.deltaY <= 0) return; // only zoom-out gestures
      const chart = (window.Chart && window.Chart.getChart) ? window.Chart.getChart(canvas) : null;
      if (!chart || !window.chartAtFullHistory || !window.chartAtFullHistory(chart)) return;
      e.preventDefault(); e.stopPropagation();
      const now = Date.now();
      if (now - wheelCooldown < 900) return;
      wheelCooldown = now;
      window.zoomExpandedChart?.(0.8); // loads the next-larger range for the price chart
    }, { passive: false, capture: true });
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", install); else install();
  setTimeout(install, 800);
}());
