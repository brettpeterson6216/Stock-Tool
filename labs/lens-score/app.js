(function () {
  "use strict";

  const engine = window.LensScoreEngine;
  if (!engine) throw new Error("LensScore engine failed to load.");

  const ASSUMPTIONS = [
    { key: "revenueGrowth", label: "Revenue growth", min: -10, max: 35, step: 1, format: "percent", note: "Normalized forward growth assumption" },
    { key: "epsGrowth", label: "EPS growth", min: -20, max: 45, step: 1, format: "percent", note: "Per-share earnings trajectory" },
    { key: "fcfMargin", label: "Free-cash-flow margin", min: -5, max: 45, step: 1, format: "percent", note: "Cash generated per revenue dollar" },
    { key: "roic", label: "Return on invested capital", min: -5, max: 50, step: 1, format: "percent", note: "Capital efficiency" },
    { key: "netDebtEbitda", label: "Net debt / EBITDA", min: -2, max: 7, step: 0.1, format: "multiple", note: "Negative values indicate net cash" },
    { key: "interestCoverage", label: "Interest coverage", min: 0, max: 40, step: 1, format: "multiple", note: "Operating earnings divided by interest" },
    { key: "dilution", label: "Annual dilution", min: -5, max: 10, step: 0.5, format: "percent", note: "Negative values represent buybacks" },
    { key: "forwardPE", label: "Reference earnings multiple", min: 5, max: 90, step: 1, format: "multiple", note: "Price divided by the disclosed EPS basis" },
    { key: "dcfUpside", label: "Modeled value gap", min: -50, max: 100, step: 1, format: "percent", note: "Price versus the normalized Implied Lens earnings-value model" },
    { key: "impliedGrowthGap", label: "Expectations gap", min: -10, max: 25, step: 1, format: "percent", note: "Implied growth minus supported growth" },
    { key: "bearDownside", label: "Bear-case downside", min: -70, max: -2, step: 1, format: "percent", note: "Modeled downside from the current price" },
  ];

  const state = {
    ticker: "AAPL",
    bars: [],
    meta: {},
    fundamentals: {},
    reportedFundamentals: {},
    fundamentalFields: {},
    fundamentalModel: {},
    provenance: null,
    result: null,
    baseline: null,
    chartPreset: "toolkit",
    source: "Waiting for live data",
    entryPrice: null,
    chartPoints: [],
  };

  const $ = selector => document.querySelector(selector);
  /* Bind only if the element is there. bindEvents() wires the whole page in one
     run, so a single $("#missing").addEventListener threw and every listener
     after it - the ticker form, the chart presets, the methodology dialog, the
     assumptions, the save button, the resize redraw - was silently never
     attached. One absent node must not be able to take the page down. */
  const on = (selector, type, handler, opts) => {
    const node = typeof selector === "string" ? $(selector) : selector;
    if (node) node.addEventListener(type, handler, opts);
    return node;
  };
  const $$ = selector => Array.from(document.querySelectorAll(selector));
  let activeRequestController = null;
  const finite = value => value !== null && value !== undefined && value !== "" && Number.isFinite(Number(value));
  const money = value => finite(value)
    ? new Intl.NumberFormat("en-US", { style: "currency", currency: "USD", maximumFractionDigits: 2 }).format(value)
    : "—";
  const pct = (value, places = 1) => finite(value) ? `${(Number(value) * 100).toFixed(places)}%` : "—";
  const compact = value => finite(value)
    ? new Intl.NumberFormat("en-US", { notation: "compact", maximumFractionDigits: 1 }).format(value)
    : "—";
  const escapeText = value => String(value ?? "");
  const normalizeTickerInput = value => String(value || "")
    .trim()
    .toUpperCase()
    .replace("/", "-")
    .replace(/[^A-Z0-9.^-]/g, "")
    .slice(0, 15);
  const SESSION_CACHE_PREFIX = "il:lens-score:v3:";
  const SESSION_CACHE_INDEX = `${SESSION_CACHE_PREFIX}index`;
  const SESSION_CACHE_TTL_MS = 15 * 60 * 1000;

  function decodeBars(rows) {
    return (rows || []).map(row => Array.isArray(row)
      ? { time: row[0], open: row[1], high: row[2], low: row[3], close: row[4], volume: row[5] }
      : row
    );
  }

  function readSessionPayload(ticker) {
    try {
      const cached = JSON.parse(window.sessionStorage.getItem(`${SESSION_CACHE_PREFIX}${ticker}`) || "null");
      if (!cached || cached.ticker !== ticker || Date.now() - cached.cachedAt > SESSION_CACHE_TTL_MS) return null;
      return cached.payload || null;
    } catch (_) {
      return null;
    }
  }

  function writeSessionPayload(ticker, payload) {
    try {
      const keys = JSON.parse(window.sessionStorage.getItem(SESSION_CACHE_INDEX) || "[]")
        .filter(key => key !== ticker);
      keys.unshift(ticker);
      keys.slice(5).forEach(key => window.sessionStorage.removeItem(`${SESSION_CACHE_PREFIX}${key}`));
      window.sessionStorage.setItem(SESSION_CACHE_INDEX, JSON.stringify(keys.slice(0, 5)));
      window.sessionStorage.setItem(`${SESSION_CACHE_PREFIX}${ticker}`, JSON.stringify({
        ticker,
        cachedAt: Date.now(),
        payload,
      }));
    } catch (_) {
      // Session caching is a speed enhancement, never a data requirement.
    }
  }

  function updateResearchLinks() {
    $$("[data-research-section]").forEach(link => {
      const params = new URLSearchParams({
        view: "tool",
        section: link.dataset.researchSection,
        symbol: state.ticker,
      });
      link.href = `/?${params.toString()}`;
    });
  }

  function applySavedTheme() {
    // Dark is the product default; light applies only when explicitly chosen.
    const saved = window.localStorage.getItem("il-theme");
    document.documentElement.dataset.theme = saved === "light" ? "light" : "dark";
  }

  function toggleTheme() {
    const next = document.documentElement.dataset.theme === "light" ? "dark" : "light";
    document.documentElement.dataset.theme = next;
    window.localStorage.setItem("il-theme", next);
    drawChart();
  }

  function chartColors() {
    const light = document.documentElement.dataset.theme === "light";
    const styles = getComputedStyle(document.documentElement);
    const token = (name, fallback) => styles.getPropertyValue(name).trim() || fallback;
    return {
      price: light ? "#27342c" : "#dce5dc",
      grid: light ? "rgba(31,41,34,.10)" : "rgba(229,237,227,.07)",
      axis: light ? "#667168" : "#7e897f",
      baseline: light ? "rgba(31,41,34,.16)" : "rgba(229,237,227,.12)",
      green: token("--green", light ? "#087a35" : "#00e676"),
      red: token("--red", light ? "#c6283d" : "#ff4d5a"),
      gold: light ? "#9b6a17" : "#d2a34c",
      blue: light ? "#315f9d" : "#7ca8df",
      purple: light ? "#704898" : "#b17bd4",
    };
  }

  function hydratePayload(payload, refreshing) {
    if (payload.provenance?.synthetic !== false) throw new Error("Unverified or synthetic data was rejected.");
    state.bars = engine.normalizeBars(decodeBars(payload.market?.bars || []));
    if (state.bars.length < 60) throw new Error("Insufficient live price history.");
    state.meta = {
      ...(payload.market?.meta || {}),
      longName: payload.company || payload.market?.meta?.name || state.ticker,
    };
    state.source = (payload.provenance?.sources || [])
      .filter(source => source.status === "available")
      .map(source => source.name)
      .join(" + ") || "Reported provider data";
    state.provenance = payload.provenance || null;
    state.fundamentals = { ...(payload.fundamentals?.values || {}) };
    state.reportedFundamentals = { ...state.fundamentals };
    state.fundamentalFields = { ...(payload.fundamentals?.fields || {}) };
    state.fundamentalModel = {
      referenceEps: payload.fundamentals?.referenceEps ?? null,
      referenceEpsBasis: payload.fundamentals?.referenceEpsBasis || "Unavailable",
      referenceEpsAsOf: payload.fundamentals?.referenceEpsAsOf || null,
      referenceEpsQuarters: payload.fundamentals?.referenceEpsQuarters || [],
    };

    const latest = state.bars[state.bars.length - 1];
    state.entryPrice = latest.close;
    state.fundamentals = normalizePresetForPrice(state.fundamentals, latest.close);
    state.reportedFundamentals = { ...state.fundamentals };
    calculate(true);
    renderAssumptions();
    if (state.result?.status === "graded") configureEntryControls();

    const retrieved = formatAsOf(payload.provenance?.retrievedAt);
    const marketAsOf = formatAsOf(payload.provenance?.asOf?.market);
    const fundamentalsAsOf = formatAsOf(payload.provenance?.asOf?.fundamentals);
    const companyEvidence = payload.provenance?.freshness?.fundamentals?.basis === "provider-snapshot"
      ? `provider metric snapshot retrieved ${fundamentalsAsOf} (reporting-period date unavailable)`
      : payload.provenance?.asOf?.fundamentals
        ? `company evidence through ${fundamentalsAsOf}`
        : "company evidence unavailable";
    const warningList = Array.isArray(payload.provenance?.warnings)
      ? payload.provenance.warnings
      : [];
    const warnings = warningList.length ? ` ${warningList.join(" ")}` : "";
    const prefix = refreshing
      ? `Showing verified session evidence retrieved ${retrieved} while live providers refresh.`
      : `Retrieved ${retrieved} from ${state.source}.`;
    setNotice(
      `${prefix} Market through ${marketAsOf}; ${companyEvidence}.${warnings}`,
      refreshing || warningList.length ? "warn" : "good"
    );
  }

  function alphaColor(hex, alpha) {
    const value = String(hex || "").replace("#", "");
    if (!/^[0-9a-f]{6}$/i.test(value)) return hex;
    const numeric = Number.parseInt(value, 16);
    return `rgba(${(numeric >> 16) & 255},${(numeric >> 8) & 255},${numeric & 255},${alpha})`;
  }

  async function loadTicker(ticker) {
    const requestedTicker = normalizeTickerInput(ticker) || "AAPL";
    if (activeRequestController) activeRequestController.abort();
    const requestController = new AbortController();
    activeRequestController = requestController;
    state.ticker = requestedTicker;
    $("#ticker-input").value = state.ticker;
    $("#lab-main").setAttribute("aria-busy", "true");
    state.chartPoints = [];
    state.bars = [];
    state.meta = { longName: state.ticker };
    state.fundamentals = {};
    state.reportedFundamentals = {};
    state.fundamentalFields = {};
    state.fundamentalModel = {};
    state.provenance = null;
    state.result = null;
    state.baseline = null;
    updateResearchLinks();
    $("#chart-tooltip").hidden = true;
    $("#chart-tooltip").textContent = "";
    let hasUsableCache = false;
    const sessionPayload = readSessionPayload(state.ticker);
    if (sessionPayload) {
      try {
        hydratePayload(sessionPayload, true);
        hasUsableCache = true;
      } catch (_) {
        hasUsableCache = false;
      }
    }
    if (!hasUsableCache) {
      renderUnavailable("Loading current market and company evidence…");
      setNotice("Loading reported company facts, earnings expectations and market history…", "");
    }
    try {
      const response = await fetch(`/api/lens-score/${encodeURIComponent(state.ticker)}?preview=1&compact=1`, {
        credentials: "same-origin",
        cache: "default",
        signal: requestController.signal,
      });
      const payload = await response.json().catch(() => ({}));
      if (requestController.signal.aborted || state.ticker !== requestedTicker) return;
      if (!response.ok) throw new Error(payload.error || `Research endpoint returned ${response.status}`);
      hydratePayload(payload, false);
      writeSessionPayload(state.ticker, payload);
    } catch (error) {
      if (error?.name === "AbortError") return;
      if (hasUsableCache) {
        setNotice(
          `Live refresh failed: ${error.message} Showing the verified session evidence above; no synthetic replacement was used.`,
          "warn"
        );
        $("#lab-main").setAttribute("aria-busy", "false");
        if (activeRequestController === requestController) activeRequestController = null;
        return;
      }
      state.bars = [];
      state.fundamentals = {};
      state.reportedFundamentals = {};
      state.fundamentalFields = {};
      state.fundamentalModel = {};
      state.result = null;
      state.baseline = null;
      state.meta = { longName: state.ticker };
      setNotice(
        `${error.message} LensScore is Not Rated; no synthetic replacement was used.`,
        "warn"
      );
      renderUnavailable();
      $("#lab-main").setAttribute("aria-busy", "false");
      if (activeRequestController === requestController) activeRequestController = null;
      return;
    }
    $("#lab-main").setAttribute("aria-busy", "false");
    if (activeRequestController === requestController) activeRequestController = null;
  }

  function formatAsOf(value) {
    if (!value) return "unavailable";
    if (/^\d{4}-\d{2}-\d{2}$/.test(String(value))) {
      return new Date(`${value}T12:00:00Z`).toLocaleDateString("en-US", {
        dateStyle: "medium",
        timeZone: "UTC",
      });
    }
    const date = new Date(value);
    return Number.isNaN(date.getTime())
      ? String(value)
      : date.toLocaleString("en-US", { dateStyle: "medium", timeStyle: "short" });
  }

  function renderUnavailable(reason = "Required live evidence is unavailable.") {
    $("#company-name").textContent = state.meta.longName || state.ticker;
    $("#company-ticker").textContent = state.ticker;
    $("#chart-ticker").textContent = state.ticker;
    $("#market-price").textContent = "—";
    $("#market-change").textContent = "Current quote unavailable";
    $("#market-change").style.color = "";
    ["#score-value", "#setup-score", "#value-score"].forEach(selector => {
      const element = $(selector);
      if (element) element.textContent = "—";
    });
    $("#score-label").textContent = "Not Rated";
    $("#score-summary").textContent = reason;
    $("#score-confidence").textContent = "Low";
    $("#model-version").textContent = engine.VERSION;
    $("#setup-label").textContent = "Not Rated";
    $("#value-label").textContent = "Not Rated";
    $("#golden-lens-signal").dataset.active = "false";
    $("#golden-lens-label").textContent = "Golden Lens unavailable";
    $("#golden-lens-reason").textContent = "Both independent lenses must have sufficient current evidence.";
    $("#score-ring").dataset.tone = "unknown";
    $("#score-ring").style.setProperty("--score-progress", 0);
    $("#score-marker").style.left = "0%";
    $("#as-of").textContent = "—";
    $("#chart-source").textContent = "Source: waiting for verified data";
    $("#buy-zone").textContent = "—";
    $("#buy-zone-note").textContent = "A current price series is required.";
    $("#invalidation-price").textContent = "—";
    $("#implied-growth").textContent = "—";
    $("#supported-growth").textContent = "—";
    $("#growth-gap").textContent = "—";
    $("#dcf-range").textContent = "Unavailable";
    $("#valuation-chip").textContent = "Not Rated";
    $("#alignment-copy").textContent = "Both lenses must be rated before LensScore can combine them.";
    $("#alignment-visual").replaceChildren();
    $("#trend-regime-heading").textContent = "Trend unavailable";
    $("#trend-regime-value").textContent = "—";
    $("#trend-agreement").textContent = "—";
    $("#trend-extension").textContent = "—";
    $("#trend-regime-votes").replaceChildren();
    $("#trend-regime-copy").textContent = "A current price series is required.";
    $("#coverage-value").textContent = "—";
    $("#history-value").textContent = "—";
    $("#cap-value").textContent = "—";
    $("#guardrail-list").replaceChildren();
    $("#strength-list").replaceChildren();
    $("#concern-list").replaceChildren();
    ["#support-zones", "#resistance-zones", "#technical-grid", "#indicator-table", "#driver-waterfall"].forEach(selector => {
      const element = $(selector);
      if (element) element.replaceChildren();
    });
    $("#chart-legend").replaceChildren();
    const canvas = $("#price-chart");
    if (canvas) {
      const context = canvas.getContext("2d");
      context?.clearRect(0, 0, canvas.width, canvas.height);
    }
    state.chartPoints = [];
  }

  function renderPartial(result) {
    const latest = state.bars[state.bars.length - 1];
    const previous = state.bars[state.bars.length - 2] || latest;
    const change = latest && previous ? latest.close / previous.close - 1 : null;
    $("#company-name").textContent = state.meta.longName || state.ticker;
    $("#company-ticker").textContent = state.ticker;
    $("#chart-ticker").textContent = state.ticker;
    $("#market-price").textContent = latest ? money(latest.close) : "—";
    $("#market-change").textContent = finite(change)
      ? `${change >= 0 ? "+" : ""}${pct(change)} last session`
      : "Current change unavailable";
    $("#market-change").style.color = finite(change)
      ? change >= 0 ? "var(--green)" : "var(--red)"
      : "";
    $("#score-value").textContent = "—";
    $("#score-label").textContent = "Combined score unavailable";
    $("#score-summary").textContent = result.reason;
    $("#score-confidence").textContent = "Low";
    $("#model-version").textContent = result.version;
    $("#as-of").textContent = latest
      ? new Date(latest.time * 1000).toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" })
      : "—";
    $("#score-ring").dataset.tone = "unknown";
    $("#score-ring").style.setProperty("--score-progress", 0);
    $("#score-marker").style.left = "0%";
    $("#chart-source").textContent = `Source: ${state.source}`;

    const setup = result.lenses?.setup;
    $("#setup-score").textContent = finite(setup?.score) ? setup.score.toFixed(1) : "—";
    $("#setup-label").textContent = setup?.label || "Not Rated";
    $("#value-score").textContent = "—";
    $("#value-label").textContent = "Insufficient company evidence";
    $("#golden-lens-signal").dataset.active = "false";
    $("#golden-lens-label").textContent = "Golden Lens unavailable";
    $("#golden-lens-reason").textContent = "LensSetup remains usable, but LensValue needs more current reported company evidence.";

    fillList("#strength-list", [], "LensSetup is available in Chart & zones.");
    fillList("#concern-list", [result.reason], "No company-data limitation was reported.");
    const support = result.technical?.zones?.support?.[0];
    if (support) {
      $("#buy-zone").textContent = `${money(support.lower)}–${money(support.upper)}`;
      $("#buy-zone-note").textContent = `${support.touches} confirmed reaction${support.touches === 1 ? "" : "s"} · ${Math.round(support.strength)}/100 zone strength`;
      $("#invalidation-price").textContent = money(support.lower - (result.technical.indicators.atr || 0));
    } else {
      $("#buy-zone").textContent = "No confirmed zone";
      $("#buy-zone-note").textContent = "No qualified nearby support cluster was found.";
      $("#invalidation-price").textContent = "—";
    }
    $("#implied-growth").textContent = "—";
    $("#supported-growth").textContent = "—";
    $("#growth-gap").textContent = "—";
    $("#dcf-range").textContent = "Unavailable";
    $("#valuation-chip").textContent = "Not Rated";
    $("#alignment-copy").textContent = "LensSetup is available independently. LensValue and the combined LensScore are withheld until company evidence is sufficient.";
    $("#coverage-value").textContent = `${result.dataCoverage?.fundamentals?.available || 0}/${result.dataCoverage?.fundamentals?.total || 7} company`;
    $("#history-value").textContent = `${result.technical?.bars?.length || 0} bars`;
    $("#cap-value").textContent = "Combined score withheld";
    $("#driver-waterfall").replaceChildren();

    if (result.technical?.status === "ok") {
      renderTiming(result);
      renderTrendRegime(result);
      renderZones(result);
      renderSetupComponents(result);
      renderTechnicalMetrics(result);
      renderIndicatorTable(result);
      drawChart();
    }
  }

  function normalizePresetForPrice(preset, price) {
    return {
      ...preset,
      _marketPrice: price,
      _baseForwardPE: preset.forwardPE,
      _baseDcfUpside: preset.dcfUpside,
      _baseBearDownside: preset.bearDownside,
      _baseImpliedGrowthGap: preset.impliedGrowthGap,
    };
  }

  function calculate(setBaseline = false) {
    state.result = engine.scoreLens({
      bars: state.bars,
      fundamentals: state.fundamentals,
      metadata: { ticker: state.ticker, source: state.source },
    });
    if (setBaseline) state.baseline = state.result;
    if (state.result.status !== "graded") {
      if (state.result.technical?.status === "ok") renderPartial(state.result);
      else renderUnavailable(state.result.reason);
      return;
    }
    renderAll();
  }

  function setNotice(message, tone) {
    const notice = $("#data-notice");
    notice.textContent = message;
    notice.className = `notice${tone ? ` ${tone}` : ""}`;
  }

  function componentLabel(key) {
    return {
      fundamentals: "Company quality",
      valuation: "Price & value",
      technical: "Chart setup",
      momentum: "Momentum",
      risk: "Risk",
    }[key] || key;
  }

  function scoreSummary(result) {
    const { setup, value, goldenLens } = result.lenses;
    if (goldenLens.active) return "Golden Lens: long-term value and tactical entry quality are exceptionally aligned.";
    if (value.score >= 8.5 && setup.score < 7) {
      return "Exceptional long-term value, but the chart has not yet confirmed a high-quality tactical entry.";
    }
    if (setup.score >= 8 && value.score < 7) {
      return "A strong tactical setup, but the long-term valuation and business case are not strong enough yet.";
    }
    if (value.score >= 7 && setup.score >= 7) {
      return "Both independent lenses are constructive, producing a broadly aligned buyability result.";
    }
    if (value.score >= setup.score) {
      return "The long-term opportunity is stronger than the current tactical entry setup.";
    }
    return "The chart setup is stronger than the current long-term value case.";
  }

  function renderAll() {
    const result = state.result;
    if (!result || result.status !== "graded") return;
    const latest = state.bars[state.bars.length - 1];
    const previous = state.bars[state.bars.length - 2] || latest;
    const change = latest.close / previous.close - 1;

    $("#company-name").textContent = state.meta.longName || state.fundamentals.name || state.ticker;
    $("#company-ticker").textContent = state.ticker;
    $("#chart-ticker").textContent = state.ticker;
    $("#market-price").textContent = money(result.price);
    $("#market-change").textContent = `${change >= 0 ? "+" : ""}${pct(change)} last session`;
    $("#market-change").style.color = change >= 0 ? "var(--green)" : "var(--red)";
    $("#score-value").textContent = result.score.toFixed(1);
    $("#score-label").textContent = result.label;
    $("#score-summary").textContent = scoreSummary(result);
    $("#score-confidence").textContent = result.confidence;
    $("#model-version").textContent = result.version;
    $("#as-of").textContent = new Date(latest.time * 1000).toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" });
    $("#score-ring").dataset.tone = result.tone;
    $("#score-ring").style.setProperty("--score-progress", result.score * 10);
    $("#score-marker").style.left = `${result.score * 10}%`;
    $("#chart-source").textContent = `Source: ${state.source}`;
    renderLenses(result);
    renderDecision(result);
    renderExpectations(result);
    renderAlignment(result);
    renderValueComponents(result);
    renderTiming(result);
    renderTrendRegime(result);
    renderZones(result);
    renderSetupComponents(result);
    renderTechnicalMetrics(result);
    renderDrivers(result);
    renderIndicatorTable(result);
    renderScenario(result);
    drawChart();
  }

  function renderLenses(result) {
    const { setup, value, goldenLens } = result.lenses;
    $("#setup-score").textContent = setup.score.toFixed(1);
    $("#setup-label").textContent = setup.label;
    $("#value-score").textContent = value.score.toFixed(1);
    $("#value-page-score").textContent = value.score.toFixed(1);
    $("#value-label").textContent = value.label;
    const signal = $("#golden-lens-signal");
    signal.dataset.active = goldenLens.active ? "true" : "false";
    $("#golden-lens-label").textContent = goldenLens.active
      ? "Golden Lens signal"
      : "Golden Lens not active";
    $("#golden-lens-reason").textContent = goldenLens.reason;
  }

  function renderValueComponents(result) {
    const detail = result.componentDetails;
    const cards = [
      ["Business quality", detail.fundamentals.score, "Growth, cash generation, capital efficiency and leverage"],
      ["Valuation", detail.valuation.score, "Modeled upside, earnings multiple and expectations gap"],
      ["Downside resilience", detail.risk.score, "Balance sheet, dilution and bear-case exposure"],
      ["Expectations", detail.valuation.parts.expectationsGap, "How achievable the growth embedded in price appears"],
      ["Capital allocation", detail.fundamentals.parts.dilution, "Share issuance, buybacks and per-share discipline"],
    ];
    $("#value-component-grid").replaceChildren(...cards.map(([label, score, note]) => {
      const card = document.createElement("article");
      card.className = "value-component-card panel";
      const head = document.createElement("div");
      const name = document.createElement("span");
      name.textContent = label;
      const value = document.createElement("strong");
      value.textContent = finite(score) ? `${(Number(score) / 10).toFixed(1)} / 10` : "Not rated";
      head.append(name, value);
      const track = document.createElement("i");
      track.style.setProperty("--value-progress", `${finite(score) ? Math.max(0, Math.min(100, Number(score))) : 0}%`);
      const copy = document.createElement("p");
      copy.textContent = note;
      card.append(head, track, copy);
      return card;
    }));
  }

  function fillList(selector, items, emptyMessage) {
    const list = $(selector);
    list.replaceChildren();
    const values = items.length ? items : [emptyMessage];
    values.slice(0, 3).forEach(item => {
      const li = document.createElement("li");
      li.textContent = item;
      list.append(li);
    });
  }

  function renderDecision(result) {
    fillList("#strength-list", result.strengths, "No strong positive contributor is currently confirmed.");
    fillList("#concern-list", result.concerns, "No material concern is currently triggered.");
    const support = result.technical.zones.support[0];
    if (support) {
      $("#buy-zone").textContent = `${money(support.lower)}–${money(support.upper)}`;
      $("#buy-zone-note").textContent = `${support.touches} confirmed reaction${support.touches === 1 ? "" : "s"} · ${Math.round(support.strength)}/100 zone strength`;
      const invalidation = support.lower - (result.technical.indicators.atr || 0);
      $("#invalidation-price").textContent = money(invalidation);
    } else {
      $("#buy-zone").textContent = "No confirmed zone";
      $("#buy-zone-note").textContent = "The current history does not produce a qualified nearby support cluster.";
      $("#invalidation-price").textContent = "—";
    }
  }

  function renderExpectations(result) {
    const implied = finite(state.fundamentals.revenueGrowth) && finite(state.fundamentals.impliedGrowthGap)
      ? Number(state.fundamentals.revenueGrowth) + Number(state.fundamentals.impliedGrowthGap)
      : null;
    const current = result.price;
    const baseValue = finite(state.fundamentals.dcfUpside)
      ? current * (1 + Number(state.fundamentals.dcfUpside))
      : null;
    const bearValue = finite(state.fundamentals.bearDownside)
      ? current * (1 + Number(state.fundamentals.bearDownside))
      : null;
    $("#implied-growth").textContent = pct(implied);
    $("#supported-growth").textContent = pct(state.fundamentals.revenueGrowth);
    $("#growth-gap").textContent = pct(state.fundamentals.impliedGrowthGap);
    $("#dcf-range").textContent = finite(bearValue) && finite(baseValue)
      ? `${money(bearValue)}–${money(baseValue)}`
      : "Unavailable";
    $("#valuation-chip").textContent = `${(result.components.valuation / 10).toFixed(1)} / 10`;
  }

  function renderAlignment(result) {
    const visual = $("#alignment-visual");
    visual.replaceChildren();
    const { setup, value, goldenLens } = result.lenses;
    const lensScores = [value.score, setup.score];
    lensScores.forEach(score => {
      const block = document.createElement("span");
      if (score >= 7) block.className = "on";
      visual.append(block);
    });
    $("#alignment-copy").textContent = goldenLens.active
      ? "Golden Lens is active: both independent lenses are exceptionally strong."
      : value.score >= 7 && setup.score >= 7
        ? "LensValue and LensSetup are both constructive, but at least one remains below Golden Lens strength."
        : value.score >= 7
          ? "The long-term case is constructive; wait for stronger tactical confirmation if timing matters."
          : setup.score >= 7
            ? "The tactical setup is constructive; the long-term value case remains the limiting lens."
            : "Neither independent lens currently shows a strong advantage.";
  }

  function renderZoneRows(containerSelector, zones, type) {
    const container = $(containerSelector);
    container.replaceChildren();
    if (!zones.length) {
      const empty = document.createElement("p");
      empty.className = "muted";
      empty.textContent = `No confirmed ${type} zone nearby.`;
      container.append(empty);
      return;
    }
    zones.forEach(zone => {
      const row = document.createElement("div");
      row.className = "zone-row";
      const left = document.createElement("div");
      const price = document.createElement("strong");
      price.textContent = `${money(zone.lower)}–${money(zone.upper)}`;
      const info = document.createElement("span");
      info.textContent = `${zone.touches} touches · ${Math.abs(zone.distancePct).toFixed(1)}% ${zone.distancePct < 0 ? "below" : "above"}`;
      left.append(price, info);
      const right = document.createElement("div");
      const strength = document.createElement("small");
      strength.textContent = `${Math.round(zone.strength)}/100 strength`;
      const dots = document.createElement("div");
      dots.className = "strength-dots";
      const active = Math.max(1, Math.ceil(zone.strength / 20));
      for (let i = 0; i < 5; i += 1) {
        const dot = document.createElement("i");
        if (i < active) dot.className = "on";
        dots.append(dot);
      }
      right.append(strength, dots);
      row.append(left, right);
      container.append(row);
    });
  }

  function renderZones(result) {
    renderZoneRows("#support-zones", result.technical.zones.support, "support");
    renderZoneRows("#resistance-zones", result.technical.zones.resistance, "resistance");
  }

  function renderTiming(result) {
    const timing = result.technical.timing;
    const score = Number(timing.timingScore);
    $("#timing-heading").textContent = timing.label;
    $("#timing-value").textContent = Number.isFinite(score) ? `${score.toFixed(1)} / 10` : "—";
    $("#timing-marker").style.left = Number.isFinite(score)
      ? `${Math.max(0, Math.min(100, score * 10))}%`
      : "50%";
    $("#timing-pressure").textContent = Number.isFinite(Number(timing.pressure))
      ? `${Number(timing.pressure) > 0 ? "+" : ""}${Number(timing.pressure).toFixed(1)}`
      : "—";
    $("#timing-agreement").textContent = `${timing.agreement} of ${timing.total}`;
    const labels = { rsi: "RSI", stochasticRsi: "Stoch RSI", macd: "MACD", bollinger: "Bands" };
    $("#timing-votes").replaceChildren(...Object.entries(timing.inputs).map(([key, vote]) => {
      const chip = document.createElement("span");
      const direction = vote < -0.15 ? "up" : vote > 0.15 ? "down" : "neutral";
      chip.className = direction;
      chip.textContent = `${labels[key]} ${direction === "up" ? "favorable" : direction === "down" ? "extended" : "balanced"}`;
      return chip;
    }));
    $("#timing-copy").textContent = timing.condition === "buyer-extreme"
      ? "Momentum is deeply compressed. LensSetup still requires support and reversal confirmation before treating this as buyable."
      : timing.condition === "seller-extreme"
        ? "Momentum is extended. A strong company or uptrend can still be a poor entry at this price."
        : "LensTiming grades entry pressure only; LensTrend, zones, volume and confirmation decide whether the setup is actionable.";
  }

  function renderTrendRegime(result) {
    const regime = result.technical.trendRegime;
    const trendScore = Number(regime.trendScore);
    const formatted = Number.isFinite(trendScore)
      ? `${trendScore.toFixed(1)} / 10`
      : "—";
    $("#trend-regime-heading").textContent = regime.label;
    $("#trend-regime-value").textContent = formatted;
    $("#trend-regime-marker").style.left = Number.isFinite(trendScore)
      ? `${Math.max(0, Math.min(100, trendScore * 10))}%`
      : "50%";
    $("#trend-agreement").textContent = `${regime.agreement} of ${regime.total}`;
    $("#trend-extension").textContent = "Direction only";
    const voteLabels = {
      priceVsEma20: "Price / EMA20",
      ema20Vs50: "EMA20 / 50",
      ema50Vs200: "EMA50 / 200",
      ema20Slope: "EMA20 slope",
      ema50Slope: "EMA50 slope",
    };
    $("#trend-regime-votes").replaceChildren(...Object.entries(regime.inputs).map(([key, vote]) => {
      const chip = document.createElement("span");
      const direction = vote > 0.15 ? "up" : vote < -0.15 ? "down" : "neutral";
      chip.className = direction;
      chip.textContent = `${voteLabels[key]} ${direction === "up" ? "↑" : direction === "down" ? "↓" : "•"}`;
      return chip;
    }));
    $("#trend-regime-copy").textContent = `${regime.agreement} of ${regime.total} moving-average structure inputs agree. LensTrend measures direction; LensTiming measures entry pressure.`;
  }

  function renderTechnicalMetrics(result) {
    const tech = result.technical;
    const regimeValue = Number.isFinite(tech.trendRegime.trendScore)
      ? `${tech.trendRegime.trendScore.toFixed(1)} / 10`
      : "—";
    const metrics = [
      ["LensTiming", `${tech.timing.timingScore.toFixed(1)} / 10`, `${tech.timing.label} · entry pressure`],
      ["Setup confirmation", `${(tech.confirmation / 10).toFixed(1)} / 10`, "Price recovery and momentum follow-through"],
      ["LensTrend", regimeValue, `${tech.trendRegime.label} · direction, not buyability`],
      ["Trend agreement", `${tech.trendRegime.agreement} / ${tech.trendRegime.total}`, "Price and moving-average structure"],
      ["RSI · 14", tech.indicators.rsi?.toFixed(1) || "—", tech.indicators.rsi > 70 ? "Extended" : tech.indicators.rsi < 35 ? "Oversold" : "Balanced"],
      ["Stochastic RSI", tech.indicators.stochasticRsi?.toFixed(1) || "—", tech.indicators.stochasticRsi > 80 ? "High momentum" : tech.indicators.stochasticRsi < 20 ? "Low momentum" : "Middle range"],
      ["MACD", tech.indicators.macd.histogram >= 0 ? "Positive" : "Negative", "Histogram"],
      ["Relative volume", `${tech.indicators.relativeVolume?.toFixed(2) || "—"}×`, "Versus 20-day"],
      ["ATR", pct(tech.indicators.atrPct), "Daily range / price"],
      ["Max drawdown", pct(tech.indicators.drawdown), "Trailing year"],
    ];
    $("#technical-grid").replaceChildren(...metrics.map(([label, value, note]) => {
      const card = document.createElement("div");
      card.className = "technical-metric";
      const labelEl = document.createElement("span");
      labelEl.textContent = label;
      const valueEl = document.createElement("strong");
      valueEl.textContent = value;
      const noteEl = document.createElement("small");
      noteEl.textContent = note;
      card.append(labelEl, valueEl, noteEl);
      return card;
    }));
  }

  function renderSetupComponents(result) {
    const tech = result.technical;
    const definitions = [
      ["Timing", tech.setupComponents.timing, "22%", "Entry pressure"],
      ["Location", tech.setupComponents.entryLocation, "20%", "Support / resistance"],
      ["Trend", tech.setupComponents.trend, "16%", "Price direction"],
      ["Structure", tech.setupComponents.structure, "14%", "Zone quality"],
      ["Volume", tech.setupComponents.volume, "10%", "Participation"],
      ["Risk", tech.setupComponents.risk, "10%", "Volatility / drawdown"],
      ["Confirmation", tech.setupComponents.confirmation, "8%", "Reversal follow-through"],
    ];
    $("#setup-page-score").textContent = `${(tech.setupScore / 10).toFixed(1)} / 10`;
    $("#setup-component-grid").replaceChildren(...definitions.map(([label, score, weight, note]) => {
      const card = document.createElement("div");
      card.className = "setup-component";
      const top = document.createElement("div");
      const name = document.createElement("span");
      name.textContent = label;
      const value = document.createElement("strong");
      value.textContent = `${(Number(score) / 10).toFixed(1)}`;
      top.append(name, value);
      const track = document.createElement("i");
      track.style.setProperty("--setup-progress", `${Math.max(0, Math.min(100, Number(score)))}%`);
      const detail = document.createElement("small");
      detail.textContent = `${weight} · ${note}`;
      card.append(top, track, detail);
      return card;
    }));
    const copy = tech.setupGuardrails.length
      ? `Active guardrail: ${tech.setupGuardrails.join(" ")}`
      : tech.setupSignals.length
        ? `Aligned signal: ${tech.setupSignals.join(" ")}`
        : "No tactical cap is active. The weighted setup remains subject to timing, zone, trend and confirmation alignment.";
    $("#setup-guardrail-copy").textContent = copy;
    $("#setup-guardrail-copy").dataset.tone = tech.setupGuardrails.length ? "caution" : tech.setupSignals.length ? "positive" : "neutral";
  }

  function renderDrivers(result) {
    const waterfall = $("#driver-waterfall");
    waterfall.replaceChildren();
    const lenses = [
      ["LensValue", result.lenses.value.rawScore, "Independent long-term lens", "70% of the combined base"],
      ["LensSetup", result.lenses.setup.rawScore, "Independent tactical lens", "30% of the combined base"],
    ];
    lenses.forEach(([label, value, role, explanation]) => {
      const row = document.createElement("div");
      row.className = "driver-row";
      const name = document.createElement("div");
      name.className = "driver-name";
      const strong = document.createElement("strong");
      strong.textContent = label;
      const span = document.createElement("span");
      span.textContent = `${role} · ${(value / 10).toFixed(1)}/10`;
      name.append(strong, span);
      const track = document.createElement("div");
      track.className = "driver-track";
      const fill = document.createElement("i");
      fill.style.width = `${value}%`;
      track.append(fill);
      const impact = document.createElement("div");
      impact.className = "driver-impact";
      impact.textContent = explanation;
      row.append(name, track, impact);
      waterfall.append(row);
    });
    $("#coverage-value").textContent = `${result.coverage}%`;
    $("#history-value").textContent = `${result.technical.bars.length} bars`;
    $("#cap-value").textContent = result.modelDetails.qualityCap < 100
      ? `${(result.modelDetails.qualityCap / 10).toFixed(1)} maximum`
      : result.caps.length ? `${result.caps.length} active` : "None";
    const guardrails = $("#guardrail-list");
    guardrails.replaceChildren();
    [
      "Confidence is separate from the score.",
      "Confirmed pivots never use bars beyond their confirmation date.",
      "Correlated indicators are grouped before weighting.",
      "LensTiming, LensTrend, support location and confirmation are graded separately.",
      ...result.technical.setupGuardrails,
      `Cross-lens agreement bonus: +${(result.modelDetails.crossLensBonus / 10).toFixed(1)} points.`,
      `Cross-lens mismatch penalty: −${(result.modelDetails.mismatchPenalty / 10).toFixed(1)} points.`,
      ...(result.caps.length ? result.caps : ["No score cap is active for this scenario."]),
    ].forEach(text => {
      const p = document.createElement("p");
      p.textContent = text;
      guardrails.append(p);
    });
  }

  function renderIndicatorTable(result) {
    const i = result.technical.indicators;
    const regimeValue = Number.isFinite(result.technical.trendRegime.trendScore)
      ? `${result.technical.trendRegime.trendScore.toFixed(1)} / 10`
      : "—";
    const rows = [
      ["LensTiming", `${result.technical.timing.timingScore.toFixed(1)} / 10`, "Entry pressure", `${result.technical.timing.agreement} of ${result.technical.timing.total} momentum inputs agree · ${result.technical.timing.label}`],
      ["Price / 20-day MA", `${money(result.price)} / ${money(i.ma20)}`, "Technical structure", result.price > i.ma20 ? "Above short-term trend" : "Below short-term trend"],
      ["50 / 200-day MA", `${money(i.ma50)} / ${money(i.ma200)}`, "Technical structure", i.ma50 > i.ma200 ? "Long-term alignment positive" : "Long-term alignment negative"],
      ["LensTrend", regimeValue, "Trend direction", `${result.technical.trendRegime.agreement} of ${result.technical.trendRegime.total} inputs agree · ${result.technical.trendRegime.label}`],
      ["RSI · 14", i.rsi?.toFixed(1) || "—", "Momentum", i.rsi > 70 ? "Extended" : i.rsi < 35 ? "Oversold" : "Balanced"],
      ["Stochastic RSI", i.stochasticRsi?.toFixed(1) || "—", "Momentum", i.stochasticRsi > 80 ? "High in recent range" : i.stochasticRsi < 20 ? "Low in recent range" : "Balanced"],
      ["MACD histogram", i.macd.histogram?.toFixed(2) || "—", "Momentum", i.macd.histogram >= 0 ? "Positive" : "Negative"],
      ["Bollinger position", i.bollingerPosition?.toFixed(2) || "—", "Momentum", i.bollingerPosition > .8 ? "Near upper band" : i.bollingerPosition < -.8 ? "Near lower band" : "Inside normal band range"],
      ["21-day return", pct(i.roc21), "Momentum", i.roc21 >= 0 ? "Positive" : "Negative"],
      ["Relative volume", `${i.relativeVolume?.toFixed(2) || "—"}×`, "Volume", i.relativeVolume >= 1 ? "Above average" : "Below average"],
      ["ATR / price", pct(i.atrPct), "Risk", i.atrPct > .035 ? "Elevated daily range" : "Contained daily range"],
      ["Trailing drawdown", pct(i.drawdown), "Risk", Math.abs(i.drawdown) > .35 ? "High drawdown" : "Within normal range"],
      ["Revenue growth", pct(state.fundamentals.revenueGrowth), "Fundamentals", state.fundamentalFields.revenueGrowth?.source || "Reported data"],
      finite(state.fundamentals.fcfMargin)
        ? ["Free-cash-flow margin", pct(state.fundamentals.fcfMargin), "Fundamentals", state.fundamentalFields.fcfMargin?.source || "Reported data"]
        : ["Net profit margin", pct(state.fundamentals.profitMargin), "Fundamentals", state.fundamentalFields.profitMargin?.source || "Reported data"],
      finite(state.fundamentals.roic)
        ? ["Return on invested capital", pct(state.fundamentals.roic), "Fundamentals", state.fundamentalFields.roic?.source || "Reported data"]
        : ["Return on equity", pct(state.fundamentals.returnOnEquity), "Fundamentals", state.fundamentalFields.returnOnEquity?.source || "Reported data"],
      ["Reference earnings multiple", Number.isFinite(Number(state.fundamentals.forwardPE)) ? `${Number(state.fundamentals.forwardPE).toFixed(1)}×` : "—", "Valuation", state.fundamentalFields.forwardPE?.source || "Reported data"],
      ["Expectations gap", pct(state.fundamentals.impliedGrowthGap), "Valuation", "Implied minus supported growth"],
    ];
    const tbody = $("#indicator-table");
    tbody.replaceChildren(...rows.map(values => {
      const tr = document.createElement("tr");
      values.forEach(value => {
        const td = document.createElement("td");
        td.textContent = value;
        tr.append(td);
      });
      return tr;
    }));
  }

  function formatAssumption(definition, rawValue) {
    const value = Number(rawValue);
    if (definition.format === "percent") return `${value.toFixed(definition.step < 1 ? 1 : 0)}%`;
    return `${value.toFixed(definition.step < 1 ? 1 : 0)}×`;
  }

  function fromSliderValue(definition, value) {
    return definition.format === "percent" ? Number(value) / 100 : Number(value);
  }

  function toSliderValue(definition, value) {
    return definition.format === "percent" ? Number(value) * 100 : Number(value);
  }

  function renderAssumptions() {
    const container = $("#assumption-inputs");
    container.replaceChildren();
    ASSUMPTIONS.forEach(definition => {
      const wrapper = document.createElement("div");
      wrapper.className = "assumption";
      const head = document.createElement("div");
      head.className = "assumption-head";
      const label = document.createElement("label");
      const inputId = `assumption-${definition.key}`;
      label.htmlFor = inputId;
      label.textContent = definition.label;
      const output = document.createElement("output");
      output.htmlFor = inputId;
      const hasValue = finite(state.fundamentals[definition.key]);
      const sliderValue = hasValue ? toSliderValue(definition, state.fundamentals[definition.key]) : definition.min;
      output.value = hasValue ? formatAssumption(definition, sliderValue) : "Unavailable";
      output.textContent = output.value;
      head.append(label, output);
      const input = document.createElement("input");
      input.type = "range";
      input.id = inputId;
      input.min = definition.min;
      input.max = definition.max;
      input.step = definition.step;
      input.value = Math.min(definition.max, Math.max(definition.min, sliderValue));
      input.dataset.key = definition.key;
      input.disabled = !hasValue;
      input.addEventListener("input", () => {
        state.fundamentals[definition.key] = fromSliderValue(definition, input.value);
        output.value = formatAssumption(definition, input.value);
        output.textContent = output.value;
        calculate(false);
      });
      const note = document.createElement("small");
      note.textContent = definition.note;
      wrapper.append(head, input, note);
      container.append(wrapper);
    });
  }

  function configureEntryControls() {
    const current = state.result.price;
    // Let users test a true half-price case (and somewhat beyond it) without
    // silently clamping the value at the bottom of the slider.
    const low = Math.max(1, current * 0.35);
    const high = current * 1.25;
    $("#entry-price").value = current.toFixed(2);
    $("#entry-price").min = low.toFixed(2);
    $("#entry-price").max = high.toFixed(2);
    $("#entry-slider").min = low.toFixed(2);
    $("#entry-slider").max = high.toFixed(2);
    $("#entry-slider").value = current.toFixed(2);
    $("#entry-low").textContent = money(low);
    $("#entry-high").textContent = money(high);
  }

  function scenarioFundamentals(entryPrice) {
    const current = state.fundamentals._marketPrice || state.result.price;
    const baseValue = finite(state.fundamentals._baseDcfUpside)
      ? current * (1 + Number(state.fundamentals._baseDcfUpside))
      : null;
    const bearValue = finite(state.fundamentals._baseBearDownside)
      ? current * (1 + Number(state.fundamentals._baseBearDownside))
      : null;
    const priceRatio = entryPrice / current;
    return {
      ...state.fundamentals,
      dcfUpside: finite(baseValue) ? baseValue / entryPrice - 1 : null,
      bearDownside: finite(bearValue) ? bearValue / entryPrice - 1 : null,
      forwardPE: finite(state.fundamentals._baseForwardPE)
        ? Number(state.fundamentals._baseForwardPE) * priceRatio
        : null,
      impliedGrowthGap: finite(state.fundamentals._baseImpliedGrowthGap)
        ? Number(state.fundamentals._baseImpliedGrowthGap) + Math.log(priceRatio) * 0.18
        : null,
    };
  }

  function scenarioResult() {
    if (!state.result) return null;
    const entry = Number(state.entryPrice || state.result.price);
    return engine.scoreLens({
      bars: state.bars,
      fundamentals: scenarioFundamentals(entry),
      metadata: { ticker: state.ticker, scenario: true },
    });
  }

  function renderScenario() {
    const scenario = scenarioResult();
    if (!scenario || scenario.status !== "graded") return;
    $("#scenario-score-value").textContent = scenario.score.toFixed(1);
    $("#scenario-score-label").textContent = scenario.label;
    $("#scenario-value-score").textContent = scenario.lenses.value.score.toFixed(1);
    $("#scenario-setup-score").textContent = scenario.lenses.setup.score.toFixed(1);
    const entry = Number(state.entryPrice || state.result.price);
    const delta = scenario.score - state.baseline.score;
    const priceDifference = entry / state.result.price - 1;
    $("#scenario-delta").textContent = Math.abs(delta) < .05
      ? Math.abs(priceDifference) >= .01
        ? `The tested price is ${Math.abs(priceDifference * 100).toFixed(1)}% ${priceDifference < 0 ? "lower" : "higher"}, but the displayed score is unchanged because the current quality cap and chart setup remain in force.`
        : "This scenario is effectively unchanged from the current setup."
      : `${delta > 0 ? "+" : ""}${delta.toFixed(1)} points versus the current LensScore of ${state.baseline.score.toFixed(1)}.`;
    $("#scenario-explanation").textContent = Math.abs(priceDifference) < .001
      ? "Test a different entry price or change the fundamental assumptions to see the score respond. This is a price-only test using today’s evidence, not a historical backtest."
      : `At ${money(entry)}, LensValue becomes ${scenario.lenses.value.score.toFixed(1)}/10 while LensSetup remains ${scenario.lenses.setup.score.toFixed(1)}/10 because the chart history is unchanged. The combined LensScore is ${scenario.score.toFixed(1)}/10. This assumes the company outlook has not deteriorated. It does not reconstruct how the stock would have scored on a past date.`;
    const eps = state.fundamentalModel.referenceEps;
    const basis = state.fundamentalModel.referenceEpsBasis || "Unavailable";
    const basisText = basis ? `${basis.charAt(0).toLowerCase()}${basis.slice(1)}` : "unavailable EPS";
    const asOf = state.fundamentalModel.referenceEpsAsOf;
    $("#scenario-eps-basis").textContent = finite(eps)
      ? `Valuation uses ${money(eps)} ${basisText}${asOf ? ` through ${formatAsOf(asOf)}` : ""}.`
      : "No reliable positive EPS basis is available, so earnings-based valuation inputs are not graded.";
    $("#scenario-score-cap").textContent = scenario.caps?.length
      ? scenario.caps.join(" ")
      : "No score cap is active. Price, company quality, valuation, risk and the unchanged chart setup all contribute independently.";
  }

  function renderChartLegend() {
    const legend = $("#chart-legend");
    legend.replaceChildren();
    const palette = chartColors();
    const items = state.chartPreset === "toolkit"
      ? [["Price", palette.price], ["LensTiming heatmap", palette.green], ["Support", palette.green], ["Resistance", palette.red], ["20 / 50 / 200-day", palette.gold]]
      : state.chartPreset === "timing"
        ? [["Price", palette.price], ["Favorable timing", palette.green], ["Extended timing", palette.red]]
      : state.chartPreset === "trend"
      ? [["Price", palette.price], ["LensTrend history", palette.green], ["20-day", palette.gold], ["50-day", palette.blue], ["200-day", palette.purple]]
      : state.chartPreset === "levels"
        ? [["Price", palette.price], ["Support", palette.green], ["Resistance", palette.red]]
        : [["Price", palette.price], ["Primary support", palette.green], ["Primary resistance", palette.red]];
    items.forEach(([label, color]) => {
      const span = document.createElement("span");
      span.textContent = label;
      span.style.setProperty("--legend-color", color);
      legend.append(span);
    });
  }

  function drawChart() {
    const canvas = $("#price-chart");
    if (!canvas || !state.result) return;
    const rect = canvas.getBoundingClientRect();
    if (!rect.width || !rect.height) return;
    const ratio = Math.min(2, window.devicePixelRatio || 1);
    canvas.width = Math.round(rect.width * ratio);
    canvas.height = Math.round(rect.height * ratio);
    const context = canvas.getContext("2d");
    const palette = chartColors();
    context.setTransform(ratio, 0, 0, ratio, 0, 0);
    const width = rect.width;
    const height = rect.height;
    context.clearRect(0, 0, width, height);

    const bars = state.bars.slice(-180);
    if (!bars.length) return;
    const pad = { top: 16, right: 62, bottom: 28, left: 8 };
    const volumeHeight = 62;
    const plotBottom = height - pad.bottom - volumeHeight;
    const values = bars.flatMap(bar => [bar.high, bar.low]);
    const zones = state.result.technical.zones;
    const shownZones = state.chartPreset === "levels" || state.chartPreset === "toolkit"
      ? [...zones.support, ...zones.resistance]
      : [zones.support[0], zones.resistance[0]].filter(Boolean);
    shownZones.forEach(zone => values.push(zone.lower, zone.upper));
    let min = Math.min(...values);
    let max = Math.max(...values);
    const range = Math.max(1, max - min);
    min -= range * .06;
    max += range * .06;
    const x = index => pad.left + index / Math.max(1, bars.length - 1) * (width - pad.left - pad.right);
    const y = value => pad.top + (max - value) / (max - min) * (plotBottom - pad.top);

    if (state.chartPreset === "timing" || state.chartPreset === "toolkit") {
      const timingByTime = new Map(
        state.result.technical.timing.series.map(point => [point.time, point])
      );
      const bandWidth = (width - pad.left - pad.right) / Math.max(1, bars.length - 1);
      bars.forEach((bar, index) => {
        const point = timingByTime.get(bar.time);
        const distanceFromBalanced = Number(point?.timingScore) - 5;
        if (!point || Math.abs(distanceFromBalanced) < 0.35) return;
        const alpha = 0.018 + Math.min(1, Math.abs(distanceFromBalanced) / 5) * 0.10;
        context.fillStyle = point.timingScore > 5
          ? alphaColor(palette.green, alpha)
          : alphaColor(palette.red, alpha);
        context.fillRect(x(index) - bandWidth / 2, pad.top, bandWidth + 1, plotBottom - pad.top);
      });
    }

    if (state.chartPreset === "trend") {
      const regimeByTime = new Map(
        state.result.technical.trendRegime.series.map(point => [point.time, point])
      );
      const bandWidth = (width - pad.left - pad.right) / Math.max(1, bars.length - 1);
      bars.forEach((bar, index) => {
        const point = regimeByTime.get(bar.time);
        const distanceFromTransition = Number(point?.trendScore) - 5;
        if (!point || Math.abs(distanceFromTransition) < 0.35) return;
        const alpha = 0.018 + Math.min(1, Math.abs(distanceFromTransition) / 5) * 0.085;
        context.fillStyle = point.trendScore > 5
          ? alphaColor(palette.green, alpha)
          : alphaColor(palette.red, alpha);
        context.fillRect(x(index) - bandWidth / 2, pad.top, bandWidth + 1, plotBottom - pad.top);
      });
    }

    context.font = "9px " + getComputedStyle(document.documentElement).getPropertyValue("--mono");
    context.textAlign = "left";
    context.textBaseline = "middle";
    for (let line = 0; line <= 5; line += 1) {
      const value = min + (max - min) * line / 5;
      const py = y(value);
      context.strokeStyle = palette.grid;
      context.beginPath();
      context.moveTo(pad.left, py);
      context.lineTo(width - pad.right, py);
      context.stroke();
      context.fillStyle = palette.axis;
      context.fillText(money(value), width - pad.right + 8, py);
    }

    shownZones.forEach(zone => {
      context.fillStyle = zone.type === "support" ? alphaColor(palette.green, .12) : alphaColor(palette.red, .10);
      context.fillRect(pad.left, y(zone.upper), width - pad.left - pad.right, Math.max(2, y(zone.lower) - y(zone.upper)));
      context.strokeStyle = zone.type === "support" ? alphaColor(palette.green, .48) : alphaColor(palette.red, .42);
      context.setLineDash([5, 5]);
      context.beginPath();
      context.moveTo(pad.left, y(zone.center));
      context.lineTo(width - pad.right, y(zone.center));
      context.stroke();
      context.setLineDash([]);
    });

    const maxVolume = Math.max(...bars.map(bar => bar.volume || 0), 1);
    const candleWidth = Math.max(1, Math.min(5, (width - pad.left - pad.right) / bars.length * .62));
    state.chartPoints = [];
    bars.forEach((bar, index) => {
      const px = x(index);
      const up = bar.close >= bar.open;
      context.strokeStyle = up ? palette.green : palette.red;
      context.fillStyle = up ? alphaColor(palette.green, .78) : alphaColor(palette.red, .78);
      context.beginPath();
      context.moveTo(px, y(bar.high));
      context.lineTo(px, y(bar.low));
      context.stroke();
      const bodyTop = y(Math.max(bar.open, bar.close));
      const bodyBottom = y(Math.min(bar.open, bar.close));
      context.fillRect(px - candleWidth / 2, bodyTop, candleWidth, Math.max(1, bodyBottom - bodyTop));
      const volHeight = (bar.volume || 0) / maxVolume * (volumeHeight - 12);
      context.fillStyle = up ? alphaColor(palette.green, .26) : alphaColor(palette.red, .23);
      context.fillRect(px - candleWidth / 2, height - pad.bottom - volHeight, candleWidth, volHeight);
      state.chartPoints.push({ x: px, bar });
    });

    if (state.chartPreset === "trend" || state.chartPreset === "toolkit") {
      const allCloses = state.bars.map(bar => bar.close);
      [[20, palette.gold], [50, palette.blue], [200, palette.purple]].forEach(([period, color]) => {
        const series = engine.sma(allCloses, period).slice(-180);
        context.strokeStyle = color;
        context.lineWidth = period === 20 ? 1.7 : 1.25;
        context.beginPath();
        let started = false;
        series.forEach((value, index) => {
          if (!Number.isFinite(value)) return;
          if (!started) {
            context.moveTo(x(index), y(value));
            started = true;
          } else context.lineTo(x(index), y(value));
        });
        context.stroke();
      });
    }

    context.strokeStyle = palette.baseline;
    context.beginPath();
    context.moveTo(pad.left, plotBottom);
    context.lineTo(width - pad.right, plotBottom);
    context.stroke();
    renderChartLegend();
  }

  function showView(name) {
    const validView = ["snapshot", "chart", "value", "drivers", "scenario"].includes(name) ? name : "snapshot";
    $$("[data-view-panel]").forEach(panel => {
      const active = panel.dataset.viewPanel === validView;
      panel.hidden = !active;
      panel.classList.toggle("active", active);
    });
    $$(".company-nav [data-view]").forEach(button => button.classList.toggle("active", button.dataset.view === validView));
    const url = new URL(window.location.href);
    if (validView === "snapshot") url.searchParams.delete("view");
    else url.searchParams.set("view", validView);
    window.history.replaceState({}, "", `${url.pathname}${url.search}`);
    if (validView === "chart") requestAnimationFrame(drawChart);
  }

  async function saveCurrentScenario() {
    const button = $("#save-scenario");
    const scenario = scenarioResult();
    const now = new Date().toISOString();
    const entry = {
      id: Date.now(),
      type: "lensscore",
      ticker: state.ticker,
      title: `${state.ticker} LensScore ${scenario.score.toFixed(1)} at ${money(state.entryPrice)}`,
      date: now,
      syncState: "local",
      data: {
        analysisKind: "lensscore",
        modelVersion: engine.VERSION,
        score: scenario.score,
        entryPrice: state.entryPrice,
        lenses: scenario.lenses || null,
        confidence: state.result?.confidence || null,
        marketAsOf: state.provenance?.asOf?.market || null,
        fundamentalsAsOf: state.provenance?.asOf?.fundamentals || null,
        assumptions: Object.fromEntries(ASSUMPTIONS.map(item => [item.key, state.fundamentals[item.key]])),
        savedAt: now,
      },
    };

    try {
      const savedKey = "impliedLens_savedAnalyses";
      const existing = JSON.parse(window.localStorage.getItem(savedKey) || "[]");
      window.localStorage.setItem(savedKey, JSON.stringify([entry, ...existing].slice(0, 100)));
      window.localStorage.setItem("implied-lens-score-scenario", JSON.stringify(entry.data));
    } catch (_) {
      $("#save-status").textContent = "Scenario is active for this session.";
      return;
    }

    button.disabled = true;
    $("#save-status").textContent = "Saved on this device. Checking account sync…";
    try {
      const csrfResponse = await fetch("/api/csrf", { credentials: "same-origin" });
      const csrfPayload = await csrfResponse.json().catch(() => ({}));
      const response = await fetch("/api/saves", {
        method: "POST",
        credentials: "same-origin",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": csrfPayload.token || "",
        },
        body: JSON.stringify({
          ticker: entry.ticker,
          type: entry.type,
          label: entry.title,
          data: entry,
        }),
      });
      const result = await response.json().catch(() => ({}));
      if (response.status === 401) {
        $("#save-status").textContent = "Saved on this device. Log in to sync it to Saved.";
        return;
      }
      if (!response.ok || !result.ok || !result.id) throw new Error(result.error || "Account sync failed.");
      try {
        const savedKey = "impliedLens_savedAnalyses";
        const existing = JSON.parse(window.localStorage.getItem(savedKey) || "[]");
        window.localStorage.setItem(savedKey, JSON.stringify(existing.map(item => item.id === entry.id
          ? { ...item, id: `db_${result.id}`, _dbId: result.id, syncState: "synced" }
          : item
        )));
      } catch (_) {}
      $("#save-status").textContent = "Saved to your Implied Lens research library.";
    } catch (error) {
      $("#save-status").textContent = `Saved on this device. ${error.message}`;
    } finally {
      button.disabled = false;
    }
  }

  function bindEvents() {
    /* The shared site header brought its own #theme-toggle-btn and this page's
       original button became #theme-button-old, so this binding had been
       pointing at nothing since. site-nav.js owns the shared toggle; this only
       has to cover the legacy button if it is still in the markup. */
    on("#theme-button, #theme-button-old", "click", toggleTheme);
    on("#ticker-form", "submit", event => {
      event.preventDefault();
      loadTicker($("#ticker-input").value.trim().toUpperCase());
    });
    $$(".quick-tickers [data-ticker]").forEach(button => button.addEventListener("click", () => loadTicker(button.dataset.ticker)));
    $$(".company-nav [data-view]").forEach(button => button.addEventListener("click", () => showView(button.dataset.view)));
    on("#open-chart-button", "click", () => showView("chart"));
    $$(".chart-presets [data-preset]").forEach(button => button.addEventListener("click", () => {
      state.chartPreset = button.dataset.preset;
      $$(".chart-presets [data-preset]").forEach(item => item.classList.toggle("active", item === button));
      drawChart();
    }));
    on("#methodology-button", "click", () => $("#methodology-dialog").showModal());
    on("#close-methodology", "click", () => $("#methodology-dialog").close());
    on("#methodology-dialog", "click", event => {
      if (event.target === $("#methodology-dialog")) $("#methodology-dialog").close();
    });
    on("#reset-assumptions", "click", () => {
      state.fundamentals = { ...state.reportedFundamentals };
      renderAssumptions();
      calculate(false);
    });
    const setEntry = value => {
      const min = Number($("#entry-slider").min);
      const max = Number($("#entry-slider").max);
      state.entryPrice = Math.min(max, Math.max(min, Number(value)));
      $("#entry-price").value = state.entryPrice.toFixed(2);
      $("#entry-slider").value = state.entryPrice;
      renderScenario();
    };
    on("#entry-slider", "input", event => setEntry(event.target.value));
    on("#entry-price", "input", event => setEntry(event.target.value));
    on("#save-scenario", "click", saveCurrentScenario);
    on("#price-chart", "mousemove", event => {
      if (!state.chartPoints.length) return;
      const rect = event.currentTarget.getBoundingClientRect();
      const mouseX = event.clientX - rect.left;
      const nearest = state.chartPoints.reduce((best, point) =>
        Math.abs(point.x - mouseX) < Math.abs(best.x - mouseX) ? point : best
      );
      const tooltip = $("#chart-tooltip");
      tooltip.hidden = false;
      tooltip.style.left = `${Math.min(rect.width - 150, Math.max(5, nearest.x + 10))}px`;
      tooltip.style.top = "18px";
      const date = new Date(nearest.bar.time * 1000).toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" });
      tooltip.textContent = `${date} · O ${money(nearest.bar.open)} · H ${money(nearest.bar.high)} · L ${money(nearest.bar.low)} · C ${money(nearest.bar.close)} · Vol ${compact(nearest.bar.volume)}`;
    });
    on("#price-chart", "mouseleave", () => { $("#chart-tooltip").hidden = true; });
    let resizeFrame = null;
    window.addEventListener("resize", () => {
      cancelAnimationFrame(resizeFrame);
      resizeFrame = requestAnimationFrame(drawChart);
    });
  }

  applySavedTheme();
  bindEvents();
  const initialParams = new URLSearchParams(window.location.search);
  const initialTicker = initialParams.get("ticker");
  showView(initialParams.get("view") || "snapshot");
  loadTicker((initialTicker || "AAPL").toUpperCase());
})();
