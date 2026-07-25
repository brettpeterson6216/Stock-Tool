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
    chartPreset: "clean",
    source: "Waiting for live data",
    entryPrice: null,
    chartPoints: [],
  };

  const $ = selector => document.querySelector(selector);
  const $$ = selector => Array.from(document.querySelectorAll(selector));
  const finite = value => value !== null && value !== undefined && value !== "" && Number.isFinite(Number(value));
  const money = value => finite(value)
    ? new Intl.NumberFormat("en-US", { style: "currency", currency: "USD", maximumFractionDigits: 2 }).format(value)
    : "—";
  const pct = (value, places = 1) => finite(value) ? `${(Number(value) * 100).toFixed(places)}%` : "—";
  const compact = value => finite(value)
    ? new Intl.NumberFormat("en-US", { notation: "compact", maximumFractionDigits: 1 }).format(value)
    : "—";
  const escapeText = value => String(value ?? "");

  function applySavedTheme() {
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

  function alphaColor(hex, alpha) {
    const value = String(hex || "").replace("#", "");
    if (!/^[0-9a-f]{6}$/i.test(value)) return hex;
    const numeric = Number.parseInt(value, 16);
    return `rgba(${(numeric >> 16) & 255},${(numeric >> 8) & 255},${numeric & 255},${alpha})`;
  }

  async function loadTicker(ticker) {
    state.ticker = ticker.replace(/[^A-Z0-9.^-]/g, "").slice(0, 10) || "AAPL";
    $("#ticker-input").value = state.ticker;
    state.chartPoints = [];
    $("#chart-tooltip").hidden = true;
    $("#chart-tooltip").textContent = "";
    setNotice("Loading reported company facts, earnings expectations and market history…", "");
    try {
      const response = await fetch(`/api/lens-score/${encodeURIComponent(state.ticker)}?preview=1`, {
        credentials: "same-origin",
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(payload.error || `Research endpoint returned ${response.status}`);
      if (payload.provenance?.synthetic !== false) throw new Error("Unverified or synthetic data was rejected.");
      state.bars = engine.normalizeBars(payload.market?.bars || []);
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
      setNotice(
        `Research loaded from ${state.source}. Market as of ${formatAsOf(payload.provenance?.asOf?.market)}; company facts as of ${formatAsOf(payload.provenance?.asOf?.fundamentals)}.`,
        "good"
      );
    } catch (error) {
      state.bars = [];
      state.fundamentals = {};
      state.reportedFundamentals = {};
      state.fundamentalFields = {};
      state.fundamentalModel = {};
      state.result = null;
      state.baseline = null;
      setNotice(
        `${error.message} LensScore is Not Rated; no synthetic replacement was used.`,
        "warn"
      );
      renderUnavailable();
      return;
    }
    const latest = state.bars[state.bars.length - 1];
    state.entryPrice = latest.close;
    state.fundamentals = normalizePresetForPrice(state.fundamentals, latest.close);
    state.reportedFundamentals = { ...state.fundamentals };
    calculate(true);
    renderAssumptions();
    if (state.result?.status === "graded") configureEntryControls();
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
    ["#score-value", "#setup-score", "#value-score"].forEach(selector => {
      const element = $(selector);
      if (element) element.textContent = "—";
    });
    $("#score-label").textContent = "Not Rated";
    $("#score-summary").textContent = reason;
    $("#score-confidence").textContent = "Low";
    $("#model-version").textContent = engine.VERSION;
    $("#score-date").textContent = new Date().toLocaleDateString("en-US", { dateStyle: "medium" });
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
      renderUnavailable(state.result.reason);
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
    renderTrendRegime(result);
    renderZones(result);
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
    $("#value-label").textContent = value.label;
    const signal = $("#golden-lens-signal");
    signal.dataset.active = goldenLens.active ? "true" : "false";
    $("#golden-lens-label").textContent = goldenLens.active
      ? "Golden Lens signal"
      : "Golden Lens not active";
    $("#golden-lens-reason").textContent = goldenLens.reason;
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
    $("#trend-extension").textContent = regime.extension === "extended"
      ? "Extended"
      : regime.extension === "washed-out" ? "Washed out" : "Normal";
    const voteLabels = {
      structure: "Structure",
      rsi: "RSI",
      stochasticRsi: "Stoch RSI",
      macd: "MACD",
      bollinger: "Bands",
    };
    $("#trend-regime-votes").replaceChildren(...Object.entries(regime.inputs).map(([key, vote]) => {
      const chip = document.createElement("span");
      const direction = vote > 0.15 ? "up" : vote < -0.15 ? "down" : "neutral";
      chip.className = direction;
      chip.textContent = `${voteLabels[key]} ${direction === "up" ? "↑" : direction === "down" ? "↓" : "•"}`;
      return chip;
    }));
    $("#trend-regime-copy").textContent = regime.extension === "extended"
      ? "LensTrend confirms direction, but price is stretched. The trend can be strong while the entry is unattractive."
      : regime.extension === "washed-out"
        ? "Selling pressure is extreme, but a reversal is not confirmed. Cheap or oversold does not automatically mean buyable."
        : `${regime.agreement} of ${regime.total} inputs agree. LensTrend measures direction; LensScore remains the buyability decision.`;
  }

  function renderTechnicalMetrics(result) {
    const tech = result.technical;
    const regimeValue = Number.isFinite(tech.trendRegime.trendScore)
      ? `${tech.trendRegime.trendScore.toFixed(1)} / 10`
      : "—";
    const metrics = [
      ["LensTrend", regimeValue, `${tech.trendRegime.label} · direction, not buyability`],
      ["Signal agreement", `${tech.trendRegime.agreement} / ${tech.trendRegime.total}`, "Structure · RSI · Stoch RSI · MACD · bands"],
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
    const delta = scenario.score - state.baseline.score;
    $("#scenario-delta").textContent = Math.abs(delta) < .05
      ? "This scenario is effectively unchanged from the current setup."
      : `${delta > 0 ? "+" : ""}${delta.toFixed(1)} points versus the current LensScore of ${state.baseline.score.toFixed(1)}.`;
    const entry = Number(state.entryPrice || state.result.price);
    const difference = entry / state.result.price - 1;
    $("#scenario-explanation").textContent = Math.abs(difference) < .001
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
    const items = state.chartPreset === "trend"
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
    const shownZones = state.chartPreset === "levels"
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

    if (state.chartPreset === "trend") {
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
    $$("[data-view-panel]").forEach(panel => {
      const active = panel.dataset.viewPanel === name;
      panel.hidden = !active;
      panel.classList.toggle("active", active);
    });
    $$(".company-nav [data-view]").forEach(button => button.classList.toggle("active", button.dataset.view === name));
    if (name === "chart") requestAnimationFrame(drawChart);
  }

  function bindEvents() {
    $("#theme-button").addEventListener("click", toggleTheme);
    $("#ticker-form").addEventListener("submit", event => {
      event.preventDefault();
      loadTicker($("#ticker-input").value.trim().toUpperCase());
    });
    $$(".quick-tickers [data-ticker]").forEach(button => button.addEventListener("click", () => loadTicker(button.dataset.ticker)));
    $$(".company-nav [data-view]").forEach(button => button.addEventListener("click", () => showView(button.dataset.view)));
    $("#open-chart-button").addEventListener("click", () => showView("chart"));
    $$(".chart-presets [data-preset]").forEach(button => button.addEventListener("click", () => {
      state.chartPreset = button.dataset.preset;
      $$(".chart-presets [data-preset]").forEach(item => item.classList.toggle("active", item === button));
      drawChart();
    }));
    $("#methodology-button").addEventListener("click", () => $("#methodology-dialog").showModal());
    $("#close-methodology").addEventListener("click", () => $("#methodology-dialog").close());
    $("#methodology-dialog").addEventListener("click", event => {
      if (event.target === $("#methodology-dialog")) $("#methodology-dialog").close();
    });
    $("#reset-assumptions").addEventListener("click", () => {
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
    $("#entry-slider").addEventListener("input", event => setEntry(event.target.value));
    $("#entry-price").addEventListener("input", event => setEntry(event.target.value));
    $("#save-scenario").addEventListener("click", () => {
      const scenario = scenarioResult();
      const payload = {
        ticker: state.ticker,
        score: scenario.score,
        entryPrice: state.entryPrice,
        assumptions: Object.fromEntries(ASSUMPTIONS.map(item => [item.key, state.fundamentals[item.key]])),
        savedAt: new Date().toISOString(),
      };
      try {
        window.localStorage.setItem("implied-lens-score-scenario", JSON.stringify(payload));
        $("#save-status").textContent = "Saved in this browser.";
      } catch (_) {
        $("#save-status").textContent = "Scenario is active for this session.";
      }
    });
    $("#price-chart").addEventListener("mousemove", event => {
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
    $("#price-chart").addEventListener("mouseleave", () => { $("#chart-tooltip").hidden = true; });
    let resizeFrame = null;
    window.addEventListener("resize", () => {
      cancelAnimationFrame(resizeFrame);
      resizeFrame = requestAnimationFrame(drawChart);
    });
  }

  applySavedTheme();
  bindEvents();
  const initialTicker = new URLSearchParams(window.location.search).get("ticker");
  loadTicker((initialTicker || "AAPL").toUpperCase());
})();
