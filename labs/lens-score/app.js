(function () {
  "use strict";

  /* LensToolkit: the LensScore report card.

     The server grades the company against its sector (lib/lens-factors.js)
     and sends the result as payload.grades. The browser keeps the chart
     engine for the Entry timing tab: zones, trend and the timing gauge are
     computed here from the same price bars. */
  const engine = window.LensScoreEngine;
  if (!engine) throw new Error("LensScore engine failed to load.");

  const state = {
    ticker: "AAPL",
    bars: [],
    meta: {},
    grades: null,
    provenance: null,
    result: null,
    chartPreset: "toolkit",
    source: "Waiting for live data",
    chartPoints: [],
  };

  const $ = selector => document.querySelector(selector);
  const on = (selector, type, handler, opts) => {
    const node = typeof selector === "string" ? $(selector) : selector;
    if (node) node.addEventListener(type, handler, opts);
    return node;
  };
  const $$ = selector => Array.from(document.querySelectorAll(selector));
  const setText = (selector, text) => { const n = $(selector); if (n) n.textContent = text; return n; };
  let activeRequestController = null;
  const finite = value => value !== null && value !== undefined && value !== "" && Number.isFinite(Number(value));
  const money = value => finite(value)
    ? new Intl.NumberFormat("en-US", { style: "currency", currency: "USD", maximumFractionDigits: 2 }).format(value)
    : "—";
  const pct = (value, places = 1) => finite(value) ? `${(Number(value) * 100).toFixed(places)}%` : "—";
  const compact = value => finite(value)
    ? new Intl.NumberFormat("en-US", { notation: "compact", maximumFractionDigits: 1 }).format(value)
    : "—";
  const normalizeTickerInput = value => String(value || "")
    .trim()
    .toUpperCase()
    .replace("/", "-")
    .replace(/[^A-Z0-9.^-]/g, "")
    .slice(0, 15);
  const SESSION_CACHE_PREFIX = "il:lens-score:v4:";
  const SESSION_CACHE_INDEX = `${SESSION_CACHE_PREFIX}index`;
  const SESSION_CACHE_TTL_MS = 3 * 60 * 1000;
  const el = (tag, cls, text) => {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined && text !== null) n.textContent = text;
    return n;
  };
  const SHORT = { value: "Value", growth: "Growth", profitability: "Profit", health: "Health", momentum: "Momentum" };
  const gradeTone = g => !g ? "unknown" : /^A/.test(g) ? "strong" : /^B/.test(g) ? "positive" : /^C/.test(g) ? "neutral" : /^D/.test(g) ? "weak" : "severe";

  function fmtMetric(value, fmt) {
    if (!finite(value)) return "n/a";
    const n = Number(value);
    const abs = Math.abs(n);
    const sign = n < 0 ? "−" : "";
    if (fmt === "%") return `${sign}${abs >= 100 ? abs.toFixed(0) : abs.toFixed(1)}%`;
    if (fmt === "pp") return `${n >= 0 ? "+" : "−"}${abs.toFixed(1)} pts`;
    if (fmt === "x") return `${sign}${abs >= 100 ? abs.toFixed(0) : abs.toFixed(1)}×`;
    return n.toFixed(2);
  }

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

  function alphaColor(hex, alpha) {
    const value = String(hex || "").replace("#", "");
    if (!/^[0-9a-f]{6}$/i.test(value)) return hex;
    const numeric = Number.parseInt(value, 16);
    return `rgba(${(numeric >> 16) & 255},${(numeric >> 8) & 255},${numeric & 255},${alpha})`;
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
    $("#timing-heading").textContent = (TIMING_PLAIN[timing.key] || TIMING_PLAIN.unknown)[0];
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
      ? "Every momentum gauge says the stock has been sold hard. That is where rebounds often start, but confirm the trend and the support zone hold first."
      : timing.condition === "seller-extreme"
        ? "Every momentum gauge says the stock has run up hard. Even a great company can be a poor buy right after a spike."
        : (TIMING_PLAIN[timing.key] || TIMING_PLAIN.unknown)[1];
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
    $("#trend-regime-copy").textContent = `${regime.agreement} of ${regime.total} moving-average checks agree. Trend says which way the stock is heading; Timing says whether the price is stretched or pulled back.`;
  }

  function renderTechnicalMetrics(result) {
    const tech = result.technical;
    const regimeValue = Number.isFinite(tech.trendRegime.trendScore)
      ? `${tech.trendRegime.trendScore.toFixed(1)} / 10`
      : "—";
    const metrics = [
      ["Lens Timing", `${tech.timing.timingScore.toFixed(1)} / 10`, (TIMING_PLAIN[tech.timing.key] || TIMING_PLAIN.unknown)[0]],
      ["Setup confirmation", `${(tech.confirmation / 10).toFixed(1)} / 10`, "Price recovery and momentum follow-through"],
      ["Lens Trend", regimeValue, tech.trendRegime.label],
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
    if ($("#setup-page-score")) $("#setup-page-score").textContent = `${(tech.setupScore / 10).toFixed(1)} / 10`;
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
    state.grades = payload.grades || null;
    state.result = engine.scoreLens({
      bars: state.bars,
      fundamentals: payload.fundamentals?.values || {},
      metadata: { ticker: state.ticker, source: state.source },
    });
    renderAll();

    const retrieved = formatAsOf(payload.provenance?.retrievedAt);
    const marketAsOf = formatAsOf(payload.provenance?.asOf?.market);
    const prefix = refreshing
      ? `Showing grades from ${retrieved} while live data refreshes.`
      : `Prices through ${marketAsOf}.`;
    const peerNote = state.grades?.status === "graded"
      ? ` Graded against ${state.grades.peerCount} ${state.grades.basis === "sector" ? `${state.grades.sectorName} companies` : "companies"}; the score ranks it among ${state.grades.universeCount} companies we cover.`
      : "";
    setNotice(`${prefix}${peerNote}`, refreshing ? "warn" : "good");
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
    state.grades = null;
    state.provenance = null;
    state.result = null;
    updateResearchLinks();
    const tip = $("#chart-tooltip");
    if (tip) { tip.hidden = true; tip.textContent = ""; }
    const url = new URL(window.location.href);
    url.searchParams.set("ticker", state.ticker);
    window.history.replaceState({}, "", `${url.pathname}${url.search}`);
    let hasUsableCache = false;
    const sessionPayload = readSessionPayload(state.ticker);
    if (sessionPayload) {
      try { hydratePayload(sessionPayload, true); hasUsableCache = true; } catch (_) { hasUsableCache = false; }
    }
    if (!hasUsableCache) {
      renderUnavailable("Grading the company against its sector…");
      setNotice("Loading company data, prices and the peer group…", "");
    }
    try {
      const response = await fetch(`/api/lens-score/${encodeURIComponent(state.ticker)}?compact=1`, {
        credentials: "same-origin",
        cache: "default",
        signal: requestController.signal,
      });
      const payload = await response.json().catch(() => ({}));
      if (requestController.signal.aborted || state.ticker !== requestedTicker) return;
      if (response.status === 429 || payload.upgrade) {
        throw new Error(payload.error || "You have used today's free research. Upgrade to Pro for unlimited grades.");
      }
      if (!response.ok) throw new Error(payload.error || `Research endpoint returned ${response.status}`);
      hydratePayload(payload, false);
      writeSessionPayload(state.ticker, payload);
      loadHistory(state.ticker);
      renderAlerts();
    } catch (error) {
      if (error?.name === "AbortError") return;
      if (hasUsableCache) {
        setNotice(`Live refresh failed: ${error.message} Showing the grades loaded earlier in this session.`, "warn");
      } else {
        setNotice(`${error.message}`, "warn");
        renderUnavailable("LensScore could not be calculated right now.");
      }
    } finally {
      if (activeRequestController === requestController) {
        $("#lab-main").setAttribute("aria-busy", "false");
        activeRequestController = null;
      }
    }
  }

  function setNotice(message, tone) {
    const notice = $("#data-notice");
    if (!notice) return;
    notice.textContent = message;
    notice.className = `notice${tone ? ` ${tone}` : ""}`;
  }

  function renderPriceLine() {
    const latest = state.bars[state.bars.length - 1];
    const previous = state.bars[state.bars.length - 2] || latest;
    const change = latest && previous ? latest.close / previous.close - 1 : null;
    setText("#company-name", state.meta.longName || state.ticker);
    setText("#company-ticker", state.ticker);
    setText("#chart-ticker", state.ticker);
    setText("#market-price", latest ? money(latest.close) : "—");
    const ch = setText("#market-change", finite(change) ? `${change >= 0 ? "+" : ""}${pct(change)} last session` : "Daily close");
    if (ch) ch.style.color = finite(change) ? (change >= 0 ? "var(--green)" : "var(--red)") : "";
  }

  function renderUnavailable(reason) {
    renderPriceLine();
    setText("#rc-score-value", "—");
    const ring = $("#rc-score");
    if (ring) { ring.dataset.tone = "unknown"; ring.style.setProperty("--p", 0); }
    setText("#rc-label", "Not rated yet");
    const rank = $("#rc-rank"); if (rank) rank.hidden = true;
    setText("#rc-verdict", reason);
    const cap = $("#rc-cap"); if (cap) cap.hidden = true;
    setText("#rc-sector", "");
    ["#rc-mini", "#rc-factors", "#strength-list", "#concern-list", "#rc-peer-body", "#rc-peek-list"].forEach(sel => $(sel)?.replaceChildren());
    setText("#rc-asof", "");
    setText("#rc-timing-title", "Waiting for prices");
    setText("#rc-timing-score", "—");
    setText("#rc-timing-copy", "");
    setText("#buy-zone", "—");
    setText("#buy-zone-note", "");
    ["#support-zones", "#resistance-zones", "#technical-grid", "#chart-legend", "#setup-component-grid", "#timing-votes", "#trend-regime-votes"].forEach(sel => $(sel)?.replaceChildren());
    const canvas = $("#price-chart");
    if (canvas) canvas.getContext("2d")?.clearRect(0, 0, canvas.width, canvas.height);
    state.chartPoints = [];
  }

  function renderAll() {
    renderPriceLine();
    renderGrades(state.grades);
    renderTimingCard(state.result);
    if (state.result?.technical?.status === "ok") {
      renderTiming(state.result);
      renderTrendRegime(state.result);
      renderZones(state.result);
      renderSetupComponents(state.result);
      renderTechnicalMetrics(state.result);
      setText("#chart-source", `Source: ${state.source}`);
      drawChart();
    }
  }

  /* ── Report card ─────────────────────────────────────────────────────── */
  function renderGrades(g) {
    const ring = $("#rc-score");
    if (!g || g.status !== "graded") {
      setText("#rc-score-value", "—");
      if (ring) { ring.dataset.tone = "unknown"; ring.style.setProperty("--p", 0); }
      setText("#rc-label", "Not rated");
      const rank = $("#rc-rank"); if (rank) rank.hidden = true;
      setText("#rc-verdict", g?.reason || "Peer grades are not available for this company yet.");
      setText("#rc-sector", g?.sectorName ? `${g.sectorName}` : "");
      const cap = $("#rc-cap"); if (cap) cap.hidden = true;
      $("#rc-mini")?.replaceChildren();
      $("#rc-factors")?.replaceChildren();
      $("#rc-peer-body")?.replaceChildren();
      fillList("#strength-list", [], "Strengths appear once the company is graded.");
      fillList("#concern-list", [], "Watch-outs appear once the company is graded.");
      return;
    }
    setText("#rc-score-value", g.score.toFixed(1));
    if (ring) { ring.dataset.tone = g.tone; ring.style.setProperty("--p", g.score * 10); }
    setText("#rc-label", g.label);
    const rank = $("#rc-rank");
    if (rank) { rank.hidden = false; rank.textContent = `#${g.rank.position} of ${g.rank.of} in ${g.rank.sectorName}`; }
    setText("#rc-sector", [g.sectorName, g.industry].filter(Boolean).filter((v, i, a) => a.indexOf(v) === i).join(" · "));
    setText("#rc-verdict", g.verdict);
    const cap = $("#rc-cap");
    if (cap) { cap.hidden = !g.caps?.length; cap.textContent = g.caps?.length ? `Why it isn't higher: ${g.caps.join(" ")}` : ""; }
    setText("#rc-group", g.basis === "sector" ? `${g.peerCount} ${g.sectorName} companies` : `${g.peerCount} companies across sectors`);
    setText("#rc-peers-sector", g.sectorName);
    setText("#rc-asof", `Model ${g.version} · ${formatAsOf(g.asOf)}`);

    $("#rc-mini")?.replaceChildren(...g.factors.map(f => {
      const chip = el("button", "rc-mini-chip");
      chip.type = "button";
      chip.dataset.tone = gradeTone(f.grade);
      chip.append(el("b", null, f.grade || "–"), el("span", null, SHORT[f.key] || f.label));
      chip.addEventListener("click", () => openFactor(f.key));
      return chip;
    }));

    $("#rc-factors")?.replaceChildren(...g.factors.map(f => factorRow(f, g)));
    renderStreet(g.street);
    fillList("#strength-list", g.strengths.map(s => s.text), "No measure stands out above its peers.");
    fillList("#concern-list", g.watch.map(s => s.text), "No measure sits in the bottom quarter of its peers.");
    renderPeers(g);
  }

  function renderStreet(st) {
    const box = $("#rc-street");
    if (!box) return;
    box.hidden = !st;
    if (!st) return;
    const r = $("#rc-street-ratings"), e = $("#rc-street-earnings");
    r.replaceChildren(); e.replaceChildren();
    if (st.ratings) {
      const x = st.ratings;
      const head = el("div", "rc-st-head");
      head.append(el("strong", null, x.label), el("span", null, `${x.total} analyst${x.total === 1 ? "" : "s"}`));
      const bar = el("div", "rc-st-bar");
      bar.setAttribute("role", "img");
      bar.setAttribute("aria-label", `${x.strongBuy} strong buy, ${x.buy} buy, ${x.hold} hold, ${x.sell} sell, ${x.strongSell} strong sell`);
      [["strongBuy", "sb"], ["buy", "b"], ["hold", "h"], ["sell", "s"], ["strongSell", "ss"]].forEach(([k, cls]) => {
        if (!x[k]) return;
        const seg = el("i", `rc-st-${cls}`);
        seg.style.flex = String(x[k]);
        seg.title = `${x[k]} ${k.replace(/([A-Z])/g, " $1").toLowerCase()}`;
        bar.append(seg);
      });
      const legend = el("p", "rc-st-legend", `${x.strongBuy + x.buy} buy · ${x.hold} hold · ${x.sell + x.strongSell} sell`);
      r.append(head, bar, legend);
      if (x.threeMonthsAgo) {
        const t = x.threeMonthsAgo;
        const dir = x.mean > t.mean + 0.05 ? "more positive than" : x.mean < t.mean - 0.05 ? "less positive than" : "about the same as";
        r.append(el("p", "rc-st-note", `Ratings are ${dir} three months ago (${t.label}, ${t.total} analysts).`));
      }
    }
    if (st.earnings) {
      const q = st.earnings.quarters;
      e.append(el("p", "rc-st-beats", `Beat the earnings estimate in ${st.earnings.beats} of the last ${q.length} quarter${q.length === 1 ? "" : "s"}.`));
      const ul = el("ul", "rc-st-list");
      q.forEach(item => {
        const li = el("li");
        const d = new Date(`${item.period}T12:00:00Z`);
        li.append(el("span", null, `Q ending ${d.toLocaleDateString("en-US", { month: "short", year: "numeric", timeZone: "UTC" })}`),
          el("span", "rc-st-num", `$${item.actual.toFixed(2)} vs $${item.estimate.toFixed(2)}`),
          el("em", item.beat ? "good" : "bad", item.surprisePct == null ? (item.beat ? "Beat" : "Missed") : `${item.surprisePct >= 0 ? "+" : "−"}${Math.abs(item.surprisePct).toFixed(1)}%`));
        ul.append(li);
      });
      e.append(ul);
    }
  }

  function readFor(f, g) {
    if (!finite(f.percentile)) return "Not enough data to grade.";
    const group = g.basis === "sector" ? `${g.sectorName} peers` : "companies we cover";
    const p = Math.round(f.percentile);
    return p >= 50 ? `Better than ${p}% of ${group}` : `Weaker than ${100 - p}% of ${group}`;
  }

  function factorRow(f, g) {
    const wrap = el("div", "rc-factor");
    wrap.dataset.key = f.key;
    const btn = el("button", "rc-factor-row");
    btn.type = "button";
    btn.setAttribute("aria-expanded", "false");
    const grade = el("span", "rc-grade", f.grade || "–");
    grade.dataset.tone = gradeTone(f.grade);
    const name = el("span", "rc-factor-name");
    name.append(el("strong", null, f.label), el("small", null, f.question));
    const bar = el("span", "rc-bar");
    const fill = el("i");
    fill.style.setProperty("--w", `${finite(f.percentile) ? Math.max(3, f.percentile) : 0}%`);
    fill.dataset.tone = gradeTone(f.grade);
    bar.append(fill, el("b"));
    bar.setAttribute("aria-hidden", "true");
    const read = el("span", "rc-factor-read", readFor(f, g));
    const chev = el("span", "rc-chev", "▾");
    chev.setAttribute("aria-hidden", "true");
    btn.append(grade, name, bar, read, chev);

    const detail = el("div", "rc-factor-detail");
    detail.hidden = true;
    detail.append(el("p", "rc-learn", f.learn));
    const table = el("table", "rc-metric-table");
    const head = el("thead");
    const hr = el("tr");
    ["Measure", g.ticker, `${g.basis === "sector" ? g.sectorName : "Peer"} median`, "Peer rank"].forEach(h => hr.append(el("th", null, h)));
    head.append(hr);
    const body = el("tbody");
    f.metrics.forEach(m => {
      const tr = el("tr");
      const tdName = el("td", "rc-m-name");
      tdName.append(el("strong", null, m.label), el("small", null, `${m.why} ${m.better === "higher" ? "Higher is better." : "Lower is better."}`));
      const tdVal = el("td", "rc-m-val", fmtMetric(m.value, m.fmt));
      const tdMed = el("td", "rc-m-med", fmtMetric(m.peerMedian, m.fmt));
      const tdRank = el("td", "rc-m-rank");
      if (finite(m.percentile)) {
        const meter = el("span", "rc-meter");
        const i = el("i");
        i.style.setProperty("--w", `${Math.max(3, m.percentile)}%`);
        i.dataset.tone = gradeTone(gradeOfPct(m.percentile));
        meter.append(i);
        tdRank.append(meter, el("em", null, `${Math.round(m.percentile)}`));
      } else {
        tdRank.append(el("em", "muted", "n/a"));
      }
      tr.append(tdName, tdVal, tdMed, tdRank);
      body.append(tr);
    });
    table.append(head, body);
    const scroller = el("div", "rc-table-wrap");
    scroller.append(table);
    detail.append(scroller);
    detail.append(el("p", "rc-rank-note", "Peer rank: 100 is the best in the group, 0 the weakest. The factor grade averages these ranks."));

    btn.addEventListener("click", () => {
      const open = btn.getAttribute("aria-expanded") === "true";
      btn.setAttribute("aria-expanded", open ? "false" : "true");
      detail.hidden = open;
      wrap.classList.toggle("open", !open);
    });
    wrap.append(btn, detail);
    return wrap;
  }

  function gradeOfPct(p) {
    return p >= 90 ? "A+" : p >= 80 ? "A" : p >= 73 ? "A-" : p >= 67 ? "B+" : p >= 60 ? "B" : p >= 53 ? "B-"
      : p >= 47 ? "C+" : p >= 40 ? "C" : p >= 33 ? "C-" : p >= 27 ? "D+" : p >= 20 ? "D" : p >= 13 ? "D-" : "F";
  }

  function openFactor(key) {
    showView("snapshot");
    const row = document.querySelector(`.rc-factor[data-key="${key}"]`);
    if (!row) return;
    const btn = row.querySelector(".rc-factor-row");
    if (btn.getAttribute("aria-expanded") !== "true") btn.click();
    row.scrollIntoView({ behavior: "smooth", block: "center" });
  }

  function renderPeers(g) {
    const body = $("#rc-peer-body");
    if (!body) return;
    body.replaceChildren(...g.peers.map(p => {
      const tr = el("tr", p.self ? "self" : "");
      tr.append(el("td", "rc-p-rank", `${p.rank}`));
      const name = el("td", "rc-p-name");
      const link = el("button", "rc-p-link");
      link.type = "button";
      link.append(el("strong", null, p.ticker), el("span", null, p.name || ""));
      if (!p.self) link.addEventListener("click", () => { showView("snapshot"); loadTicker(p.ticker); window.scrollTo({ top: 0, behavior: "smooth" }); });
      else link.disabled = true;
      name.append(link);
      tr.append(name);
      const score = el("td", "rc-p-score", finite(p.score) ? p.score.toFixed(1) : "—");
      tr.append(score);
      ["value", "growth", "profitability", "health", "momentum"].forEach(k => {
        const td = el("td");
        const chip = el("span", "rc-chip", p.grades?.[k] || "–");
        chip.dataset.tone = gradeTone(p.grades?.[k]);
        td.append(chip);
        tr.append(td);
      });
      return tr;
    }));
    const peek = $("#rc-peek-list");
    if (peek) {
      const top = g.peers.filter(p => p.rank <= 5);
      const self = g.peers.find(p => p.self);
      if (self && self.rank > 5) top.push(self);
      peek.replaceChildren(...top.map(p => {
        const li = el("li", p.self ? "self" : "");
        const b = el("button", "rc-peek-item");
        b.type = "button";
        b.append(el("span", "rc-peek-rank", `${p.rank}`), el("strong", null, p.ticker), el("span", "rc-peek-name", p.name || ""), el("em", null, finite(p.score) ? p.score.toFixed(1) : "—"));
        if (p.self) b.disabled = true;
        else b.addEventListener("click", () => { loadTicker(p.ticker); window.scrollTo({ top: 0, behavior: "smooth" }); });
        li.append(b);
        return li;
      }));
      setText("#rc-peek-title", `Top of ${g.rank.sectorName}`);
    }
    setText("#rc-peer-foot", `Ranked by LensScore among ${g.rank.of} ${g.rank.sectorName} companies we cover. Grades compare each company with its own sector.`);
  }

  function fillList(selector, items, emptyMessage) {
    const list = $(selector);
    if (!list) return;
    list.replaceChildren();
    const values = items.length ? items : [emptyMessage];
    values.slice(0, 4).forEach(item => list.append(el("li", null, item)));
  }

  /* ── Entry timing (chart engine) ─────────────────────────────────────── */
  const TIMING_PLAIN = {
    "maximum-opportunity": ["Sharp pullback", "The stock has dropped hard in the short term. Pullbacks like this are where buyers have often stepped in, but only if the trend and support hold."],
    "favorable": ["Pulled back", "Short-term momentum has cooled off without breaking the trend, which is usually a calmer moment to buy than after a big run."],
    "mildly-favorable": ["Slight pullback", "The stock has eased a little from recent strength. Neither stretched nor deeply pulled back."],
    "balanced": ["Neutral", "Short-term momentum is balanced. Nothing in the chart argues strongly for waiting or for hurrying."],
    "extended": ["Stretched", "The stock has run up quickly. Buying after a sharp run raises the chance of a near-term pullback."],
    "maximum-risk": ["Very stretched", "The stock is far above its recent range on every momentum gauge. Historically a risky moment to chase."],
    unknown: ["Not enough data", "At least 60 trading days of prices are needed."],
  };
  function renderTimingCard(result) {
    const tech = result?.technical;
    if (!tech || tech.status !== "ok") {
      setText("#rc-timing-title", "Not enough price history");
      setText("#rc-timing-score", "—");
      setText("#rc-timing-copy", "At least 60 trading days of prices are needed.");
      return;
    }
    const t = tech.timing;
    const [label, copy] = TIMING_PLAIN[t.key] || TIMING_PLAIN.unknown;
    setText("#rc-timing-title", label);
    setText("#rc-timing-score", finite(t.timingScore) ? `${Number(t.timingScore).toFixed(1)} / 10` : "—");
    const marker = $("#rc-timing-marker");
    if (marker) marker.style.left = `${finite(t.timingScore) ? Math.max(0, Math.min(100, t.timingScore * 10)) : 50}%`;
    const trend = tech.trendRegime?.label ? ` Trend: ${tech.trendRegime.label.toLowerCase()}.` : "";
    setText("#rc-timing-copy", `${copy}${trend}`);
    const support = tech.zones?.support?.[0];
    if (support) {
      setText("#buy-zone", `${money(support.lower)}–${money(support.upper)}`);
      setText("#buy-zone-note", `${Math.abs(support.distancePct).toFixed(1)}% below the price · buyers stepped in here ${support.touches} time${support.touches === 1 ? "" : "s"} before`);
      setText("#invalidation-price", money(support.lower - (tech.indicators.atr || 0)));
    } else {
      setText("#buy-zone", "None nearby");
      setText("#buy-zone-note", "No price level below has held repeatedly in the past year.");
      setText("#invalidation-price", "—");
    }
  }

  function showView(name) {
    const validView = ["snapshot", "peers", "chart", "leaders"].includes(name) ? name : "snapshot";
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
    if (validView === "leaders") loadLeaders();
  }

  /* ── Score history ───────────────────────────────────────────────────── */
  async function loadHistory(ticker) {
    const box = $("#rc-history-chart");
    if (!box) return;
    try {
      const r = await fetch(`/api/lens-history/${encodeURIComponent(ticker)}`, { credentials: "same-origin" });
      const j = await r.json();
      if (state.ticker !== ticker) return;
      renderHistory(r.ok ? (j.points || []) : []);
    } catch (_) { renderHistory([]); }
  }

  function smoothPath(pts) {
    if (pts.length < 2) return "";
    let d = `M${pts[0][0].toFixed(1)},${pts[0][1].toFixed(1)}`;
    for (let i = 0; i < pts.length - 1; i++) {
      const p0 = pts[i - 1] || pts[i], p1 = pts[i], p2 = pts[i + 1], p3 = pts[i + 2] || p2;
      const c1 = [p1[0] + (p2[0] - p0[0]) / 6, p1[1] + (p2[1] - p0[1]) / 6];
      const c2 = [p2[0] - (p3[0] - p1[0]) / 6, p2[1] - (p3[1] - p1[1]) / 6];
      d += ` C${c1[0].toFixed(1)},${c1[1].toFixed(1)} ${c2[0].toFixed(1)},${c2[1].toFixed(1)} ${p2[0].toFixed(1)},${p2[1].toFixed(1)}`;
    }
    return d;
  }

  function renderHistory(points) {
    const box = $("#rc-history-chart");
    if (!box) return;
    const note = $("#rc-history-note");
    box.replaceChildren();
    if (!points.length) {
      box.append(el("p", "rc-history-empty", "Daily score history starts with tonight's snapshot. Come back tomorrow to see the first change."));
      if (note) note.textContent = "Saved once a trading day after the close.";
      return;
    }
    const fmtDay = d => new Date(`${d}T12:00:00Z`).toLocaleDateString("en-US", { month: "short", day: "numeric", timeZone: "UTC" });
    if (note) note.textContent = `${points.length} trading day${points.length === 1 ? "" : "s"} since ${fmtDay(points[0].day)}`;
    const W = Math.max(300, Math.round(box.clientWidth || 640)), H = W < 500 ? 170 : 150, L = 30, R = 14, T = 12, B = 24;
    const x = i => points.length === 1 ? (L + (W - R)) / 2 : L + (i / (points.length - 1)) * (W - L - R);
    const y = v => T + (1 - v / 10) * (H - T - B);
    const NS = "http://www.w3.org/2000/svg";
    const svg = document.createElementNS(NS, "svg");
    svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
    svg.setAttribute("class", "rc-history-svg");
    svg.setAttribute("role", "img");
    svg.setAttribute("aria-label", `LensScore history: ${points.map(p => `${fmtDay(p.day)} ${p.score.toFixed(1)}`).join(", ")}`);
    const mk = (tag, attrs) => { const n = document.createElementNS(NS, tag); Object.entries(attrs).forEach(([k, v]) => n.setAttribute(k, v)); return n; };
    [0, 5, 10].forEach(v => {
      svg.append(mk("line", { x1: L, x2: W - R, y1: y(v), y2: y(v), class: "rc-h-grid" }));
      const t = mk("text", { x: L - 8, y: y(v) + 4, class: "rc-h-axis", "text-anchor": "end" }); t.textContent = String(v); svg.append(t);
    });
    const pts = points.map((p, i) => [x(i), y(p.score)]);
    if (pts.length > 1) {
      const area = mk("path", { d: `${smoothPath(pts)} L${pts.at(-1)[0]},${y(0)} L${pts[0][0]},${y(0)} Z`, class: "rc-h-area" });
      svg.append(area, mk("path", { d: smoothPath(pts), class: "rc-h-line" }));
    }
    const last = pts.at(-1);
    svg.append(mk("circle", { cx: last[0], cy: last[1], r: 4.5, class: "rc-h-dot" }));
    const lab = mk("text", { x: Math.min(last[0], W - R - 2), y: last[1] - 10, class: "rc-h-label", "text-anchor": pts.length > 1 ? "end" : "middle" });
    lab.textContent = points.at(-1).score.toFixed(1);
    svg.append(lab);
    const d0 = mk("text", { x: L, y: H - 6, class: "rc-h-axis" }); d0.textContent = fmtDay(points[0].day); svg.append(d0);
    if (points.length > 1) { const d1 = mk("text", { x: W - R, y: H - 6, class: "rc-h-axis", "text-anchor": "end" }); d1.textContent = fmtDay(points.at(-1).day); svg.append(d1); }
    box.append(svg);
    if (points.length > 1) {
      const first = points[0], lastP = points.at(-1);
      const diff = lastP.score - first.score;
      const changed = Object.keys(lastP.grades || {}).filter(k => (first.grades || {})[k] && first.grades[k] !== lastP.grades[k]);
      box.append(el("p", "rc-history-read", `${diff === 0 ? "Unchanged" : `${diff > 0 ? "Up" : "Down"} ${Math.abs(diff).toFixed(1)}`} since ${fmtDay(first.day)}.${changed.length ? ` Grade changes: ${changed.map(k => `${SHORT[k]} ${first.grades[k]} → ${lastP.grades[k]}`).join(", ")}.` : ""}`));
    }
  }

  /* ── Leaderboard ─────────────────────────────────────────────────────── */
  let leaders = { at: 0, data: null };
  async function loadLeaders() {
    if (leaders.data && Date.now() - leaders.at < 5 * 60 * 1000) return renderLeaders(leaders.data);
    setText("#rc-leaders-note", "Loading the leaderboard…");
    try {
      const r = await fetch("/api/lens-leaders", { credentials: "same-origin" });
      const j = await r.json();
      if (!r.ok) throw new Error(j.error || "The leaderboard is unavailable right now.");
      leaders = { at: Date.now(), data: j };
      renderLeaders(j);
    } catch (error) {
      setText("#rc-leaders-note", error.message);
    }
  }

  function gradeCells(tr, grades) {
    ["value", "growth", "profitability", "health", "momentum"].forEach(k => {
      const td = el("td");
      const chip = el("span", "rc-chip", grades?.[k] || "–");
      chip.dataset.tone = gradeTone(grades?.[k]);
      td.append(chip);
      tr.append(td);
    });
  }

  function gradeLink(ticker, name) {
    const b = el("button", "rc-p-link");
    b.type = "button";
    b.append(el("strong", null, ticker), el("span", null, name || ""));
    b.addEventListener("click", () => { showView("snapshot"); loadTicker(ticker); window.scrollTo({ top: 0, behavior: "smooth" }); });
    return b;
  }

  function renderLeaders(d) {
    const fmtDay = v => new Date(`${v}T12:00:00Z`).toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric", timeZone: "UTC" });
    setText("#rc-leaders-note", `Ranked by LensScore across ${d.universe} companies we cover · updated ${formatAsOf(d.asOf)}.`);
    $("#rc-leaders-body")?.replaceChildren(...d.top.map((r, i) => {
      const tr = el("tr");
      tr.append(el("td", "rc-p-rank", `${i + 1}`));
      const name = el("td", "rc-p-name"); name.append(gradeLink(r.ticker, r.name)); tr.append(name);
      tr.append(el("td", "rc-p-sector", r.sectorName));
      tr.append(el("td", "rc-p-score", r.score.toFixed(1)));
      gradeCells(tr, r.grades);
      return tr;
    }));
    const movers = $("#rc-movers-body");
    if (movers) {
      movers.replaceChildren();
      if (!d.movers || (!d.movers.up.length && !d.movers.down.length)) {
        movers.append(el("p", "rc-history-empty", d.historyStarts
          ? `Score history began ${fmtDay(d.historyStarts)}. Weekly moves appear after the next trading day's snapshot.`
          : "Score history starts with tonight's snapshot. Weekly moves appear from tomorrow."));
      } else {
        const list = (title, rows, cls) => {
          const wrap = el("div", "rc-mover-col");
          wrap.append(el("h4", cls, title));
          const ul = el("ul", "rc-mover-list");
          rows.forEach(m => {
            const li = el("li");
            li.append(gradeLink(m.ticker, m.name), el("em", cls, `${m.change > 0 ? "+" : "−"}${Math.abs(m.change).toFixed(1)}`), el("small", null, `${m.then.toFixed(1)} → ${m.now.toFixed(1)}`));
            ul.append(li);
          });
          wrap.append(ul);
          return wrap;
        };
        movers.append(el("p", "rc-card-note", `Since ${fmtDay(d.movers.since)}`), list("Rising", d.movers.up, "good"), list("Falling", d.movers.down, "bad"));
      }
    }
    const track = $("#rc-track-body");
    if (track) {
      track.replaceChildren();
      const tr = d.trackRecord;
      if (!tr || !tr.companies) {
        track.append(el("p", "rc-history-empty", `${d.historyStarts ? `The record started ${fmtDay(d.historyStarts)}.` : "The record starts with tonight's snapshot."} Each night we save every grade with its price, then show how each score band has performed since, winners and losers alike. Meaningful results take months; we will show them from day one anyway.`));
      } else {
        track.append(el("p", "rc-card-note", `Price change since ${fmtDay(tr.startDay)} for the ${tr.companies} companies graded that day. All companies: ${tr.allAverage >= 0 ? "+" : ""}${tr.allAverage}%.`));
        const table = el("table", "rc-peer-table rc-track-table");
        const head = el("tr"); ["Score band on day one", "Companies", "Average change", "vs all"].forEach(h => head.append(el("th", null, h)));
        const thead = el("thead"); thead.append(head);
        const tbody = el("tbody");
        tr.bands.forEach(b => {
          const row = el("tr");
          row.append(el("td", null, b.label), el("td", "rc-p-rank", `${b.count}`),
            el("td", "rc-p-score", b.averageReturn == null ? "—" : `${b.averageReturn >= 0 ? "+" : ""}${b.averageReturn}%`),
            el("td", b.beatAll > 0 ? "good" : b.beatAll < 0 ? "bad" : "", b.beatAll == null ? "—" : `${b.beatAll >= 0 ? "+" : ""}${b.beatAll} pts`));
          tbody.append(row);
        });
        table.append(thead, tbody);
        track.append(table, el("p", "rc-rank-note", "Past results do not predict future returns. Prices only; dividends not included."));
      }
    }
    $("#rc-sector-grid")?.replaceChildren(...d.sectors.map(sec => {
      const card = el("div", "rc-sector-card");
      card.append(el("h4", null, sec.sectorName), el("small", null, `${sec.count} companies`));
      const ol = el("ol");
      sec.top.forEach(r => {
        const li = el("li");
        li.append(gradeLink(r.ticker, r.name), el("em", null, r.score.toFixed(1)));
        ol.append(li);
      });
      card.append(ol);
      return card;
    }));
  }

  async function copyPost() {
    const d = leaders.data;
    if (!d) return;
    const lines = d.top.slice(0, 5).map((r, i) => `${i + 1}. $${r.ticker} ${r.score.toFixed(1)} (Value ${r.grades.value}, Growth ${r.grades.growth}, Profit ${r.grades.profitability})`);
    let text = `Top-rated stocks by LensScore this week, graded against their own sector:\n\n${lines.join("\n")}`;
    if (d.movers?.up?.length) text += `\n\nBiggest riser: $${d.movers.up[0].ticker} ${d.movers.up[0].then.toFixed(1)} → ${d.movers.up[0].now.toFixed(1)}`;
    text += "\n\nEvery grade and the numbers behind it: impliedlens.com/lens-score";
    try {
      await navigator.clipboard.writeText(text);
      setText("#rc-post-status", "Copied. Paste it into X.");
    } catch (_) {
      window.prompt("Copy this post:", text);
    }
  }

  /* ── Email alerts ────────────────────────────────────────────────────── */
  let alertState = { list: [], limit: 0, loggedIn: null };
  const KIND_TEXT = { above: "rises to", below: "falls to", buy_zone: "reaches the buy zone", score: "grade change" };
  async function csrfToken() {
    try { const r = await fetch("/api/csrf", { credentials: "same-origin" }); const j = await r.json(); return j.token || ""; } catch (_) { return ""; }
  }
  async function loadAlerts() {
    try {
      const r = await fetch("/api/alerts", { credentials: "same-origin" });
      if (r.status === 401) { alertState = { list: [], limit: 0, loggedIn: false }; return renderAlerts(); }
      const j = await r.json();
      alertState = { list: j.alerts || [], limit: j.limit || 0, loggedIn: true };
    } catch (_) { alertState.loggedIn = alertState.loggedIn ?? null; }
    renderAlerts();
  }
  function renderAlerts() {
    const ul = $("#rc-alert-list");
    if (!ul) return;
    ul.replaceChildren();
    if (alertState.loggedIn === false) {
      const li = el("li", "rc-alert-login");
      const a = el("a", null, "Log in or create a free account");
      a.href = `/login?next=${encodeURIComponent(location.pathname + location.search)}`;
      li.append(a, document.createTextNode(" to get email alerts."));
      ul.append(li);
      return;
    }
    const mine = alertState.list.filter(a => a.active);
    const sorted = mine.filter(a => a.ticker === state.ticker).concat(mine.filter(a => a.ticker !== state.ticker));
    sorted.slice(0, 12).forEach(a => {
      const li = el("li");
      const txt = a.kind === "score" ? `${a.ticker} · any grade change` : a.kind === "buy_zone" ? `${a.ticker} · buy zone at ${money(a.level)}` : `${a.ticker} · ${KIND_TEXT[a.kind]} ${money(a.level)}`;
      li.append(el("span", a.ticker === state.ticker ? "here" : "", txt));
      const del = el("button", "rc-alert-del", "Remove");
      del.type = "button";
      del.setAttribute("aria-label", `Remove alert: ${txt}`);
      del.addEventListener("click", () => deleteAlert(a.id));
      li.append(del);
      ul.append(li);
    });
    if (alertState.limit) setText("#rc-alerts-title", `Email alerts · ${mine.length} of ${alertState.limit}`);
  }
  async function addAlert(kind, level) {
    if (alertState.loggedIn === false) { setText("#rc-alert-status", "Log in to set alerts."); return; }
    setText("#rc-alert-status", "Saving…");
    try {
      const r = await fetch("/api/alerts", {
        method: "POST", credentials: "same-origin",
        headers: { "Content-Type": "application/json", "X-CSRF-Token": await csrfToken() },
        body: JSON.stringify({ ticker: state.ticker, kind, level }),
      });
      const j = await r.json().catch(() => ({}));
      if (r.status === 401) { alertState.loggedIn = false; renderAlerts(); setText("#rc-alert-status", "Log in to set alerts."); return; }
      if (!r.ok) throw new Error(j.error || "Could not save the alert.");
      alertState.list = j.alerts || alertState.list;
      renderAlerts();
      setText("#rc-alert-status", j.duplicate ? "You already have that alert." : "Alert saved. We check every 10 minutes while the market is open.");
    } catch (error) { setText("#rc-alert-status", error.message); }
  }
  async function deleteAlert(id) {
    try {
      const r = await fetch(`/api/alerts/${encodeURIComponent(id)}`, { method: "DELETE", credentials: "same-origin", headers: { "X-CSRF-Token": await csrfToken() } });
      const j = await r.json().catch(() => ({}));
      if (r.ok) { alertState.list = j.alerts || alertState.list.filter(a => a.id !== id); renderAlerts(); setText("#rc-alert-status", "Alert removed."); }
    } catch (_) { setText("#rc-alert-status", "Could not remove the alert."); }
  }

  async function saveCurrentScenario() {
    const button = $("#save-scenario");
    const g = state.grades;
    if (!g || g.status !== "graded") { setText("#save-status", "Nothing to save until the company is graded."); return; }
    const now = new Date().toISOString();
    const price = state.bars.at(-1)?.close ?? null;
    const letters = g.factors.map(f => `${SHORT[f.key]} ${f.grade}`).join(", ");
    const entry = {
      id: Date.now(),
      type: "lensscore",
      ticker: state.ticker,
      title: `${state.ticker} LensScore ${g.score.toFixed(1)} (${letters})`,
      date: now,
      syncState: "local",
      data: {
        analysisKind: "lensscore",
        modelVersion: g.version,
        score: g.score,
        label: g.label,
        rank: g.rank,
        grades: Object.fromEntries(g.factors.map(f => [f.key, f.grade])),
        entryPrice: price,
        timing: state.result?.technical?.timing?.timingScore ?? null,
        savedAt: now,
      },
    };
    try {
      const savedKey = "impliedLens_savedAnalyses";
      const existing = JSON.parse(window.localStorage.getItem(savedKey) || "[]");
      window.localStorage.setItem(savedKey, JSON.stringify([entry, ...existing].slice(0, 100)));
    } catch (_) { /* local copy is optional */ }
    button.disabled = true;
    setText("#save-status", "Saving…");
    try {
      const csrfResponse = await fetch("/api/csrf", { credentials: "same-origin" });
      const csrfPayload = await csrfResponse.json().catch(() => ({}));
      const response = await fetch("/api/saves", {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json", "X-CSRF-Token": csrfPayload.token || "" },
        body: JSON.stringify({ ticker: entry.ticker, type: entry.type, label: entry.title, data: entry }),
      });
      const result = await response.json().catch(() => ({}));
      if (response.status === 401) { setText("#save-status", "Saved on this device. Log in to keep it in your library."); return; }
      if (!response.ok || !result.ok) throw new Error(result.error || "Account sync failed.");
      setText("#save-status", "Saved to your library.");
    } catch (error) {
      setText("#save-status", `Saved on this device. ${error.message}`);
    } finally {
      button.disabled = false;
    }
  }

  function bindEvents() {
    on("#theme-button, #theme-button-old", "click", toggleTheme);
    on("#ticker-form", "submit", event => {
      event.preventDefault();
      loadTicker($("#ticker-input").value.trim().toUpperCase());
    });
    $$(".quick-tickers [data-ticker]").forEach(button => button.addEventListener("click", () => loadTicker(button.dataset.ticker)));
    $$(".company-nav [data-view]").forEach(button => button.addEventListener("click", () => showView(button.dataset.view)));
    on("#open-chart-button", "click", () => { showView("chart"); $("#view-chart")?.scrollIntoView({ behavior: "smooth", block: "start" }); });
    $$(".chart-presets [data-preset]").forEach(button => button.addEventListener("click", () => {
      state.chartPreset = button.dataset.preset;
      $$(".chart-presets [data-preset]").forEach(item => item.classList.toggle("active", item === button));
      drawChart();
    }));
    on("#methodology-button", "click", () => $("#methodology-dialog").showModal());
    on("#methodology-button-old", "click", () => $("#methodology-dialog").showModal());
    on("#close-methodology", "click", () => $("#methodology-dialog").close());
    on("#methodology-dialog", "click", event => {
      if (event.target === $("#methodology-dialog")) $("#methodology-dialog").close();
    });
    on("#save-scenario", "click", saveCurrentScenario);
    on("#rc-copy-post", "click", copyPost);
    on("#rc-alert-zone", "click", () => {
      const zone = state.result?.technical?.zones?.support?.[0];
      if (!zone) { setText("#rc-alert-status", "There is no buy zone below the price right now."); return; }
      addAlert("buy_zone", Math.round(zone.upper * 100) / 100);
    });
    on("#rc-alert-score", "click", () => addAlert("score", null));
    on("#rc-alert-form", "submit", event => {
      event.preventDefault();
      const level = Number($("#rc-alert-level").value);
      if (!(level > 0)) { setText("#rc-alert-status", "Enter a price."); return; }
      addAlert($("#rc-alert-kind").value, level);
    });
    on("#rc-peek-all", "click", () => { showView("peers"); $(".company-nav")?.scrollIntoView({ behavior: "smooth", block: "start" }); });
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
    on("#price-chart", "mouseleave", () => { const t = $("#chart-tooltip"); if (t) t.hidden = true; });
    let resizeFrame = null;
    window.addEventListener("resize", () => {
      cancelAnimationFrame(resizeFrame);
      resizeFrame = requestAnimationFrame(drawChart);
    });
  }

  applySavedTheme();
  bindEvents();
  const initialParams = new URLSearchParams(window.location.search);
  const initialTicker = initialParams.get("ticker") || initialParams.get("symbol");
  showView(initialParams.get("view") || "snapshot");
  loadTicker((initialTicker || "AAPL").toUpperCase());
  loadAlerts();
})();
