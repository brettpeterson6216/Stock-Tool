(function () {
  "use strict";

  const ACCENTS = {
    gold: { main: "#D9A441", soft: "rgba(217,164,65,.16)", line: "rgba(217,164,65,.34)" },
    emerald: { main: "#42C98A", soft: "rgba(66,201,138,.14)", line: "rgba(66,201,138,.32)" },
    cobalt: { main: "#4D91DF", soft: "rgba(77,145,223,.14)", line: "rgba(77,145,223,.32)" },
    violet: { main: "#A36BD4", soft: "rgba(163,107,212,.14)", line: "rgba(163,107,212,.32)" },
  };
  let accentName = "gold";
  let lastCard = null;

  function text(id, fallback = "—") {
    const node = document.getElementById(id);
    return (node?.textContent || "").trim() || fallback;
  }

  function researchState() {
    const state = window.IL_STATE || {};
    const ticker = text("r-ticker", state.ticker || "").replace(/[^A-Z0-9.^-]/gi, "");
    return {
      ticker,
      company: text("r-name", ticker || "Implied Lens research"),
      exchange: text("r-exchange", ""),
      price: text("r-price"),
      change: text("r-change", "Latest session"),
      asOf: text("r-time", "Latest provider observation"),
      source: (document.getElementById("quote-source")?.innerText || "Provider-sourced market data").replace(/\s+/g, " ").trim(),
      range: state.range || "1y",
    };
  }

  function metricPairs() {
    const pairs = [];
    document.querySelectorAll("#metrics-grid .metric-card").forEach(card => {
      const labelNode = card.querySelector(".m-lbl");
      const label = labelNode
        ? Array.from(labelNode.childNodes).filter(node => node.nodeType === Node.TEXT_NODE).map(node => node.textContent).join(" ").replace(/\s+/g, " ").trim()
        : "";
      const value = card.querySelector(".m-val")?.textContent?.trim();
      if (label && value && value !== "—" && pairs.length < 6) pairs.push({ label, value });
    });
    return pairs;
  }

  function chartCanvas() {
    try {
      const chart = window.__ilChart?.chart;
      if (chart?.takeScreenshot) return chart.takeScreenshot();
    } catch (_) {}
    const fallback = document.getElementById("price-chart");
    return fallback?.width > 20 && fallback?.height > 20 ? fallback : null;
  }

  function roundRect(ctx, x, y, w, h, radius) {
    const r = Math.min(radius, w / 2, h / 2);
    ctx.beginPath();
    ctx.moveTo(x + r, y);
    ctx.arcTo(x + w, y, x + w, y + h, r);
    ctx.arcTo(x + w, y + h, x, y + h, r);
    ctx.arcTo(x, y + h, x, y, r);
    ctx.arcTo(x, y, x + w, y, r);
    ctx.closePath();
  }

  function fillRound(ctx, x, y, w, h, radius, fill, stroke) {
    roundRect(ctx, x, y, w, h, radius);
    ctx.fillStyle = fill;
    ctx.fill();
    if (stroke) {
      ctx.strokeStyle = stroke;
      ctx.lineWidth = 1;
      ctx.stroke();
    }
  }

  function wrapText(ctx, value, x, y, maxWidth, lineHeight, maxLines) {
    const words = String(value || "").trim().split(/\s+/);
    const lines = [];
    let line = "";
    for (const word of words) {
      const test = line ? `${line} ${word}` : word;
      if (ctx.measureText(test).width > maxWidth && line) {
        lines.push(line);
        line = word;
      } else line = test;
    }
    if (line) lines.push(line);
    const visible = lines.slice(0, maxLines);
    if (lines.length > maxLines) {
      let last = visible[maxLines - 1];
      while (ctx.measureText(`${last}…`).width > maxWidth && last.length) last = last.slice(0, -1);
      visible[maxLines - 1] = `${last}…`;
    }
    visible.forEach((entry, i) => ctx.fillText(entry, x, y + i * lineHeight));
    return y + visible.length * lineHeight;
  }

  function drawMark(ctx, x, y, size, accent) {
    ctx.save();
    ctx.translate(x, y);
    ctx.strokeStyle = accent.main;
    ctx.lineWidth = 3;
    ctx.beginPath();
    ctx.arc(0, 0, size * .34, 0, Math.PI * 2);
    ctx.stroke();
    ctx.strokeStyle = "rgba(242,240,234,.34)";
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.arc(0, 0, size * .48, 0, Math.PI * 2);
    ctx.stroke();
    ctx.fillStyle = accent.main;
    [-.18, 0, .18].forEach((dx, i) => ctx.fillRect(dx * size - 2, (i - 1) * 4, 4, 13 - i * 2));
    ctx.restore();
  }

  function drawGrid(ctx, width, height) {
    ctx.save();
    ctx.strokeStyle = "rgba(255,255,255,.026)";
    ctx.lineWidth = 1;
    for (let x = 48; x < width; x += 64) {
      ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, height); ctx.stroke();
    }
    for (let y = 46; y < height; y += 64) {
      ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(width, y); ctx.stroke();
    }
    ctx.restore();
  }

  function drawCard() {
    const canvas = document.getElementById("share-studio-canvas");
    if (!canvas) return null;
    const ctx = canvas.getContext("2d");
    const W = canvas.width;
    const H = canvas.height;
    const accent = ACCENTS[accentName] || ACCENTS.gold;
    const state = researchState();
    const metrics = metricPairs();
    const headline = document.getElementById("share-studio-caption")?.value?.trim() || "Price, trend, and expectations in one view";

    ctx.clearRect(0, 0, W, H);
    const background = ctx.createLinearGradient(0, 0, W, H);
    background.addColorStop(0, "#090E10");
    background.addColorStop(.55, "#070A0C");
    background.addColorStop(1, "#050708");
    ctx.fillStyle = background;
    ctx.fillRect(0, 0, W, H);
    drawGrid(ctx, W, H);

    const glow = ctx.createRadialGradient(1080, 380, 30, 1080, 380, 620);
    glow.addColorStop(0, accent.soft);
    glow.addColorStop(1, "rgba(0,0,0,0)");
    ctx.fillStyle = glow;
    ctx.fillRect(0, 0, W, H);

    ctx.strokeStyle = "rgba(255,255,255,.11)";
    ctx.lineWidth = 2;
    roundRect(ctx, 18, 18, W - 36, H - 36, 28);
    ctx.stroke();
    ctx.strokeStyle = accent.line;
    ctx.lineWidth = 1;
    roundRect(ctx, 28, 28, W - 56, H - 56, 22);
    ctx.stroke();

    drawMark(ctx, 88, 82, 45, accent);
    ctx.fillStyle = "#F3F0E9";
    ctx.font = '600 22px "Plus Jakarta Sans", Arial';
    ctx.letterSpacing = "4px";
    ctx.fillText("IMPLIED LENS", 126, 90);
    ctx.letterSpacing = "0px";
    ctx.fillStyle = accent.main;
    ctx.font = '600 13px "JetBrains Mono", Consolas';
    ctx.fillText("RESEARCH FRAME", 126, 115);

    ctx.textAlign = "right";
    ctx.fillStyle = "#7D8581";
    ctx.font = '500 13px "JetBrains Mono", Consolas';
    ctx.fillText(`${String(state.range).toUpperCase()} · ${state.asOf}`, W - 74, 86);
    ctx.fillStyle = accent.main;
    ctx.fillText("IMPLIEDLENS.COM", W - 74, 112);
    ctx.textAlign = "left";

    ctx.fillStyle = "#F4F1EA";
    ctx.font = '400 52px "Instrument Serif", Georgia, serif';
    wrapText(ctx, headline, 72, 188, W - 144, 58, 2);

    fillRound(ctx, 72, 292, 456, 142, 16, "rgba(14,20,22,.92)", "rgba(255,255,255,.10)");
    ctx.fillStyle = accent.main;
    ctx.font = '700 17px "JetBrains Mono", Consolas';
    ctx.fillText(state.ticker || "TICKER", 96, 330);
    ctx.fillStyle = "#8F9894";
    ctx.font = '500 15px "Plus Jakarta Sans", Arial';
    ctx.fillText(state.company, 96, 358);
    ctx.fillStyle = "#F4F1EA";
    ctx.font = '500 40px "JetBrains Mono", Consolas';
    ctx.fillText(state.price, 96, 408);
    ctx.fillStyle = /-|▼|down/i.test(state.change) ? "#F06A75" : "#45D590";
    ctx.font = '600 16px "JetBrains Mono", Consolas';
    ctx.fillText(state.change, 318, 405);

    const chart = chartCanvas();
    const chartX = 568, chartY = 264, chartW = 958, chartH = 445;
    fillRound(ctx, chartX, chartY, chartW, chartH, 18, "rgba(10,15,17,.94)", "rgba(255,255,255,.10)");
    if (chart) {
      ctx.save();
      roundRect(ctx, chartX + 12, chartY + 12, chartW - 24, chartH - 24, 12);
      ctx.clip();
      const ratio = chart.width / chart.height;
      const target = chartW / chartH;
      let sx = 0, sy = 0, sw = chart.width, sh = chart.height;
      if (ratio > target) { sw = chart.height * target; sx = (chart.width - sw) / 2; }
      else { sh = chart.width / target; sy = (chart.height - sh) / 2; }
      ctx.drawImage(chart, sx, sy, sw, sh, chartX + 12, chartY + 12, chartW - 24, chartH - 24);
      ctx.restore();
    } else {
      ctx.fillStyle = "#6F7874";
      ctx.font = '500 20px "Plus Jakarta Sans", Arial';
      ctx.textAlign = "center";
      ctx.fillText("Load a company chart to populate this frame", chartX + chartW / 2, chartY + chartH / 2);
      ctx.textAlign = "left";
    }

    const available = metrics.length ? metrics.slice(0, 6) : [
      { label: "52W POSITION", value: "Load chart" },
      { label: "RSI (14)", value: "—" },
      { label: "MA 50", value: "—" },
    ];
    const boxGap = 12;
    const boxW = (W - 144 - boxGap * (available.length - 1)) / available.length;
    available.forEach((metric, i) => {
      const x = 72 + i * (boxW + boxGap);
      fillRound(ctx, x, 744, boxW, 86, 12, "rgba(13,18,20,.9)", "rgba(255,255,255,.08)");
      ctx.fillStyle = "#6F7874";
      ctx.font = '600 11px "JetBrains Mono", Consolas';
      ctx.fillText(metric.label.toUpperCase().slice(0, 22), x + 16, 774);
      ctx.fillStyle = "#EDEBE5";
      ctx.font = '600 20px "JetBrains Mono", Consolas';
      ctx.fillText(metric.value.slice(0, 16), x + 16, 808);
    });

    ctx.fillStyle = "#68706D";
    ctx.font = '500 11px "Plus Jakarta Sans", Arial';
    ctx.fillText((state.source || "Provider-sourced market data").slice(0, 150), 72, 862);
    ctx.textAlign = "right";
    ctx.fillText("Educational research · Not investment advice", W - 72, 862);
    ctx.textAlign = "left";
    lastCard = canvas;
    return canvas;
  }

  function openShareStudio() {
    const state = researchState();
    if (!state.ticker || !chartCanvas()) {
      if (typeof window.toast === "function") window.toast("Load a company chart first", "red");
      const tickerInput = document.getElementById("main-ticker");
      tickerInput?.focus();
      return;
    }
    const modal = document.getElementById("share-studio");
    if (!modal) return;
    modal.hidden = false;
    document.body.classList.add("share-studio-open");
    requestAnimationFrame(() => {
      modal.classList.add("open");
      drawCard();
    });
  }

  function closeShareStudio() {
    const modal = document.getElementById("share-studio");
    if (!modal) return;
    modal.classList.remove("open");
    document.body.classList.remove("share-studio-open");
    setTimeout(() => { modal.hidden = true; }, 180);
  }

  function setShareAccent(name, button) {
    if (!ACCENTS[name]) return;
    accentName = name;
    document.querySelectorAll(".share-accent").forEach(node => node.classList.toggle("active", node === button));
    drawCard();
  }

  function downloadShareStudio() {
    const canvas = drawCard() || lastCard;
    if (!canvas) return;
    const state = researchState();
    const link = document.createElement("a");
    link.download = `${state.ticker || "implied-lens"}-${state.range || "chart"}-research-frame.png`;
    link.href = canvas.toDataURL("image/png", 1);
    link.click();
    if (typeof window.toast === "function") window.toast("1600 × 900 research frame downloaded", "green");
  }

  function install() {
    window.openShareStudio = openShareStudio;
    window.closeShareStudio = closeShareStudio;
    window.renderShareStudio = drawCard;
    window.setShareAccent = setShareAccent;
    window.downloadShareStudio = downloadShareStudio;
    window.exportExpandedChart = openShareStudio;
    document.getElementById("share-studio")?.addEventListener("click", event => {
      if (event.target.id === "share-studio") closeShareStudio();
    });
    document.addEventListener("keydown", event => {
      if (event.key === "Escape" && document.getElementById("share-studio")?.classList.contains("open")) closeShareStudio();
    });
    setTimeout(() => { window.exportExpandedChart = openShareStudio; }, 1400);
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", install);
  else install();
}());
