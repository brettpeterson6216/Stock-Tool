/* Report card share image.

   One click from the stock page's report card: a branded image of a stock's
   LensScore, its five sector-relative grades and the verdict, in three sizes
   (X landscape, square, portrait), with a suggested post. Every figure comes
   from the report card payload the page already loaded, so the image can
   never say something the card does not.

   stock-report-card.js calls ILReportCardShare.open({ ticker, name, grades,
   funds }). */
(function () {
  "use strict";

  var SIZES = {
    wide: { w: 1600, h: 900, label: "Landscape", note: "1600 × 900 · best for X" },
    square: { w: 1080, h: 1080, label: "Square", note: "1080 × 1080 · X, Instagram, LinkedIn" },
    tall: { w: 1080, h: 1350, label: "Portrait", note: "1080 × 1350 · Instagram feed" },
  };
  var C = {
    bg: "#0C0B09", line: "rgba(241,237,227,.10)", cream: "#F3EEE3", dim: "rgba(243,238,227,.62)", faint: "rgba(243,238,227,.40)",
    gold: "#E3A945", tile: "rgba(243,238,227,.035)",
  };
  var TONE = { strong: "#4FC48A", positive: "#A3CF63", neutral: "#E3A945", weak: "#F0904F", severe: "#FF6670", unknown: "rgba(243,238,227,.45)" };
  var F = {
    sans: '"Plus Jakarta Sans", "Segoe UI", Arial, sans-serif',
    serif: '"Instrument Serif", Georgia, serif',
    num: '"IBM Plex Sans", "Plus Jakarta Sans", Arial, sans-serif',
  };
  var SHORT = { value: "Value", growth: "Growth", profitability: "Profit", health: "Health", momentum: "Momentum" };

  var state = { size: "wide", headline: "", card: null };
  var root = null, canvas = null, fontsReady = null;

  function font(g, weight, size, family) {
    g.font = weight + " " + Math.round(size) + "px " + family;
    if ("wordSpacing" in g) g.wordSpacing = size < 30 ? Math.round(size * 0.12) + "px" : Math.round(size * 0.04) + "px";
  }
  function rr(g, x, y, w, h, r) {
    r = Math.min(r, w / 2, h / 2);
    g.beginPath(); g.moveTo(x + r, y); g.arcTo(x + w, y, x + w, y + h, r); g.arcTo(x + w, y + h, x, y + h, r);
    g.arcTo(x, y + h, x, y, r); g.arcTo(x, y, x + w, y, r); g.closePath();
  }
  function box(g, x, y, w, h, r, fill, stroke, lw) { rr(g, x, y, w, h, r); if (fill) { g.fillStyle = fill; g.fill(); } if (stroke) { g.strokeStyle = stroke; g.lineWidth = lw || 1.5; g.stroke(); } }
  function wrap(g, text, x, y, maxW, lineH, maxLines) {
    var words = String(text || "").split(/\s+/), line = "", lines = [];
    words.forEach(function (w) {
      var t = line ? line + " " + w : w;
      if (g.measureText(t).width > maxW && line) { lines.push(line); line = w; } else line = t;
    });
    if (line) lines.push(line);
    if (maxLines && lines.length > maxLines) { lines = lines.slice(0, maxLines); lines[maxLines - 1] = lines[maxLines - 1].replace(/\s*\S*$/, "") + "…"; }
    lines.forEach(function (l, i) { g.fillText(l, x, y + i * lineH); });
    return y + (lines.length - 1) * lineH;
  }
  function fit(g, text, weight, size, family, maxW) {
    var s = size; font(g, weight, s, family);
    while (g.measureText(text).width > maxW && s > 10) { s -= 2; font(g, weight, s, family); }
    return s;
  }
  function mark(g, x, y, s) {
    g.save(); g.translate(x, y);
    g.strokeStyle = C.gold; g.lineWidth = s * 0.09;
    g.beginPath(); g.arc(s / 2, s / 2, s * 0.42, 0, Math.PI * 2); g.stroke();
    g.fillStyle = C.gold;
    [0.28, 0.46, 0.64].forEach(function (fx, i) { var hh = s * (0.16 + i * 0.12); g.fillRect(s * fx - s * 0.05, s * 0.68 - hh, s * 0.1, hh); });
    g.restore();
  }
  function frame(g, W, H, u) {
    g.fillStyle = C.bg; g.fillRect(0, 0, W, H);
    var glow = g.createRadialGradient(W * 0.85, -H * 0.1, 10, W * 0.85, -H * 0.1, Math.max(W, H) * 0.75);
    glow.addColorStop(0, "rgba(227,169,69,.17)"); glow.addColorStop(1, "rgba(227,169,69,0)");
    g.fillStyle = glow; g.fillRect(0, 0, W, H);
    var P = 64 * u;
    mark(g, P, P - 4 * u, 34 * u);
    g.textBaseline = "middle";
    font(g, 700, 25 * u, F.sans); g.fillStyle = C.cream; g.fillText("Implied", P + 46 * u, P + 13 * u);
    var iw = g.measureText("Implied").width;
    font(g, 400, 29 * u, F.serif); g.fillStyle = C.gold; g.fillText("Lens", P + 46 * u + iw + 3 * u, P + 12 * u);
    font(g, 700, 15 * u, F.sans); g.fillStyle = C.dim; g.textAlign = "right";
    g.fillText("LENSSCORE REPORT CARD", W - P, P + 13 * u);
    g.textAlign = "left";
    g.strokeStyle = C.line; g.lineWidth = 1; g.beginPath(); g.moveTo(P, H - P - 30 * u); g.lineTo(W - P, H - P - 30 * u); g.stroke();
    font(g, 500, 15 * u, F.sans); g.fillStyle = C.faint;
    g.fillText("Grades rank the company against its sector peers, from SEC filings. Not investment advice.", P, H - P + 2 * u);
    font(g, 700, 17 * u, F.sans); g.fillStyle = C.gold; g.textAlign = "right";
    g.fillText("impliedlens.com", W - P, H - P + 2 * u);
    g.textAlign = "left"; g.textBaseline = "alphabetic";
    return { P: P, top: P + 84 * u, bottom: H - P - 60 * u };
  }

  function draw(target) {
    var sz = SIZES[state.size], cv = target || canvas, card = state.card;
    cv.width = sz.w; cv.height = sz.h;
    var g = cv.getContext("2d"), W = sz.w, H = sz.h, wide = W / H > 1.4;
    var u = wide ? 1 : W / 1000;
    var k = wide ? 1 : Math.max(1, H / W);   // portrait: spread the same parts down the taller card
    var f = frame(g, W, H, u), P = f.P, gr = card.grades, inner = W - 2 * P;
    var y = f.top + 30 * u;

    // Ticker + company, score on the right (landscape) or below (square/tall).
    font(g, 600, 22 * u, F.sans); g.fillStyle = C.gold;
    g.fillText("$" + card.ticker + (gr.rank && gr.rank.position ? "  ·  #" + gr.rank.position + " of " + gr.rank.of + " in " + (gr.rank.sectorName || gr.sectorName || "its sector") : ""), P, y);
    y += 62 * u;
    var head = state.headline || card.name || card.ticker;
    var scoreW = wide ? 300 * u : 0;
    var hs = fit(g, head, 700, (wide ? 64 : 60) * u, F.sans, inner - scoreW - 20 * u);
    g.fillStyle = C.cream; g.fillText(head, P, y);

    function scoreBlock(x, yy, align) {
      var col = TONE[gr.tone] || C.gold;
      g.textAlign = align;
      font(g, 700, 120 * u, F.num); g.fillStyle = col;
      var s = gr.score.toFixed(1); g.fillText(s, x - (align === "right" ? 64 * u : 0), yy);
      var sw = g.measureText(s).width;
      font(g, 500, 34 * u, F.num); g.fillStyle = C.dim;
      g.textAlign = "left";
      g.fillText("/10", align === "right" ? x - 60 * u : x + sw + 6 * u, yy);
      font(g, 700, 22 * u, F.sans); g.fillStyle = col; g.textAlign = align;
      g.fillText(gr.label || "", align === "right" ? x : x, yy + 40 * u);
      g.textAlign = "left";
    }
    if (wide) { scoreBlock(W - P, y + 6 * u, "right"); y += 110 * u; }
    else { y += (40 * k + 96) * u; scoreBlock(P, y, "left"); y += 30 * u; }

    // Five grade tiles.
    y += (wide ? 0 : 46 * k * k) * u;
    var tiles = gr.factors || [], gap = 14 * u, tw = (inner - gap * (tiles.length - 1)) / tiles.length, th = (wide ? 190 : 150 * k) * u;
    tiles.forEach(function (t, i) {
      var x = P + i * (tw + gap), col = TONE[t.tone] || TONE.unknown;
      box(g, x, y, tw, th, 16 * u, C.tile, col.replace(/^#(..)(..)(..)$/, function (_, r, gg, b) { return "rgba(" + parseInt(r, 16) + "," + parseInt(gg, 16) + "," + parseInt(b, 16) + ",.55)"; }), 2 * u);
      g.textAlign = "center";
      font(g, 600, (wide ? 22 : 19) * u, F.sans); g.fillStyle = C.dim; g.fillText(SHORT[t.key] || t.label, x + tw / 2, y + (wide ? 50 : 40 * k) * u);
      font(g, 700, (wide ? 78 : 62) * u, F.num); g.fillStyle = col; g.fillText(t.grade || "\u2013", x + tw / 2, y + (wide ? 132 : 106 * k) * u);
      if (Number.isFinite(t.percentile)) { font(g, 500, (wide ? 17 : 16) * u, F.sans); g.fillStyle = C.faint; g.fillText("beats " + t.percentile + "%" + (wide ? " of peers" : ""), x + tw / 2, y + (wide ? 168 : 134 * k) * u); }
      g.textAlign = "left";
    });
    y += th + (wide ? 64 : 52 * k * k) * u;

    // Verdict, then famous investors and the next report when there is room.
    font(g, 500, (wide ? 25 : 27) * u, F.sans); g.fillStyle = C.cream;
    var maxLines = wide ? 2 : 4;
    var vy = wrap(g, gr.verdict || "", P, y, inner, 36 * k * u, maxLines);
    var extra = [];
    if (card.funds && card.funds.length) extra.push("Held by " + card.funds.slice(0, 2).join(", ") + (card.funds.length > 2 ? " +" + (card.funds.length - 2) + " more famous investors" : ""));
    var n = gr.street && gr.street.nextEarnings;
    if (n && n.days >= 0 && n.days <= 45) extra.push("Earnings expected around " + new Date(n.date + "T12:00:00Z").toLocaleDateString("en-US", { month: "short", day: "numeric", timeZone: "UTC" }));
    if (extra.length && vy + 60 * u < f.bottom) {
      font(g, 600, 20 * u, F.sans); g.fillStyle = C.gold;
      wrap(g, extra.join("   ·   "), P, Math.min(vy + 56 * u, f.bottom), inner, 28 * u, wide ? 1 : 2);
    }
  }

  function postText() {
    var c = state.card, gr = c.grades;
    var lines = (gr.factors || []).map(function (f) { return (SHORT[f.key] || f.label) + " " + (f.grade || "–"); });
    var rank = gr.rank && gr.rank.position ? ", #" + gr.rank.position + " of " + gr.rank.of + " in " + (gr.rank.sectorName || gr.sectorName || "its sector") : "";
    return "$" + c.ticker + " report card: " + gr.score.toFixed(1) + "/10 (" + gr.label + ")" + rank + ".\n\n" + lines.join("\n") +
      "\n\nGraded against sector peers from SEC filings. Grade any stock free:\nimpliedlens.com/stock/" + encodeURIComponent(c.ticker);
  }

  function ensureFonts() {
    if (fontsReady) return fontsReady;
    if (!document.fonts || !document.fonts.load) return (fontsReady = Promise.resolve());
    fontsReady = Promise.all([
      document.fonts.load('700 40px "Plus Jakarta Sans"'), document.fonts.load('500 20px "Plus Jakarta Sans"'),
      document.fonts.load('400 40px "Instrument Serif"'), document.fonts.load('700 40px "IBM Plex Sans"'),
    ]).catch(function () {});
    return fontsReady;
  }
  function render() {
    if (!root || !state.card) return;
    root.querySelectorAll("[data-rcs]").forEach(function (b) { b.setAttribute("aria-pressed", String(state.size === b.getAttribute("data-rcs"))); });
    root.querySelector(".ilpc-size-note").textContent = SIZES[state.size].note;
    root.querySelector(".ilpc-post").value = postText();
    root.querySelector(".ilpc-head-in").placeholder = state.card.name || state.card.ticker;
    draw();
  }
  function fileName() { return state.card.ticker + "-report-card-" + state.size + ".png"; }
  function blob() { return new Promise(function (res) { canvas.toBlob(res, "image/png"); }); }
  function note(msg, ok) { if (typeof window.toast === "function") window.toast(msg, ok === false ? "red" : "green"); }
  function download() {
    blob().then(function (b) {
      var url = URL.createObjectURL(b), a = document.createElement("a");
      a.href = url; a.download = fileName(); document.body.appendChild(a); a.click();
      setTimeout(function () { a.remove(); URL.revokeObjectURL(url); }, 200);
      note("Image saved");
    });
  }
  function copyImage() {
    if (!navigator.clipboard || !window.ClipboardItem) return note("Copying images isn't supported in this browser. Use Download.", false);
    navigator.clipboard.write([new ClipboardItem({ "image/png": blob() })]).then(function () { note("Image copied. Paste it into your post."); }, function () { note("Couldn't copy. Use Download instead.", false); });
  }
  function share() {
    blob().then(function (b) {
      var file = new File([b], fileName(), { type: "image/png" }), data = { files: [file], text: postText() };
      if (navigator.canShare && navigator.canShare(data)) navigator.share(data).catch(function () {}); else download();
    });
  }
  function copyText() {
    var t = root.querySelector(".ilpc-post");
    (navigator.clipboard ? navigator.clipboard.writeText(t.value) : Promise.reject()).then(function () { note("Post text copied"); }, function () { t.select(); document.execCommand("copy"); note("Post text copied"); });
  }

  /* Uses the Valuation Lab card studio's sheet styles (projection-cards.js
     adds them); the few extra rules sit here. */
  function build() {
    if (window.ILProjectionCards && window.ILProjectionCards.ensureStyle) window.ILProjectionCards.ensureStyle();
    root = document.createElement("div");
    root.className = "ilpc"; root.hidden = true;
    root.innerHTML =
      '<div class="ilpc-back" data-close></div>' +
      '<div class="ilpc-sheet" role="dialog" aria-modal="true" aria-labelledby="ilrcs-title" tabindex="-1">' +
        '<header class="ilpc-head"><div><span class="ilpc-kicker">Share the report card</span><h2 id="ilrcs-title">Make a post-ready image</h2></div>' +
        '<button type="button" class="ilpc-x" data-close aria-label="Close"><i class="ti ti-x" aria-hidden="true"></i></button></header>' +
        '<div class="ilpc-body">' +
          '<div class="ilpc-controls">' +
            '<div class="ilpc-group"><span class="ilpc-lbl">Size</span><div class="ilpc-seg">' +
              Object.keys(SIZES).map(function (k) { return '<button type="button" data-rcs="' + k + '">' + SIZES[k].label + '</button>'; }).join("") +
            '</div><span class="ilpc-size-note"></span></div>' +
            '<label class="ilpc-group"><span class="ilpc-lbl">Headline <em>optional</em></span><input class="ilpc-head-in" type="text" maxlength="60" autocomplete="off"></label>' +
          '</div>' +
          '<div class="ilpc-stage"><canvas class="ilpc-canvas" aria-label="Preview of the report card image"></canvas></div>' +
          '<div class="ilpc-actions">' +
            '<button type="button" class="ilpc-btn is-gold" data-act="download"><i class="ti ti-download" aria-hidden="true"></i> Download PNG</button>' +
            '<button type="button" class="ilpc-btn" data-act="copy">Copy image</button>' +
            '<button type="button" class="ilpc-btn ilpc-share" data-act="share" hidden>Share</button>' +
            '<label class="ilpc-group ilpc-postwrap"><span class="ilpc-lbl">Suggested post</span><textarea class="ilpc-post" rows="6"></textarea></label>' +
            '<button type="button" class="ilpc-btn" data-act="text">Copy post text</button>' +
          '</div>' +
        '</div>' +
      '</div>';
    document.body.appendChild(root);
    canvas = root.querySelector(".ilpc-canvas");
    if (navigator.canShare && window.File) {
      try { if (navigator.canShare({ files: [new File([""], "x.png", { type: "image/png" })] })) root.querySelector(".ilpc-share").hidden = false; } catch (e) {}
    }
    root.addEventListener("click", function (e) {
      if (e.target.closest("[data-close]")) return close();
      var s = e.target.closest("[data-rcs]");
      if (s) { state.size = s.getAttribute("data-rcs"); render(); return; }
      var a = e.target.closest("[data-act]");
      if (!a) return;
      var act = a.getAttribute("data-act");
      if (act === "download") download(); else if (act === "copy") copyImage(); else if (act === "share") share(); else if (act === "text") copyText();
    });
    root.querySelector(".ilpc-head-in").addEventListener("input", function (e) { state.headline = e.target.value.trim(); draw(); });
    document.addEventListener("keydown", function (e) { if (e.key === "Escape" && root && !root.hidden) close(); });
  }

  function open(card) {
    if (!card || !card.grades || card.grades.status !== "graded") return;
    if (!root) build();
    state.card = card; state.headline = "";
    root.querySelector(".ilpc-head-in").value = "";
    root.hidden = false;
    document.documentElement.classList.add("ilpc-open");
    root.querySelector(".ilpc-sheet").focus({ preventScroll: true });
    render();
    ensureFonts().then(render);
    if (typeof window.track === "function") window.track("report_card_share_opened", { ticker: card.ticker });
  }
  function close() {
    if (!root) return;
    root.hidden = true;
    document.documentElement.classList.remove("ilpc-open");
  }

  window.ILReportCardShare = { open: open, close: close, _draw: draw, _state: state, _post: postText };
})();
