/* ═══════════════════════════════════════════════════════════════════════════
   Overlaid index chart with a traceable crosshair.

   Three indexes on one set of axes. Their levels are nowhere near each other -
   the Dow is around 41,000 while the S&P is around 5,800 - so plotting raw
   values would put two of the three lines flat against an edge and tell you
   nothing. Every series is normalised to percent change from the first point
   in the window, which is what a comparison chart is actually for: the shapes
   become comparable and the y-axis means one thing for all three.

   What this is: several lines, a crosshair that follows the pointer with each
   series' value at that moment, a legend that toggles series, and a shared
   time axis. What it is not: candlesticks, indicators, drawing tools, zoom or
   pan. Those belong to a charting library, and a shallow imitation of them
   would be worse than their absence.
   ═══════════════════════════════════════════════════════════════════════════ */
(function () {
  "use strict";

  var NS = "http://www.w3.org/2000/svg";
  var COLORS = ["var(--ilx-a)", "var(--ilx-b)", "var(--ilx-c)"];

  function el(name, attrs) {
    var node = document.createElementNS(NS, name);
    for (var k in attrs) if (attrs[k] != null) node.setAttribute(k, attrs[k]);
    return node;
  }

  function fmtPct(v) {
    if (!Number.isFinite(v)) return "—";
    return (v >= 0 ? "+" : "") + v.toFixed(2) + "%";
  }

  function fmtWhen(seconds, intraday) {
    if (!Number.isFinite(seconds)) return "";
    var d = new Date(seconds * 1000);
    var date = d.toLocaleDateString("en-US", { month: "short", day: "numeric" });
    if (!intraday) return date;
    return date + " " + d.toLocaleTimeString("en-US", { hour: "numeric", minute: "2-digit" });
  }

  /* Series arrive on their own timestamps - a holiday or a halt in one index
     is not a gap in another - so they share one axis built from the union of
     every timestamp any series reported, sorted. Each series is then drawn
     against that axis by position in it.

     Two things fall out of that. Series stay aligned: lining them up by array
     index instead would slide one against the others by however many bars
     they differ. And the axis is ordinal rather than real time, so the
     sixty-five closed hours of a weekend take up no width - the same reason a
     trading chart does not leave two-thirds of itself blank. Mapping x to
     real seconds looked correct and drew a month of markets as a row of thin
     stripes separated by voids. */
  function buildSlots(series) {
    var seen = Object.create(null);
    series.forEach(function (s) {
      (s.stamps || []).forEach(function (at) {
        if (Number.isFinite(at)) seen[at] = true;
      });
    });
    var slots = Object.keys(seen).map(Number).sort(function (a, b) { return a - b; });
    if (slots.length < 2) return null;
    var index = Object.create(null);
    for (var i = 0; i < slots.length; i += 1) index[slots[i]] = i;
    return { slots: slots, index: index, last: slots.length - 1 };
  }

  /* A close of zero is not a price, it is a bar that has not printed. Plotting
     it gives -100% and drags the axis to the floor, which is what put a cliff
     at the front of the chart and flattened every real move into the bottom
     edge. Holes are dropped; the line joins across them, which is honest for
     a missing bar and invisible for a missing session. */
  function normalise(s, frame) {
    var base = null, i;
    for (i = 0; i < s.closes.length; i += 1) {
      var c0 = Number(s.closes[i]);
      if (Number.isFinite(c0) && c0 > 0) { base = c0; break; }
    }
    if (base == null) return [];
    var out = [];
    for (i = 0; i < s.closes.length; i += 1) {
      var c = Number(s.closes[i]);
      var at = Number(s.stamps[i]);
      if (!Number.isFinite(c) || c <= 0 || !Number.isFinite(at)) continue;
      var slot = frame.index[at];
      if (slot == null) continue;
      out.push({ at: at, slot: slot, pct: ((c - base) / base) * 100, raw: c });
    }
    return out;
  }

  window.ilRenderIndexChart = function (host, indexes) {
    if (!host) return;
    host.innerHTML = "";

    var usable = (indexes || []).filter(function (s) {
      return s && Array.isArray(s.closes) && Array.isArray(s.stamps) && s.closes.length > 1 &&
        s.closes.length === s.stamps.length;
    });
    if (!usable.length) {
      var msg = document.createElement("p");
      msg.className = "ilx-empty";
      msg.textContent = "Index history is unavailable right now.";
      host.appendChild(msg);
      return null;
    }

    var frame = buildSlots(usable);
    if (!frame) return null;

    var series = usable.map(function (s, i) {
      return { symbol: s.symbol, name: s.name || s.symbol, colour: COLORS[i % COLORS.length],
               points: normalise(s, frame), on: true, interval: s.interval };
    }).filter(function (s) { return s.points.length > 1; });
    if (!series.length) return null;

    var intraday = usable.some(function (s) { return s.interval && s.interval !== "1d"; });

    // Geometry in view units; the SVG scales to its container.
    var W = 1000, H = 320, PAD_L = 6, PAD_R = 54, PAD_T = 14, PAD_B = 26;
    var plotW = W - PAD_L - PAD_R, plotH = H - PAD_T - PAD_B;

    var lo = Infinity, hi = -Infinity;
    series.forEach(function (s) {
      s.points.forEach(function (p) {
        if (p.pct < lo) lo = p.pct;
        if (p.pct > hi) hi = p.pct;
      });
    });
    if (!(hi > lo)) { hi = lo + 1; }
    var padY = (hi - lo) * 0.12;
    lo -= padY; hi += padY;

    var x = function (slot) { return PAD_L + (slot / frame.last) * plotW; };
    var y = function (pct) { return PAD_T + (1 - (pct - lo) / (hi - lo)) * plotH; };

    var svg = el("svg", {
      viewBox: "0 0 " + W + " " + H, preserveAspectRatio: "none",
      class: "ilx-svg", role: "img",
      "aria-label": "Percent change of " + series.map(function (s) { return s.name; }).join(", ") +
        " over the selected window"
    });

    // Zero line: the level every series started at, which is what the
    // normalised numbers are measured against.
    var zeroY = y(0);
    if (zeroY > PAD_T && zeroY < PAD_T + plotH) {
      svg.appendChild(el("line", { class: "ilx-zero", x1: PAD_L, x2: PAD_L + plotW, y1: zeroY, y2: zeroY }));
    }

    /* Gridlines in the SVG; their labels in HTML. Text inside a
       preserveAspectRatio="none" SVG is stretched horizontally by whatever
       ratio the container happens to be - at 1440px wide that is 1.44x - and
       the glyphs then run past the viewBox edge and get clipped, which is
       exactly what the first version did to "+9.13%". Positioned HTML is not
       distorted and cannot be clipped by the viewBox. */
    var ticks = 4;
    var axis = document.createElement("div");
    axis.className = "ilx-axis";
    for (var t = 0; t <= ticks; t += 1) {
      var pct = lo + ((hi - lo) * t) / ticks;
      var gy = y(pct);
      svg.appendChild(el("line", { class: "ilx-grid", x1: PAD_L, x2: PAD_L + plotW, y1: gy, y2: gy }));
      var lab = document.createElement("span");
      lab.className = "ilx-ylab";
      lab.style.top = ((gy / H) * 100).toFixed(3) + "%";
      lab.textContent = fmtPct(pct);
      axis.appendChild(lab);
    }

    series.forEach(function (s) {
      var d = s.points.map(function (p, i) {
        return (i ? "L" : "M") + x(p.slot).toFixed(2) + " " + y(p.pct).toFixed(2);
      }).join(" ");
      s.path = el("path", { class: "ilx-line", d: d, style: "stroke:" + s.colour });
      svg.appendChild(s.path);
      /* The dot is two zero-length lines with round caps rather than a
         circle. preserveAspectRatio="none" scales x and y by different
         factors, so a circle drawn in view units comes out as an ellipse -
         at 1024px the plot is squeezed to about half its width and the dots
         turn into flat lozenges. A round line cap is sized by stroke-width,
         and non-scaling-stroke measures stroke-width in screen pixels, so
         this stays a true circle at every container width. */
      s.dot = el("g", { class: "ilx-dot", opacity: 0 });
      s.dotHalo = el("line", { class: "ilx-dot-halo" });
      s.dotCore = el("line", { class: "ilx-dot-core", style: "stroke:" + s.colour });
      s.dot.appendChild(s.dotHalo);
      s.dot.appendChild(s.dotCore);
      svg.appendChild(s.dot);
    });

    var cross = el("line", { class: "ilx-cross", y1: PAD_T, y2: PAD_T + plotH, opacity: 0 });
    svg.appendChild(cross);

    host.appendChild(svg);
    host.appendChild(axis);

    // Readout, legend and hit surface live in HTML rather than SVG so text
    // stays at real pixel sizes: the SVG is stretched by preserveAspectRatio
    // none, which would distort anything drawn inside it.
    var readout = document.createElement("div");
    readout.className = "ilx-readout";
    host.appendChild(readout);

    var legend = document.createElement("div");
    legend.className = "ilx-legend";
    series.forEach(function (s) {
      var b = document.createElement("button");
      b.type = "button";
      b.className = "ilx-key is-on";
      b.setAttribute("aria-pressed", "true");
      b.innerHTML = '<span class="ilx-swatch" style="background:' + s.colour + '"></span>' +
        '<span class="ilx-key-name"></span><span class="ilx-key-val"></span>';
      b.querySelector(".ilx-key-name").textContent = s.name;
      b.addEventListener("click", function () {
        s.on = !s.on;
        b.classList.toggle("is-on", s.on);
        b.setAttribute("aria-pressed", String(s.on));
        s.path.style.opacity = s.on ? "" : "0";
        if (!s.on) s.dot.setAttribute("opacity", 0);
      });
      s.key = b;
      legend.appendChild(b);
    });
    host.appendChild(legend);

    function placeDot(s, px, py) {
      [s.dotHalo, s.dotCore].forEach(function (n) {
        n.setAttribute("x1", px); n.setAttribute("x2", px);
        n.setAttribute("y1", py); n.setAttribute("y2", py);
      });
    }

    function latest() {
      readout.textContent = "";
      series.forEach(function (s) {
        var last = s.points[s.points.length - 1];
        s.key.querySelector(".ilx-key-val").textContent = last ? fmtPct(last.pct) : "—";
        s.dot.setAttribute("opacity", 0);
      });
      cross.setAttribute("opacity", 0);
    }

    function nearest(points, slot) {
      var best = null, bestD = Infinity;
      for (var i = 0; i < points.length; i += 1) {
        var d = Math.abs(points[i].slot - slot);
        if (d < bestD) { bestD = d; best = points[i]; }
        if (d === 0) break;
      }
      return best;
    }

    function trace(clientX) {
      var box = svg.getBoundingClientRect();
      if (!box.width) return;
      var ratio = Math.min(1, Math.max(0, (clientX - box.left) / box.width));
      var slot = Math.round(Math.min(1, Math.max(0, (ratio * W - PAD_L) / plotW)) * frame.last);
      var viewX = x(slot);

      cross.setAttribute("x1", viewX);
      cross.setAttribute("x2", viewX);
      cross.setAttribute("opacity", 1);

      var stamp = null;
      series.forEach(function (s) {
        if (!s.on) { s.dot.setAttribute("opacity", 0); s.key.querySelector(".ilx-key-val").textContent = "—"; return; }
        var p = nearest(s.points, slot);
        if (!p) return;
        if (stamp == null) stamp = p.at;
        placeDot(s, x(p.slot), y(p.pct));
        s.dot.setAttribute("opacity", 1);
        s.key.querySelector(".ilx-key-val").textContent = fmtPct(p.pct);
      });
      readout.textContent = fmtWhen(stamp, intraday);
    }

    svg.addEventListener("pointermove", function (e) { trace(e.clientX); });
    svg.addEventListener("pointerleave", latest);
    svg.addEventListener("pointerdown", function (e) { trace(e.clientX); });

    latest();
    return { series: series, intraday: intraday };
  };
}());
