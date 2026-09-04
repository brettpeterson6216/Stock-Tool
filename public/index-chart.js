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

  /* The chart is drawn at the container's real pixel size rather than at a
     fixed viewBox stretched to fit. preserveAspectRatio="none" scaled x and y
     by different factors, which is why axis labels came out 1.44x wide and
     clipped, why dots had to be faked out of line caps, and why every stroke
     needed non-scaling-stroke to keep one weight. At 1:1 none of that is
     true: a circle is a circle and a pixel is a pixel. The cost is having to
     redraw on resize, which is what the observer below is for. */
  window.ilRenderIndexChart = function (host, indexes) {
    if (!host) return;
    if (host.ilxObserver) { host.ilxObserver.disconnect(); host.ilxObserver = null; }
    host.ilxSeries = indexes;

    var drawn = draw(host, indexes);

    if (typeof ResizeObserver === "function") {
      var lastW = host.clientWidth;
      var pending = 0;
      var ro = new ResizeObserver(function () {
        var w = host.clientWidth;
        if (!w || Math.abs(w - lastW) < 2) return;
        lastW = w;
        // Coalesce the burst a drag produces into one redraw per frame.
        if (pending) cancelAnimationFrame(pending);
        pending = requestAnimationFrame(function () {
          pending = 0;
          draw(host, host.ilxSeries);
        });
      });
      ro.observe(host);
      host.ilxObserver = ro;
    }
    return drawn;
  };

  function draw(host, indexes) {
    if (!host) return null;
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

    // Real pixels, measured from the container. Never below a width where the
    // plot would be narrower than the axis gutter.
    var W = Math.max(320, Math.round(host.clientWidth) || 960);
    var H = 320, PAD_L = 6, PAD_R = 54, PAD_T = 14, PAD_B = 26;
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
      viewBox: "0 0 " + W + " " + H, width: W, height: H,
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

    /* Gridlines in the SVG; their labels in HTML. The labels were moved out
       when the chart was still stretched to fit, which distorted them 1.44x
       and clipped "+9.13%" to "+9.13:". The chart is drawn at real pixels now
       so SVG text would be safe again, but positioned HTML inherits the
       page's font stack and theme tokens directly, so it stays. */
    var ticks = 4;
    var axis = document.createElement("div");
    axis.className = "ilx-axis";
    for (var t = 0; t <= ticks; t += 1) {
      var pct = lo + ((hi - lo) * t) / ticks;
      var gy = y(pct);
      svg.appendChild(el("line", { class: "ilx-grid", x1: PAD_L, x2: PAD_L + plotW, y1: gy, y2: gy }));
      var lab = document.createElement("span");
      lab.className = "ilx-ylab";
      lab.style.top = gy.toFixed(1) + "px";
      lab.textContent = fmtPct(pct);
      axis.appendChild(lab);
    }

    series.forEach(function (s) {
      var d = s.points.map(function (p, i) {
        return (i ? "L" : "M") + x(p.slot).toFixed(2) + " " + y(p.pct).toFixed(2);
      }).join(" ");
      s.path = el("path", { class: "ilx-line", d: d, style: "stroke:" + s.colour });
      svg.appendChild(s.path);
      s.dot = el("circle", { class: "ilx-dot", r: 3.5, style: "fill:" + s.colour, opacity: 0 });
      svg.appendChild(s.dot);
    });

    var cross = el("line", { class: "ilx-cross", y1: PAD_T, y2: PAD_T + plotH, opacity: 0 });
    svg.appendChild(cross);

    host.appendChild(svg);
    host.appendChild(axis);

    // Readout and legend are HTML: they carry live values and interaction,
    // and they inherit the page's type and theme without restating any of it.
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
        s.dot.setAttribute("cx", x(p.slot));
        s.dot.setAttribute("cy", y(p.pct));
        s.dot.setAttribute("opacity", 1);
        s.key.querySelector(".ilx-key-val").textContent = fmtPct(p.pct);
      });
      readout.textContent = fmtWhen(stamp, intraday);
    }

    svg.addEventListener("pointermove", function (e) { trace(e.clientX); });
    svg.addEventListener("pointerleave", latest);
    svg.addEventListener("pointerdown", function (e) { trace(e.clientX); });

    latest();
    return { series: series, intraday: intraday, width: W };
  }
}());
