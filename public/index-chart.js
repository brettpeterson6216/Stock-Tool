/* ═══════════════════════════════════════════════════════════════════════════
   Overlaid index chart with a traceable crosshair.

   Several indexes on one set of axes. Their levels are nowhere near each other
   - the Dow is around 41,000 while the S&P is around 5,800 - so plotting raw
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

  /* ── The y scale ──────────────────────────────────────────────────────────
     Fitting the axis tightly to the data and padding it by a flat percentage
     produced gridlines at +9.13%, +6.42%, +3.72% - arbitrary numbers nobody
     reads, and the loudest single tell that a chart was drawn by hand rather
     than by something that does this for a living. Every real one rounds
     outward to clean intervals first and labels those. */
  function niceScale(lo, hi, target) {
    if (!Number.isFinite(lo) || !Number.isFinite(hi)) { lo = 0; hi = 1; }
    if (!(hi > lo)) { hi = lo + 1; }
    var rawStep = (hi - lo) / Math.max(1, target);
    var mag = Math.pow(10, Math.floor(Math.log(rawStep) / Math.LN10));
    var norm = rawStep / mag;
    var step = (norm <= 1 ? 1 : norm <= 2 ? 2 : norm <= 2.5 ? 2.5 : norm <= 5 ? 5 : 10) * mag;
    var start = Math.floor(lo / step) * step;
    var end = Math.ceil(hi / step) * step;
    var ticks = [];
    for (var i = 0; start + i * step <= end + step / 2; i += 1) ticks.push(start + i * step);
    return { lo: start, hi: end, step: step, ticks: ticks };
  }

  function fmtPct(v, step) {
    if (!Number.isFinite(v)) return "—";
    var dp = step == null ? 2 : (step >= 1 ? 0 : step >= 0.5 ? 1 : 2);
    var n = Number(v.toFixed(dp));
    if (Object.is(n, -0)) n = 0;
    return (n > 0 ? "+" : "") + n.toFixed(dp) + "%";
  }

  /* ── The x scale ──────────────────────────────────────────────────────────
     A chart with no time axis reads as unfinished however good the line is.
     The label format follows the window: a day wants clock times, a year wants
     months, and stamping the year on every tick of a one-month chart is noise. */
  function tickFormat(spanSeconds) {
    if (spanSeconds <= 3 * 86400) {
      return function (d) { return d.toLocaleTimeString("en-US", { hour: "numeric", minute: "2-digit" }); };
    }
    if (spanSeconds <= 200 * 86400) {
      return function (d) { return d.toLocaleDateString("en-US", { month: "short", day: "numeric" }); };
    }
    return function (d) { return d.toLocaleDateString("en-US", { month: "short", year: "2-digit" }); };
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

    var intraday = usable.some(function (s) {
      return s.interval && s.interval !== "1d" && s.interval !== "1wk";
    });

    // Real pixels, measured from the container. The bottom padding is the
    // x-axis band: a fixed height that excludes it is what gives a chart card
    // its own little scrollbar.
    var W = Math.max(320, Math.round(host.clientWidth) || 960);
    var H = 372, PAD_L = 8, PAD_R = 62, PAD_T = 18, PAD_B = 34;
    var plotW = W - PAD_L - PAD_R, plotH = H - PAD_T - PAD_B;

    var dataLo = Infinity, dataHi = -Infinity;
    series.forEach(function (s) {
      s.points.forEach(function (p) {
        if (p.pct < dataLo) dataLo = p.pct;
        if (p.pct > dataHi) dataHi = p.pct;
      });
    });
    var scale = niceScale(dataLo, dataHi, Math.max(3, Math.min(6, Math.round(plotH / 64))));
    var lo = scale.lo, hi = scale.hi;

    var x = function (slot) { return PAD_L + (slot / frame.last) * plotW; };
    var y = function (pct) { return PAD_T + (1 - (pct - lo) / (hi - lo)) * plotH; };

    var svg = el("svg", {
      viewBox: "0 0 " + W + " " + H, width: W, height: H,
      class: "ilx-svg", role: "img",
      "aria-label": "Percent change of " + series.map(function (s) { return s.name; }).join(", ") +
        " over the selected window"
    });

    /* Gridlines in the SVG; their labels in HTML. The labels were moved out
       when the chart was still stretched to fit, which distorted them 1.44x
       and clipped "+9.13%" to "+9.13:". The chart is drawn at real pixels now
       so SVG text would be safe again, but positioned HTML inherits the
       page's font stack and theme tokens directly, so it stays. */
    var axis = document.createElement("div");
    axis.className = "ilx-axis";
    scale.ticks.forEach(function (pct) {
      var gy = y(pct);
      if (gy < PAD_T - 0.5 || gy > PAD_T + plotH + 0.5) return;
      /* Zero is the level every series started at, which is what the
         normalised numbers are measured against, so it is drawn one step
         stronger than the rest of the grid - and solid, like them. A dashed
         rule reads as a projection or a threshold when it is just an origin. */
      svg.appendChild(el("line", {
        class: Math.abs(pct) < scale.step / 100 ? "ilx-zero" : "ilx-grid",
        x1: PAD_L, x2: PAD_L + plotW, y1: gy, y2: gy
      }));
      var lab = document.createElement("span");
      lab.className = "ilx-ylab";
      lab.style.top = gy.toFixed(1) + "px";
      lab.textContent = fmtPct(pct, scale.step);
      axis.appendChild(lab);
    });

    // Time axis. Roughly one label per 130px, snapped to real data slots so a
    // label never names a moment the chart does not contain.
    var span = frame.slots[frame.last] - frame.slots[0];
    var fmtTick = tickFormat(span);
    var wantTicks = Math.max(2, Math.min(8, Math.floor(plotW / 130)));
    var xband = document.createElement("div");
    xband.className = "ilx-xaxis";
    xband.style.height = PAD_B + "px";
    for (var t = 0; t <= wantTicks; t += 1) {
      var slot = Math.round((frame.last * t) / wantTicks);
      var gx = x(slot);
      if (t > 0 && t < wantTicks) {
        svg.appendChild(el("line", { class: "ilx-vgrid", x1: gx, x2: gx, y1: PAD_T, y2: PAD_T + plotH }));
      }
      var xl = document.createElement("span");
      // The edge labels align to the plot edge instead of centring on it, or
      // half of "Aug 26" hangs off the left of the card and gets clipped. This
      // is a class rather than an inline transform because the stylesheet's
      // rule carries !important, which an inline style does not beat.
      xl.className = "ilx-xlab" + (t === 0 ? " at-start" : t === wantTicks ? " at-end" : "");
      xl.style.left = gx.toFixed(1) + "px";
      xl.textContent = fmtTick(new Date(frame.slots[slot] * 1000));
      xband.appendChild(xl);
    }

    series.forEach(function (s) {
      var d = s.points.map(function (p, i) {
        return (i ? "L" : "M") + x(p.slot).toFixed(2) + " " + y(p.pct).toFixed(2);
      }).join(" ");
      s.path = el("path", { class: "ilx-line", d: d, style: "stroke:" + s.colour });
      svg.appendChild(s.path);
    });

    var cross = el("line", { class: "ilx-cross", y1: PAD_T, y2: PAD_T + plotH, opacity: 0 });
    svg.appendChild(cross);

    // Dots last so they sit above every line, each with a ring in the surface
    // colour so it stays legible where two series cross.
    series.forEach(function (s) {
      s.dot = el("circle", { class: "ilx-dot", r: 4, style: "fill:" + s.colour, opacity: 0 });
      svg.appendChild(s.dot);
    });

    host.appendChild(svg);
    host.appendChild(axis);
    host.appendChild(xband);

    // The crosshair's moment rides the time axis in a pill, the way it does on
    // a trading chart, rather than floating loose in a corner of the plot.
    var readout = document.createElement("div");
    readout.className = "ilx-readout";
    readout.hidden = true;
    xband.appendChild(readout);

    var legend = document.createElement("div");
    legend.className = "ilx-legend";
    series.forEach(function (s) {
      var b = document.createElement("button");
      b.type = "button";
      b.className = "ilx-key is-on";
      b.setAttribute("aria-pressed", "true");
      // A line key, not a filled box: the legend mirrors the mark it stands for.
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
      readout.hidden = true;
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
      readout.hidden = stamp == null;
      // Keep the pill inside the plot rather than letting it hang off an edge.
      readout.style.left = Math.min(W - 4, Math.max(4, viewX)) + "px";
      readout.style.transform =
        viewX < 46 ? "translateX(0)" : viewX > W - 46 ? "translateX(-100%)" : "translateX(-50%)";
    }

    svg.addEventListener("pointermove", function (e) { trace(e.clientX); });
    svg.addEventListener("pointerleave", latest);
    svg.addEventListener("pointerdown", function (e) { trace(e.clientX); });

    latest();
    return { series: series, intraday: intraday, width: W, ticks: scale.ticks };
  }
}());
