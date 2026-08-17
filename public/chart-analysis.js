/* ═══════════════════════════════════════════════════════════════════════════
   Implied Lens — technical read

   Design constraint from the brief: this must never get in the way of someone
   who already knows how to read a chart.

     · Collapsed to a single line by default.
     · Makes no network request until it is opened. Nothing is computed on the
       server, and no model is called, unless the user asks for it.
     · One click on × hides it for good (persisted). The chart toolbar keeps a
       quiet "Read" toggle so it can come back.
     · Remembers open/closed per visitor, so opening it once does not commit
       you to seeing it forever, and closing it once is respected.
   ═══════════════════════════════════════════════════════════════════════════ */
(function () {
  "use strict";

  var PREF = "il-analysis-pref";
  var pref = { hidden: false, open: false };
  try { pref = Object.assign(pref, JSON.parse(localStorage.getItem(PREF) || "{}")); } catch (e) {}
  function save() { try { localStorage.setItem(PREF, JSON.stringify(pref)); } catch (e) {} }

  var cache = {};      // ticker:range → payload
  var busy = false;

  function el(tag, cls, html) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (html != null) n.innerHTML = html;
    return n;
  }

  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, function (ch) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[ch];
    });
  }

  /* ── the one-line preview, computed locally so it costs nothing ───────── */
  function localHeadline() {
    var TA = window.ILTA, S = window.S;
    if (!TA || !S || !S.data || !S.data.indicators) return null;
    var q = S.data.indicators.quote[0] || {};
    var c = (q.close || []).map(Number).filter(isFinite);
    if (c.length < 30) return null;
    var n = c.length, last = c[n - 1];
    var s50 = TA.sma(c, 50)[n - 1], s200 = TA.sma(c, 200)[n - 1];
    var r = TA.rsi(c, 14)[n - 1];
    var trend = s50 == null ? "—"
      : last > s50 && (s200 == null || last > s200) ? "Uptrend"
      : last < s50 && (s200 == null || last < s200) ? "Downtrend" : "Mixed";
    var bits = [trend];
    if (r != null) bits.push("RSI " + r.toFixed(0));
    if (s50 != null) bits.push((last >= s50 ? "+" : "−") + Math.abs((last - s50) / s50 * 100).toFixed(1) + "% vs 50D");
    return bits.join("  ·  ");
  }

  /* ── rendering ────────────────────────────────────────────────────────── */
  function signalRow(s) {
    var detail = (s.detail || []).join(". ");
    return '<div class="ilan-sig">' +
      '<div class="ilan-sig-head"><span class="ilan-sig-label">' + esc(s.label) + '</span>' +
      '<span class="ilan-sig-state">' + esc(s.state || "") + '</span></div>' +
      (s.value ? '<div class="ilan-sig-value">' + esc(s.value) + "</div>" : "") +
      (detail ? '<div class="ilan-sig-detail">' + esc(detail) + (detail.slice(-1) === "." ? "" : ".") + "</div>" : "") +
      "</div>";
  }

  function renderBody(box, data) {
    var body = box.querySelector(".ilan-body");
    if (!data) { body.innerHTML = '<div class="ilan-empty">No technical read available for this series.</div>'; return; }

    var html = '<div class="ilan-grid">' + (data.signals || []).map(signalRow).join("") + "</div>";

    if (data.invalidation) {
      html += '<div class="ilan-invalidation"><span class="ilan-inv-label">What would change this</span>' +
              "<p>" + esc(data.invalidation.text) + "</p></div>";
    }

    if (data.summary) {
      html += '<div class="ilan-summary">' +
        data.summary.split(/\n{2,}/).map(function (p) { return "<p>" + esc(p.trim()) + "</p>"; }).join("") +
        '<div class="ilan-source">' +
        (data.summarySource === "model"
          ? "Written from the computed signals above. No figure is introduced that is not in them."
          : "Generated directly from the computed signals above.") +
        "</div></div>";
    }

    html += '<div class="ilan-foot">' +
      esc(data.bars || "—") + " bars · " +
      esc((data.range || "").toUpperCase()) +
      (data.asOf ? " · as of " + esc(new Date(data.asOf).toLocaleDateString("en-US",
        { month: "short", day: "numeric", year: "numeric" })) : "") +
      " · Describes what the price series shows. Not advice, not a forecast." +
      "</div>";

    body.innerHTML = html;
  }

  function fetchRead(box) {
    var S = window.S;
    if (!S || !S.ticker || busy) return;
    var key = S.ticker + ":" + (S.range || "1y");
    if (cache[key]) { renderBody(box, cache[key]); return; }

    busy = true;
    box.querySelector(".ilan-body").innerHTML = '<div class="ilan-loading">Reading the series…</div>';
    fetch("/api/analysis/" + encodeURIComponent(S.ticker) +
          "?range=" + encodeURIComponent(S.range || "1y") + "&explain=1",
          { credentials: "same-origin" })
      .then(function (r) { return r.ok ? r.json() : Promise.reject(new Error("HTTP " + r.status)); })
      .then(function (j) { cache[key] = j; renderBody(box, j); })
      .catch(function () {
        box.querySelector(".ilan-body").innerHTML =
          '<div class="ilan-empty">Could not compute a read right now. The chart above is unaffected.</div>';
      })
      .finally(function () { busy = false; });
  }

  /* ── mount ────────────────────────────────────────────────────────────── */
  function mount() {
    if (pref.hidden) { removeBox(); syncToggle(); return; }
    var canvas = document.getElementById("price-chart");
    var slot = canvas && canvas.parentElement;
    var card = slot && slot.closest(".chart-wrap");
    if (!card) return;

    var box = card.querySelector(".il-analysis");
    if (!box) {
      box = el("div", "il-analysis");
      box.innerHTML =
        '<button type="button" class="ilan-bar" aria-expanded="false">' +
          '<span class="ilan-eyebrow">Technical read</span>' +
          '<span class="ilan-headline">—</span>' +
          '<span class="ilan-chev" aria-hidden="true">▾</span>' +
        "</button>" +
        '<button type="button" class="ilan-dismiss" title="Hide the technical read" aria-label="Hide the technical read">×</button>' +
        '<div class="ilan-body" hidden></div>';
      card.appendChild(box);

      box.querySelector(".ilan-bar").addEventListener("click", function () {
        pref.open = !pref.open; save();
        applyOpen(box);
        if (pref.open) fetchRead(box);
      });

      box.querySelector(".ilan-dismiss").addEventListener("click", function () {
        pref.hidden = true; pref.open = false; save();
        removeBox();
        syncToggle();
        if (typeof window.showToast === "function") {
          window.showToast("Technical read hidden. Turn it back on with “Read” in the chart toolbar.");
        }
      });
    }

    var head = localHeadline();
    box.querySelector(".ilan-headline").textContent = head || "Load a ticker to see the read";
    applyOpen(box);
    if (pref.open && window.S && S.ticker) fetchRead(box);
    syncToggle();
  }

  function applyOpen(box) {
    var body = box.querySelector(".ilan-body");
    var bar = box.querySelector(".ilan-bar");
    body.hidden = !pref.open;
    bar.setAttribute("aria-expanded", String(pref.open));
    box.classList.toggle("open", pref.open);
  }

  function removeBox() {
    var b = document.querySelector(".il-analysis");
    if (b) b.remove();
  }

  /* ── toolbar toggle so a hidden read can be recovered ─────────────────── */
  function syncToggle() {
    var btn = document.getElementById("il-read-toggle");
    if (!btn) return;
    btn.classList.toggle("on", !pref.hidden);
    btn.setAttribute("aria-pressed", String(!pref.hidden));
  }

  window.ilToggleRead = function () {
    pref.hidden = !pref.hidden;
    if (!pref.hidden) pref.open = true;
    save();
    if (pref.hidden) removeBox(); else mount();
    syncToggle();
  };

  function addToolbarButton() {
    var bar = document.getElementById("app-chart-toolbar");
    if (!bar || document.getElementById("il-read-toggle")) return;
    var b = el("button", "act-btn", '<i class="ti ti-bulb"></i> Read');
    b.type = "button";
    b.id = "il-read-toggle";
    b.title = "Show or hide the technical read beneath the chart";
    b.setAttribute("data-mobile-label", "Read");
    b.setAttribute("onclick", "ilToggleRead()");
    var right = bar.querySelector(".act-right");
    if (right) bar.insertBefore(b, right); else bar.appendChild(b);
    syncToggle();
  }

  /* Re-run whenever the chart re-renders (new ticker, new range, new type). */
  document.addEventListener("il-chart-rendered", function () {
    // A new series invalidates the previously fetched narrative.
    mount();
  });

  function boot() { addToolbarButton(); mount(); }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", boot);
  else boot();
  setTimeout(boot, 1000);
})();
