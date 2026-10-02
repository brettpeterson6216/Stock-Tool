/* The in-app Learn section shows the real Academy.

   It used to carry its own five-module course (EDU_LESSONS in app-legacy.js),
   separate from the twenty lessons at /learn, with separate progress. This
   draws the Academy from public/lessons-data.js (window.IL_LESSONS) instead:
   five levels, each lesson linking to its page, ticked from the same
   browser-stored list the lesson pages write (il-academy-done). */
(function () {
  "use strict";

  var KEY = "il-academy-done";

  function done() {
    try { var v = JSON.parse(localStorage.getItem(KEY) || "[]"); return Array.isArray(v) ? v : []; }
    catch (_) { return []; }
  }

  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  function render() {
    var host = document.getElementById("il-ac-levels");
    var data = window.IL_LESSONS;
    if (!host || !data || !Array.isArray(data.lessons) || !data.lessons.length) return;
    var lessons = data.lessons;
    var finished = done();
    var levels = [];
    lessons.forEach(function (l) {
      var key = l.level || 0;
      var lv = levels.filter(function (x) { return x.level === key; })[0];
      if (!lv) { lv = { level: key, name: String(l.group || "").replace(/^Level\s+\d+\s*·\s*/i, ""), items: [] }; levels.push(lv); }
      lv.items.push(l);
    });
    var next = lessons.filter(function (l) { return finished.indexOf(l.slug) < 0; })[0];
    var count = lessons.filter(function (l) { return finished.indexOf(l.slug) >= 0; }).length;
    var n = 0;

    host.innerHTML = levels.map(function (lv) {
      var lvDone = lv.items.filter(function (l) { return finished.indexOf(l.slug) >= 0; }).length;
      return '<div class="il-ac-level">' +
        '<div class="il-ac-level-head"><span class="il-ac-level-num">' + lv.level + '</span>' +
        '<div><b>' + esc(lv.name) + '</b><span>' + lvDone + ' of ' + lv.items.length + ' done</span></div></div>' +
        '<ol class="il-ac-list">' + lv.items.map(function (l) {
          n += 1;
          var isDone = finished.indexOf(l.slug) >= 0;
          var isNext = next && next.slug === l.slug;
          return '<li class="il-ac-item' + (isDone ? " is-done" : "") + (isNext ? " is-next" : "") + '">' +
            '<a href="/learn/' + encodeURIComponent(l.slug) + '">' +
            '<span class="il-ac-mark" aria-hidden="true">' + (isDone ? "&#10003;" : n) + '</span>' +
            '<span class="il-ac-title">' + esc(l.title) + '</span>' +
            '<span class="il-ac-min">' + (l.minutes ? l.minutes + " min" : "") + (isDone ? '<span class="sr-only"> · done</span>' : "") + '</span>' +
            '</a></li>';
        }).join("") + '</ol></div>';
    }).join("");

    var doneEl = document.getElementById("il-ac-done"), totalEl = document.getElementById("il-ac-total");
    var fill = document.getElementById("il-ac-fill"), nextEl = document.getElementById("il-ac-next");
    if (doneEl) doneEl.textContent = String(count);
    if (totalEl) totalEl.textContent = String(lessons.length);
    if (fill) fill.style.width = Math.round(count / lessons.length * 100) + "%";
    if (nextEl) {
      if (next) {
        nextEl.href = "/learn/" + encodeURIComponent(next.slug);
        nextEl.innerHTML = (count ? "Continue: " : "Start: ") + esc(next.title) + ' <span aria-hidden="true">&rarr;</span>';
      } else {
        nextEl.href = "/learn";
        nextEl.innerHTML = 'All lessons done. Review the Academy <span aria-hidden="true">&rarr;</span>';
      }
    }
  }

  function wireWorkshop() {
    var btn = document.getElementById("il-ac-workshop");
    if (!btn) return;
    btn.addEventListener("click", function () {
      if (typeof window.openLearnWorkshop === "function") {
        window.openLearnWorkshop();
        var host = document.getElementById("edu-workshop");
        if (host && host.scrollIntoView) host.scrollIntoView({ behavior: "smooth", block: "start" });
      } else {
        window.location.href = "/learn/thesis";
      }
    });
  }

  function init() { render(); wireWorkshop(); }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
  // Progress changes in another tab (a lesson page) show up when you come back.
  window.addEventListener("storage", function (e) { if (e.key === KEY) render(); });
  window.addEventListener("focus", render);
})();
