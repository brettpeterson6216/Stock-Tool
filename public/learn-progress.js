/* Academy progress and quizzes. Progress is kept in this browser only
   (localStorage), wrapped so a blocked or private-mode store simply means
   no progress is shown — every lesson still works without it. */
(function () {
  "use strict";
  var KEY = "il-academy-done";

  function load() {
    try { var v = JSON.parse(localStorage.getItem(KEY) || "[]"); return Array.isArray(v) ? v : []; }
    catch (_) { return []; }
  }
  function save(list) {
    try { localStorage.setItem(KEY, JSON.stringify(list)); return true; } catch (_) { return false; }
  }
  function track(name, props) {
    try {
      fetch("/api/track", {
        method: "POST", credentials: "same-origin", keepalive: true,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ event: name, properties: props || {} }),
      }).catch(function () {});
    } catch (_) {}
  }

  function wireQuiz() {
    document.querySelectorAll(".lxl-q").forEach(function (q) {
      var answer = Number(q.getAttribute("data-answer"));
      q.querySelectorAll("button[data-opt]").forEach(function (b) {
        b.addEventListener("click", function () {
          if (q.classList.contains("is-answered")) return;
          q.classList.add("is-answered");
          var pick = Number(b.getAttribute("data-opt"));
          b.classList.add(pick === answer ? "is-right" : "is-wrong");
          var right = q.querySelector('button[data-opt="' + answer + '"]');
          if (right) right.classList.add("is-right");
          var why = q.querySelector(".lxl-why");
          if (why) why.open = true;
          var all = document.querySelectorAll(".lxl-q");
          var done = document.querySelectorAll(".lxl-q.is-answered");
          if (all.length && all.length === done.length) {
            var main = document.querySelector(".lxl-lesson");
            var correct = document.querySelectorAll(".lxl-q button.is-wrong").length === 0;
            track("academy_quiz_completed", { lesson: main && main.getAttribute("data-lesson"), all_correct: correct });
          }
        });
      });
    });
  }

  function lessonPage(main) {
    var slug = main.getAttribute("data-lesson");
    var btn = document.getElementById("lxl-complete");
    var done = load();
    if (!btn) return;
    function paint() {
      var isDone = load().indexOf(slug) !== -1;
      btn.textContent = isDone ? "Completed ✓" : "Mark lesson complete";
      btn.classList.toggle("is-done", isDone);
    }
    btn.hidden = false;
    paint();
    btn.addEventListener("click", function () {
      var list = load();
      var i = list.indexOf(slug);
      if (i === -1) { list.push(slug); track("academy_lesson_completed", { lesson: slug }); }
      else list.splice(i, 1);
      save(list);
      paint();
    });
    if (done.indexOf(slug) === -1) track("academy_lesson_viewed", { lesson: slug });
  }

  function indexPage() {
    var done = load();
    var links = document.querySelectorAll(".lxl-list a[data-lesson]");
    var total = links.length;
    var count = 0, firstOpen = null;
    links.forEach(function (a) {
      var isDone = done.indexOf(a.getAttribute("data-lesson")) !== -1;
      a.classList.toggle("is-done", isDone);
      if (isDone) count++; else if (!firstOpen) firstOpen = a;
    });
    var bar = document.getElementById("lxl-progress");
    if (bar && count > 0) {
      bar.hidden = false;
      var fill = document.getElementById("lxl-progress-fill");
      if (fill) fill.style.width = Math.round((count / total) * 100) + "%";
      var label = document.getElementById("lxl-progress-label");
      if (label) label.textContent = count + " of " + total + " complete";
      var cont = document.getElementById("lxl-continue");
      if (cont && firstOpen) {
        cont.href = firstOpen.getAttribute("href");
        cont.textContent = "Continue: " + (firstOpen.querySelector("strong") || firstOpen).textContent + " →";
      } else if (cont && !firstOpen) {
        cont.textContent = "Course complete. Review lesson 1 →";
      }
    }
  }

  function init() {
    wireQuiz();
    var main = document.querySelector(".lxl-lesson");
    if (main) lessonPage(main);
    else if (document.querySelector(".lxl-list")) indexPage();
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
