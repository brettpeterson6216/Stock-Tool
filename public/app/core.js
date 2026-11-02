/* ═══════════════════════════════════════════════════════════════════════════
   ImpliedLens app core — shared by every rebuilt page.

   Small on purpose: an API helper that understands the plan gates, number
   formatting, the top bar with one search, the phone bottom bar, the account
   menu, toasts, tooltips and a dialog. Pages build on window.IL.
   ═══════════════════════════════════════════════════════════════════════════ */
(function () {
  "use strict";

  var IL = window.IL = window.IL || {};

  /* ── DOM helpers ─────────────────────────────────────────────────────── */
  var ESC = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
  IL.h = function (v) { return String(v == null ? "" : v).replace(/[&<>"']/g, function (c) { return ESC[c]; }); };
  IL.$ = function (sel, root) { return (root || document).querySelector(sel); };
  IL.$$ = function (sel, root) { return Array.prototype.slice.call((root || document).querySelectorAll(sel)); };

  /* ── Formatting ──────────────────────────────────────────────────────── */
  var MINUS = "−";
  function finite(v) { return typeof v === "number" && isFinite(v); }
  function toNum(v) {
    if (v && typeof v === "object" && "raw" in v) v = v.raw;
    if (v === null || v === undefined || v === "") return null;
    var n = Number(v);
    return isFinite(n) ? n : null;
  }
  IL.n = toNum;
  IL.finite = finite;
  function sign(n) { return n > 0 ? "+" : n < 0 ? MINUS : ""; }
  function fixed(n, d) {
    return Math.abs(n).toLocaleString("en-US", { minimumFractionDigits: d, maximumFractionDigits: d });
  }
  IL.fmt = {
    MINUS: MINUS,
    price: function (v) {
      var n = toNum(v); if (n === null) return "—";
      var d = Math.abs(n) >= 1 ? 2 : 4;
      return (n < 0 ? MINUS : "") + "$" + fixed(n, d);
    },
    money: function (v, digits) {
      var n = toNum(v); if (n === null) return "—";
      var a = Math.abs(n), s = n < 0 ? MINUS : "", d = digits == null ? null : digits;
      if (a >= 1e12) return s + "$" + fixed(a / 1e12, d == null ? 2 : d) + "T";
      if (a >= 1e9) return s + "$" + fixed(a / 1e9, d == null ? (a >= 1e11 ? 0 : 1) : d) + "B";
      if (a >= 1e6) return s + "$" + fixed(a / 1e6, d == null ? (a >= 1e8 ? 0 : 1) : d) + "M";
      if (a >= 1e3) return s + "$" + fixed(a / 1e3, d == null ? 1 : d) + "K";
      return s + "$" + fixed(a, d == null ? 2 : d);
    },
    count: function (v) {
      var n = toNum(v); if (n === null) return "—";
      var a = Math.abs(n), s = n < 0 ? MINUS : "";
      if (a >= 1e9) return s + fixed(a / 1e9, 2) + "B";
      if (a >= 1e6) return s + fixed(a / 1e6, 1) + "M";
      if (a >= 1e3) return s + fixed(a / 1e3, 1) + "K";
      return s + fixed(a, 0);
    },
    /* pct takes a percent number (12.5 → "12.5%"). */
    pct: function (v, d) {
      var n = toNum(v); if (n === null) return "—";
      return (n < 0 ? MINUS : "") + fixed(n, d == null ? 1 : d) + "%";
    },
    spct: function (v, d) {
      var n = toNum(v); if (n === null) return "—";
      return sign(n) + fixed(n, d == null ? 1 : d) + "%";
    },
    schg: function (v) {
      var n = toNum(v); if (n === null) return "—";
      return sign(n) + fixed(n, 2);
    },
    mult: function (v) {
      var n = toNum(v); if (n === null || n <= 0) return "—";
      return fixed(n, n >= 100 ? 0 : 1) + "×";
    },
    eps: function (v) {
      var n = toNum(v); if (n === null) return "—";
      return (n < 0 ? MINUS : "") + "$" + fixed(n, 2);
    },
    num: function (v, d) {
      var n = toNum(v); if (n === null) return "—";
      return (n < 0 ? MINUS : "") + fixed(n, d == null ? 2 : d);
    },
    cls: function (v) { var n = toNum(v); return n === null || n === 0 ? "flat" : n > 0 ? "up" : "down"; },
    date: function (v, opts) {
      if (!v) return "—";
      var d = typeof v === "number" ? new Date(v < 1e12 ? v * 1000 : v) : new Date(String(v).length === 10 ? v + "T12:00:00Z" : v);
      if (isNaN(d)) return "—";
      return d.toLocaleDateString("en-US", Object.assign({ month: "short", day: "numeric", year: "numeric", timeZone: "UTC" }, opts || {}));
    },
    shortDate: function (v) { return IL.fmt.date(v, { year: undefined }); },
  };

  /* ── API ─────────────────────────────────────────────────────────────── */
  var csrfToken = null;
  function csrf() {
    if (csrfToken) return Promise.resolve(csrfToken);
    return fetch("/api/csrf", { credentials: "same-origin" })
      .then(function (r) { return r.json(); })
      .then(function (j) { csrfToken = j.token; return csrfToken; });
  }
  IL.csrf = csrf;

  /* Resolves to { ok, status, data, gate } and never throws: every caller
     needs to draw something whatever happened. gate is "login" (needs a free
     account), "pro" (needs Pro), "limit" (daily lookups used) or null. */
  var getCache = new Map();
  IL.api = function (path, opts) {
    opts = opts || {};
    var method = (opts.method || "GET").toUpperCase();
    if (method === "GET" && !opts.fresh && getCache.has(path)) return getCache.get(path);
    var run = (method === "GET" ? Promise.resolve(null) : csrf()).then(function (token) {
      var headers = { Accept: "application/json" };
      if (token) headers["X-CSRF-Token"] = token;
      if (opts.body !== undefined) headers["Content-Type"] = "application/json";
      return fetch(path, {
        method: method, headers: headers, credentials: "same-origin",
        body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
      });
    }).then(function (r) {
      return r.text().then(function (t) {
        var data = null;
        try { data = t ? JSON.parse(t) : null; } catch (_) { data = null; }
        var gate = null;
        if (r.status === 429 && data && data.limitReached) gate = "limit";
        else if (r.status === 401 || (data && data.requiresLogin && !r.ok)) gate = "login";
        else if (r.status === 403 && data && data.requiresPro) gate = "pro";
        return { ok: r.ok, status: r.status, data: data, gate: gate };
      });
    }).catch(function () {
      return { ok: false, status: 0, data: null, gate: null };
    });
    if (method === "GET") {
      getCache.set(path, run);
      run.then(function (res) { if (!res.ok) getCache.delete(path); });
    }
    return run;
  };

  /* ── Who is signed in ────────────────────────────────────────────────── */
  var mePromise = null;
  IL.me = function () {
    if (!mePromise) {
      /* One sign-in check per page: shell.js makes it, the app reads it. */
      mePromise = (window.ILShell ? window.ILShell.me() : IL.api("/api/auth/me").then(function (res) {
        var u = res.ok && res.data && res.data.user ? res.data.user : null;
        if (u) u.plan = u.effectivePlan || u.plan || "free";
        return u;
      })).then(function (u) { IL.user = u; return u; });
    }
    return mePromise;
  };
  IL.isPro = function (u) { u = u || IL.user; return !!u && (u.plan === "pro" || u.plan === "trial"); };
  IL.loginHref = function () { return "/login?next=" + encodeURIComponent(location.pathname + location.search); };
  IL.signupHref = function () { return "/signup?next=" + encodeURIComponent(location.pathname + location.search); };

  /* ── Icons (inline, stroke) ──────────────────────────────────────────── */
  var I = {
    search: '<path d="M11 18a7 7 0 1 0 0-14 7 7 0 0 0 0 14Z"/><path d="m20 20-3.5-3.5"/>',
    home: '<path d="M4 10.5 12 4l8 6.5V20a1 1 0 0 1-1 1h-5v-6h-4v6H5a1 1 0 0 1-1-1z"/>',
    research: '<path d="M4 19V5"/><path d="M4 19h16"/><path d="m7 15 4-4 3 3 5-6"/>',
    screener: '<path d="M4 6h16"/><path d="M7 12h10"/><path d="M10 18h4"/>',
    star: '<path d="m12 3 2.7 5.6 6.1.9-4.4 4.3 1 6.1L12 17l-5.4 2.9 1-6.1-4.4-4.3 6.1-.9z"/>',
    bell: '<path d="M6 8a6 6 0 0 1 12 0c0 7 3 9 3 9H3s3-2 3-9"/><path d="M10 21h4"/>',
    lock: '<rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/>',
    learn: '<path d="M3 7l9-4 9 4-9 4z"/><path d="M7 9v5c0 1.5 2.5 3 5 3s5-1.5 5-3V9"/>',
    sun: '<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/>',
    moon: '<path d="M20 14.5A8 8 0 0 1 9.5 4 8 8 0 1 0 20 14.5Z"/>',
    out: '<path d="M15 4h4a1 1 0 0 1 1 1v14a1 1 0 0 1-1 1h-4"/><path d="M10 17l5-5-5-5"/><path d="M15 12H4"/>',
    user: '<circle cx="12" cy="8" r="4"/><path d="M4 21c1.5-4 4.5-6 8-6s6.5 2 8 6"/>',
    folder: '<path d="M3 6a1 1 0 0 1 1-1h5l2 2h9a1 1 0 0 1 1 1v10a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1z"/>',
    arrow: '<path d="M5 12h14"/><path d="m13 6 6 6-6 6"/>',
    ext: '<path d="M14 4h6v6"/><path d="M20 4 10 14"/><path d="M19 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V6a1 1 0 0 1 1-1h5"/>',
    check: '<path d="m5 12 5 5 9-10"/>',
    info: '<circle cx="12" cy="12" r="9"/><path d="M12 11v5"/><path d="M12 8h.01"/>',
    doc: '<path d="M7 3h7l5 5v12a1 1 0 0 1-1 1H7a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1z"/><path d="M14 3v5h5"/>',
    expand: '<path d="M4 9V4h5"/><path d="M20 9V4h-5"/><path d="M4 15v5h5"/><path d="M20 15v5h-5"/>',
    share: '<path d="M12 15V3"/><path d="m7 8 5-5 5 5"/><path d="M5 13v6a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1v-6"/>',
    download: '<path d="M12 4v11"/><path d="m7 10 5 5 5-5"/><path d="M5 20h14"/>',
    spark: '<path d="M12 3v4M12 17v4M3 12h4M17 12h4"/><path d="m6.5 6.5 2 2M15.5 15.5l2 2M6.5 17.5l2-2M15.5 8.5l2-2"/>',
    plus: '<path d="M12 5v14M5 12h14"/>',
    globe: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18"/><path d="M12 3a14 14 0 0 1 0 18a14 14 0 0 1 0-18"/>',
    pulse: '<path d="M3 12h4l3-7 4 14 3-7h4"/>',
  };
  IL.icon = function (name, size) {
    var s = size || 16;
    return '<svg width="' + s + '" height="' + s + '" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' + (I[name] || "") + "</svg>";
  };

  /* ── Theme ───────────────────────────────────────────────────────────── */
  IL.theme = function () { return document.documentElement.getAttribute("data-theme") === "dark" ? "dark" : "light"; };
  IL.setTheme = function (t) {
    if (t === "dark") document.documentElement.setAttribute("data-theme", "dark");
    else document.documentElement.removeAttribute("data-theme");
    try { localStorage.setItem("il-theme", t); } catch (_) {}
    if (window.syncBrowserChrome) window.syncBrowserChrome();
    document.dispatchEvent(new CustomEvent("il:theme", { detail: t }));
  };

  /* ── Shell: top bar and phone tab bar come from shell.js, the same file
     every page on the site uses; this adds the app's footer. ─────────── */
  IL.shell = function (active) {
    document.body.classList.add("il-app");
    if (window.ILShell) window.ILShell.mount({ active: active });
    var foot = document.getElementById("il-foot");
    if (foot) {
      foot.className = "il-foot";
      foot.innerHTML =
        "<span>\u00a9 " + new Date().getFullYear() + " ImpliedLens. Research, not investment advice.</span>" +
        '<a href="/data-sources">Data sources</a><a href="/pricing" data-show="upgrade">Pricing</a><a href="/learn">Learn</a>' +
        '<a href="/privacy">Privacy</a><a href="/terms">Terms</a><a href="/support">Support</a>';
    }
  };

  /* Index funds and sector ETFs for the day, from /api/market/landing-summary
     (cached five minutes on the server and in this tab). */
  IL.marketSummary = function () {
    try { var c = JSON.parse(sessionStorage.getItem("il-mkt") || "null"); if (c && Date.now() - c.at < 5 * 60 * 1000) return Promise.resolve(c.data); } catch (_) {}
    return IL.api("/api/market/landing-summary?window=1M").then(function (res) {
      if (!res.ok || !res.data) return null;
      try { sessionStorage.setItem("il-mkt", JSON.stringify({ at: Date.now(), data: res.data })); } catch (_) {}
      return res.data;
    });
  };
  /* Company names from filings: drop state suffixes ("/De", "/New/") and
     fix all-caps. */
  IL.cleanName = function (n) {
    n = String(n || "").replace(/\s*\/[A-Za-z]{2,4}\/?\s*$/, "").replace(/\s+\/[A-Za-z]+\//g, " ").trim();
    if (n && n === n.toUpperCase()) n = n.toLowerCase().replace(/\b([a-z])/g, function (m) { return m.toUpperCase(); }).replace(/\b(Inc|Corp|Co|Ltd|Plc|Llc|Nv|Sa|Ag)\b/g, function (m) { return m === "Llc" ? "LLC" : m === "Plc" ? "plc" : m === "Nv" ? "N.V." : m === "Sa" ? "S.A." : m === "Ag" ? "AG" : m; });
    return n;
  };

  /* ── Search with suggestions ─────────────────────────────────────────── */
  IL.go = function (sym) {
    sym = String(sym || "").trim().toUpperCase().replace(/[^A-Z0-9.^-]/g, "");
    if (sym) location.href = "/research/" + encodeURIComponent(sym);
  };

  function wireSearch(input, list, onPick) {
    if (!input || !list) return;
    var pick = function (sym) { if (onPick) { input.value = ""; close(); onPick(String(sym || "").trim().toUpperCase()); } else IL.go(sym); };
    var items = [], sel = -1, seq = 0, timer = null;
    function close() { list.hidden = true; input.setAttribute("aria-expanded", "false"); sel = -1; }
    function paint() {
      if (!items.length) {
        list.innerHTML = '<div class="il-sugg-empty">No match. Press Enter to open ' + IL.h(input.value.trim().toUpperCase()) + " anyway.</div>";
      } else {
        list.innerHTML = items.map(function (it, i) {
          return '<button type="button" role="option" class="il-sugg-item" id="il-sugg-' + i + '" data-sym="' + IL.h(it.symbol) + '" aria-selected="' + (i === sel) + '">' +
            '<span class="il-sugg-sym">' + IL.h(it.symbol) + '</span><span class="il-sugg-name">' + IL.h(it.name || "") + "</span></button>";
        }).join("");
      }
      list.hidden = false; input.setAttribute("aria-expanded", "true");
      if (sel >= 0) input.setAttribute("aria-activedescendant", "il-sugg-" + sel); else input.removeAttribute("aria-activedescendant");
    }
    function query() {
      var q = input.value.trim();
      if (!q) { close(); return; }
      var my = ++seq;
      IL.api("/api/search?q=" + encodeURIComponent(q)).then(function (res) {
        if (my !== seq) return;
        items = (res.data && res.data.results ? res.data.results : []).slice(0, 8);
        sel = items.length ? 0 : -1;
        paint();
      });
    }
    input.addEventListener("input", function () { clearTimeout(timer); timer = setTimeout(query, 110); });
    input.addEventListener("focus", function () { if (input.value.trim()) query(); });
    input.addEventListener("keydown", function (e) {
      if (e.key === "ArrowDown" && items.length) { e.preventDefault(); sel = (sel + 1) % items.length; paint(); }
      else if (e.key === "ArrowUp" && items.length) { e.preventDefault(); sel = (sel - 1 + items.length) % items.length; paint(); }
      else if (e.key === "Enter") { e.preventDefault(); pick(sel >= 0 && items[sel] ? items[sel].symbol : input.value); }
      else if (e.key === "Escape") { close(); input.blur(); }
    });
    list.addEventListener("mousedown", function (e) { e.preventDefault(); });
    list.addEventListener("click", function (e) {
      var b = e.target.closest("[data-sym]"); if (b) pick(b.getAttribute("data-sym"));
    });
    input.addEventListener("blur", function () { setTimeout(close, 120); });
  }
  IL.wireSearch = wireSearch;
  IL.wireSearchPick = function (input, list, onPick) { wireSearch(input, list, onPick); };

  /* ── Toast ───────────────────────────────────────────────────────────── */
  var toastEl = null, toastTimer = null;
  IL.toast = function (msg) {
    if (!toastEl) {
      toastEl = document.createElement("div");
      toastEl.className = "il-toast"; toastEl.setAttribute("role", "status"); toastEl.setAttribute("aria-live", "polite");
      document.body.appendChild(toastEl);
    }
    toastEl.textContent = msg;
    requestAnimationFrame(function () { toastEl.classList.add("show"); });
    clearTimeout(toastTimer);
    toastTimer = setTimeout(function () { toastEl.classList.remove("show"); }, 2600);
  };

  /* ── Dialog ──────────────────────────────────────────────────────────── */
  IL.dialog = function (html, onMount) {
    var d = document.createElement("dialog");
    d.className = "il-dialog";
    d.innerHTML = '<div class="il-dialog-in">' + html + "</div>";
    document.body.appendChild(d);
    d.addEventListener("close", function () { d.remove(); });
    d.addEventListener("click", function (e) { if (e.target === d) d.close(); });
    d.addEventListener("click", function (e) { if (e.target.closest("[data-close]")) d.close(); });
    if (onMount) onMount(d);
    d.showModal();
    return d;
  };

  /* ── Tooltips: any element with data-tip ─────────────────────────────── */
  var pop = null;
  function showTip(el) {
    if (!pop) { pop = document.createElement("div"); pop.className = "tip-pop"; pop.setAttribute("role", "tooltip"); pop.id = "il-tip"; document.body.appendChild(pop); }
    pop.textContent = el.getAttribute("data-tip");
    pop.style.display = "block";
    var r = el.getBoundingClientRect(), pw = Math.min(280, window.innerWidth - 24);
    pop.style.maxWidth = pw + "px";
    var pr = pop.getBoundingClientRect();
    var left = Math.max(12, Math.min(window.innerWidth - pr.width - 12, r.left + r.width / 2 - pr.width / 2));
    var top = r.top - pr.height - 8;
    if (top < 8) top = r.bottom + 8;
    pop.style.left = left + window.scrollX + "px";
    pop.style.top = top + window.scrollY + "px";
    el.setAttribute("aria-describedby", "il-tip");
  }
  function hideTip() { if (pop) pop.style.display = "none"; }
  document.addEventListener("mouseover", function (e) { var t = e.target.closest && e.target.closest("[data-tip]"); if (t) showTip(t); });
  document.addEventListener("mouseout", function (e) { var t = e.target.closest && e.target.closest("[data-tip]"); if (t) hideTip(); });
  document.addEventListener("focusin", function (e) { var t = e.target.closest && e.target.closest("[data-tip]"); if (t) showTip(t); });
  document.addEventListener("focusout", hideTip);
  window.addEventListener("scroll", hideTip, { passive: true });
  IL.tip = function (text) { return '<button type="button" class="tip" data-tip="' + IL.h(text) + '" aria-label="What is this?">?</button>'; };

  /* ── Gates: what to show when data needs an account or Pro ───────────── */
  IL.gate = function (kind, what, opts) {
    opts = opts || {};
    var center = opts.center ? " center" : "";
    if (opts.slim) {
      var href = kind === "pro" ? "/pricing" : IL.signupHref();
      return '<div class="gate slim"><span class="gate-ico">' + IL.icon("lock") + '</span><span class="gate-t">' + IL.h(what || "Part of Pro") + '</span><a class="btn sm" href="' + href + '">' + (kind === "pro" ? "See Pro" : "Create a free account") + "</a></div>";
    }
    if (kind === "pro") {
      return '<div class="gate' + center + '"><span class="gate-ico">' + IL.icon("lock") + '</span>' +
        '<div class="gate-t">' + IL.h(what || "This is part of Pro") + "</div>" +
        '<div class="gate-s">' + IL.h(opts.why || "Pro unlocks every tab, unlimited lookups, alerts and the Valuation Lab. $7.99 a month after a 30-day free trial; cancel any time.") + "</div>" +
        '<a class="btn primary" href="/pricing">Start the free trial</a></div>';
    }
    if (kind === "limit") {
      var signedIn = !!IL.user;
      return '<div class="gate' + center + '"><span class="gate-ico">' + IL.icon("lock") + '</span>' +
        '<div class="gate-t">You have used today’s free lookups</div>' +
        '<div class="gate-s">' + (signedIn ? "Free accounts can open a few new companies a day. Pro has no limit." : "Create a free account for more lookups each day, or start Pro for no limit.") + "</div>" +
        '<div class="row wrap">' + (signedIn ? "" : '<a class="btn primary" href="' + IL.signupHref() + '">Create a free account</a>') +
        '<a class="btn' + (signedIn ? " primary" : "") + '" href="/pricing">See Pro</a></div></div>';
    }
    return '<div class="gate' + center + '"><span class="gate-ico">' + IL.icon("lock") + '</span>' +
      '<div class="gate-t">' + IL.h(what || "Create a free account to see this") + "</div>" +
      '<div class="gate-s">' + IL.h(opts.why || "A free account unlocks financial statements, earnings history and a watchlist. No card needed.") + "</div>" +
      '<div class="row wrap"><a class="btn primary" href="' + IL.signupHref() + '">Create a free account</a><a class="btn ghost" href="' + IL.loginHref() + '">Log in</a></div></div>';
  };


  /* ── Plates: the engraved art behind the top of a page ───────────────── */
  var PLATE_SRC = { engraved: "/share/engraved-v1.webp", atlas: "/share/atlas-v1.webp", globe: "/share/globe-v1.webp", ledger: "/share/ledger-v1.webp", dial: "/share/dial-v1.webp" };
  IL.plateSrc = function (name) { return PLATE_SRC[name] || PLATE_SRC.engraved; };
  /* Put a plate behind a hero block. The art sits to the right and fades
     out to the left and the bottom, so text and numbers stay on calm ground. */
  IL.plate = function (host, name, pos) {
    if (!host) return;
    host.classList.add("plate");
    host.style.setProperty("--plate", "url(" + IL.plateSrc(name) + ")");
    if (pos) host.style.setProperty("--plate-pos", pos);
  };


  /* ── Share images: one dialog for every exportable widget ───────────────
     IL.shareImage({ title, text, file, styles: ["engraved", …],
                     render: function (style, plateImage) { return canvas; } })
     Shows the image with a background switch (remembered per viewer), a
     suggested post, Copy, Download and Share / Post on X. */
  var STYLE_LABEL = { engraved: "Engraved", atlas: "Atlas", globe: "Globe", ledger: "Ledger", dial: "Dial", plain: "Plain" };
  var plateImgs = {};
  IL.loadPlate = function (style) {
    if (!plateImgs[style]) plateImgs[style] = new Promise(function (res) {
      if (style === "plain" || !PLATE_SRC[style]) return res(null);
      var im = new Image(); im.onload = function () { res(im); }; im.onerror = function () { res(null); }; im.src = PLATE_SRC[style];
    });
    return plateImgs[style];
  };
  IL.shareFonts = function () {
    var fonts = ["700 40px Inter", "600 40px Inter", "500 40px Inter", "400 40px Inter", "500 40px 'IBM Plex Sans'", "600 40px 'IBM Plex Sans'"];
    return document.fonts && document.fonts.load ? Promise.all(fonts.map(function (f) { return document.fonts.load(f).catch(function () {}); })) : Promise.resolve();
  };
  function pickStyle(styles, set) {
    var v = null;
    try { if (set) localStorage.setItem("il-share-style", set); v = localStorage.getItem("il-share-style"); } catch (_) { v = set; }
    return styles.indexOf(v) >= 0 ? v : styles[0];
  }
  IL.shareImage = function (o) {
    var styles = o.styles && o.styles.length ? o.styles : ["engraved"];
    var style = pickStyle(styles), name = (o.file || "impliedlens") + ".png";
    Promise.all([IL.shareFonts(), IL.loadPlate(style)]).then(function (r) {
      var c = o.render(style, r[1]), href = c.toDataURL("image/png"), file = null;
      function toFile(cv) { if (cv.toBlob && window.File) cv.toBlob(function (b) { if (b) file = new File([b], name, { type: "image/png" }); }, "image/png"); }
      toFile(c);
      var canShare = !!(navigator.canShare && window.File);
      var seg = styles.length > 1 ? '<div class="row wrap" role="group" aria-label="Background" style="gap:6px;margin:10px 0 2px">' + styles.map(function (k) {
        return '<button class="btn' + (k === style ? " primary" : " ghost") + '" type="button" data-plate="' + k + '" aria-pressed="' + (k === style) + '">' + (STYLE_LABEL[k] || k) + "</button>";
      }).join("") + "</div>" : "";
      IL.dialog('<h2>' + IL.h(o.title || "Share") + '</h2><img id="sc-img" src="' + href + '" alt="" style="width:100%;border-radius:10px;border:1px solid var(--line)">' + seg +
        '<label class="field">Suggested post<textarea class="input" rows="3" style="height:auto;padding:10px 12px" id="sc-text">' + IL.h(o.text || "") + "</textarea></label>" +
        '<div class="row wrap" style="justify-content:flex-end"><button class="btn ghost" type="button" data-close>Close</button><button class="btn" type="button" id="sc-copy">Copy text</button><a class="btn" id="sc-dl" href="' + href + '" download="' + IL.h(name) + '">Download image</a>' +
        (canShare ? '<button class="btn primary" type="button" id="sc-share">Share</button>' : '<a class="btn primary" target="_blank" rel="noopener" href="https://x.com/intent/post?text=' + encodeURIComponent(o.text || "") + '">Post on X</a>') + "</div>",
        function (d) {
          d.style.width = "min(640px, calc(100vw - 32px))";
          d.querySelector("#sc-copy").addEventListener("click", function () { var tx = d.querySelector("#sc-text").value; (navigator.clipboard ? navigator.clipboard.writeText(tx) : Promise.reject()).then(function () { IL.toast("Copied"); }, function () { IL.toast("Copy failed"); }); });
          var sb = d.querySelector("#sc-share");
          if (sb) sb.addEventListener("click", function () {
            var payload = { text: d.querySelector("#sc-text").value };
            if (file && navigator.canShare({ files: [file] })) payload.files = [file];
            navigator.share(payload).catch(function () {});
          });
          Array.prototype.forEach.call(d.querySelectorAll("[data-plate]"), function (b) {
            b.addEventListener("click", function () {
              var k = pickStyle(styles, b.getAttribute("data-plate"));
              Array.prototype.forEach.call(d.querySelectorAll("[data-plate]"), function (x) { var on = x === b; x.className = "btn" + (on ? " primary" : " ghost"); x.setAttribute("aria-pressed", String(on)); });
              IL.loadPlate(k).then(function (im) { var cv = o.render(k, im), u = cv.toDataURL("image/png"); d.querySelector("#sc-img").src = u; d.querySelector("#sc-dl").href = u; toFile(cv); });
            });
          });
        });
    });
  };
  /* Drawing helpers for 1200×630 share images. */
  IL.cardKit = function (x) {
    var hasLS = "letterSpacing" in x;
    var K = {
      C: { bg: "#10110F", text: "#F3F0E7", t2: "#B9B6AB", t3: "#8C897F", gold: "#E5B65A", gain: "#4CC38A", gradeB: "#8FD0A4", amber: "#E5B65A", loss: "#F07B7B", rule: "rgba(243,240,231,0.12)" },
      sans: "Inter, system-ui, sans-serif", nums: "'IBM Plex Sans', Inter, sans-serif", DASH: "—",
      font: function (w, px, fam) { return w + " " + px + "px " + fam; },
      width: function (str, f, track) { x.font = f; if (hasLS) x.letterSpacing = (track || 0) + "px"; var w = x.measureText(str).width; if (hasLS) x.letterSpacing = "0px"; return w; },
      box: function (str, X, Y, w, h, f, color, align, track) {
        x.font = f; x.fillStyle = color; x.textAlign = align || "left"; x.textBaseline = "alphabetic";
        if (hasLS) x.letterSpacing = (track || 0) + "px";
        var m = x.measureText("Hg0"), asc = m.actualBoundingBoxAscent, desc = m.actualBoundingBoxDescent;
        var base = Y + (h - (asc + desc)) / 2 + asc, ax = align === "center" ? X + w / 2 : align === "right" ? X + w : X;
        x.fillText(str, ax, base); var tw = x.measureText(str).width;
        if (hasLS) x.letterSpacing = "0px";
        return { w: tw, base: base };
      },
      fit: function (str, wt, fam, max, min, maxW, track) { var px = max; while (px > min && K.width(str, K.font(wt, px, fam), track) > maxW) px -= 1; return px; },
      ellipsize: function (str, f, maxW) { str = String(str || ""); if (K.width(str, f) <= maxW) return str; while (str.length > 1 && K.width(str + "…", f) > maxW) str = str.slice(0, -1); return str.replace(/\s+$/, "") + "…"; },
      gradeCol: function (g) { g = String(g || "").charAt(0); return g === "A" ? K.C.gain : g === "B" ? K.C.gradeB : g === "C" ? K.C.amber : g ? K.C.loss : K.C.t3; },
      /* The plate with feathered veils: two text columns, a lit middle. */
      plate: function (plate, W, H) {
        x.fillStyle = K.C.bg; x.fillRect(0, 0, W, H);
        if (plate) x.drawImage(plate, 0, 0, W, H);
        var vl = x.createLinearGradient(0, 0, 600, 0);
        vl.addColorStop(0, "rgba(16,17,15,0.86)"); vl.addColorStop(0.62, "rgba(16,17,15,0.72)"); vl.addColorStop(0.86, "rgba(16,17,15,0.28)"); vl.addColorStop(1, "rgba(16,17,15,0)");
        x.fillStyle = vl; x.fillRect(0, 0, 600, H);
        var vr = x.createLinearGradient(740, 0, W, 0);
        vr.addColorStop(0, "rgba(16,17,15,0)"); vr.addColorStop(0.3, "rgba(16,17,15,0.6)"); vr.addColorStop(0.55, "rgba(16,17,15,0.8)"); vr.addColorStop(1, "rgba(16,17,15,0.86)");
        x.fillStyle = vr; x.fillRect(740, 0, W - 740, H);
        var vb = x.createLinearGradient(0, 540, 0, H);
        vb.addColorStop(0, "rgba(16,17,15,0)"); vb.addColorStop(0.45, "rgba(16,17,15,0.8)"); vb.addColorStop(1, "rgba(16,17,15,0.92)");
        x.fillStyle = vb; x.fillRect(0, 540, W, H - 540);
      },
      /* The plate under one even veil, for layouts with text everywhere. */
      plateFlat: function (plate, W, H, a) {
        x.fillStyle = K.C.bg; x.fillRect(0, 0, W, H);
        if (plate) x.drawImage(plate, 0, 0, W, H);
        x.fillStyle = "rgba(16,17,15," + (a || 0.72) + ")"; x.fillRect(0, 0, W, H);
        var vb = x.createLinearGradient(0, 540, 0, H); vb.addColorStop(0, "rgba(16,17,15,0)"); vb.addColorStop(1, "rgba(16,17,15,0.9)");
        x.fillStyle = vb; x.fillRect(0, 540, W, H - 540);
      },
      brand: function (label) {
        var bw = K.box("Implied", 48, 32, 240, 28, K.font(700, 23, K.sans), K.C.text).w;
        K.box("Lens", 48 + bw, 32, 240, 28, K.font(700, 23, K.sans), K.C.gold);
        if (label) K.box(label, 692, 38, 460, 20, K.font(500, 13, K.sans), K.C.t2, "right", 1);
      },
      footer: function (url) {
        x.fillStyle = K.C.rule; x.fillRect(48, 566, 1104, 1);
        K.box(url, 48, 586, 690, 23, K.font(600, 18, K.sans), K.C.text);
        K.box("Educational research · not investment advice", 792, 590, 360, 18, K.font(400, 13, K.sans), K.C.t3, "right");
      }
    };
    return K;
  };

  /* ── Widgets: one frame and one set of tools for every tool on the site ──
     <section data-w="expand,share,csv" data-w-title="…">. The tools sit top
     right and survive the section being repainted. Actions:
       expand  open the widget large in a dialog
       share   IL.widgetShare[id]() if the page registers one
       csv     download the widget's first table as CSV */
  IL.widgetShare = {};
  function tableCsv(el, name) {
    var t = el.querySelector("table"); if (!t) { IL.toast("Nothing to export yet."); return; }
    var rows = Array.prototype.map.call(t.querySelectorAll("tr"), function (tr) {
      return Array.prototype.map.call(tr.querySelectorAll("th,td"), function (c) { var v = c.innerText.replace(/\s+/g, " ").trim(); return /[",\n]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v; }).join(",");
    }).join("\n");
    var a = document.createElement("a");
    a.href = "data:text/csv;charset=utf-8," + encodeURIComponent(rows); a.download = (name || "impliedlens") + ".csv";
    document.body.appendChild(a); a.click(); a.remove();
  }
  function expandWidget(el) {
    var clone = el.cloneNode(true);
    var tools = clone.querySelector(".w-tools"); if (tools) tools.remove();
    var src = el.querySelectorAll("canvas"), dst = clone.querySelectorAll("canvas");
    Array.prototype.forEach.call(dst, function (c, i) { try { c.getContext("2d").drawImage(src[i], 0, 0); } catch (_) {} });
    clone.removeAttribute("id"); clone.classList.add("w-big");
    IL.dialog('<div class="w-dlg-h"><h2>' + IL.h(el.getAttribute("data-w-title") || "") + '</h2><button class="btn ghost" type="button" data-close>Close</button></div>', function (d) {
      d.classList.add("w-dlg"); d.querySelector(".il-dialog-in").appendChild(clone);
    });
  }
  function toolsHtml(el) {
    var kinds = String(el.getAttribute("data-w") || "").split(",").map(function (k) { return k.trim(); }).filter(Boolean);
    var title = el.getAttribute("data-w-title") || "this";
    var label = { expand: "Open " + title + " larger", share: "Share " + title + " as an image", csv: "Download " + title + " as CSV" };
    var icon = { expand: "expand", share: "share", csv: "download" };
    return kinds.filter(function (k) { return icon[k] && (k !== "share" || IL.widgetShare[el.id]); }).map(function (k) {
      return '<button class="w-btn" type="button" data-w-act="' + k + '" aria-label="' + IL.h(label[k]) + '" title="' + IL.h(label[k]) + '">' + IL.icon(icon[k], 15) + "</button>";
    }).join("");
  }
  function ensureTools(el) {
    if (el.querySelector(":scope > .w-tools")) return;
    var html = toolsHtml(el); if (!html) return;
    var box = document.createElement("div"); box.className = "w-tools"; box.innerHTML = html;
    el.appendChild(box);
  }
  IL.widgets = function (root) {
    root = root || document;
    Array.prototype.forEach.call(root.querySelectorAll("[data-w]"), function (el) {
      el.classList.add("w");
      ensureTools(el);
      if (el.__wObs) return;
      el.__wObs = new MutationObserver(function () { ensureTools(el); });
      el.__wObs.observe(el, { childList: true });
      el.addEventListener("click", function (e) {
        var b = e.target.closest("[data-w-act]"); if (!b || !el.contains(b)) return;
        var k = b.getAttribute("data-w-act");
        if (k === "expand") expandWidget(el);
        else if (k === "csv") tableCsv(el, (el.getAttribute("data-w-title") || "table").toLowerCase().replace(/[^a-z0-9]+/g, "-"));
        else if (k === "share" && IL.widgetShare[el.id]) IL.widgetShare[el.id]();
      });
    });
  };

  /* ── Brand pieces ────────────────────────────────────────────────────── */
  var SECTOR_HUE = { tech: 212, technology: 212, health: 158, "health care": 158, healthcare: 158, financ: 42, bank: 42, consumer: 18, retail: 18, communication: 278, media: 278, energy: 28, util: 192, industr: 0, "real est": 330, reit: 330, staple: 95, material: 120 };
  IL.monoHue = function (t, sector) {
    t = String(t || "?").toUpperCase();
    var s = String(sector || "").toLowerCase();
    for (var k in SECTOR_HUE) { if (s.indexOf(k) >= 0) return SECTOR_HUE[k]; }
    var hsh = 0; for (var i = 0; i < t.length; i++) hsh = (hsh * 31 + t.charCodeAt(i)) % 360;
    return hsh;
  };
  IL.mono = function (t, sector, size) {
    t = String(t || "?").toUpperCase();
    var hue = IL.monoHue(t, sector);
    var label = t.replace(/[^A-Z0-9]/g, "").slice(0, t.length > 4 ? 3 : 4);
    return '<span class="mono' + (size ? " " + size : "") + '" style="--h:' + hue + '" aria-hidden="true">' + IL.h(label.length > 3 && size !== "lg" ? label.slice(0, 3) : label) + "</span>";
  };
  IL.eyebrow = function (text, icon) { return '<span class="eyebrow">' + (icon ? IL.icon(icon, 13) : "") + IL.h(text) + "</span>"; };
  IL.gchip = function (g) { return g ? '<span class="gchip" style="color:' + IL.gradeTone(g) + '">' + IL.h(g) + "</span>" : '<span class="faint">\u2014</span>'; };
  /* The brand ribbon behind a hero block (il-ribbon.js loads on demand). */
  IL.ribbon = function (host, path, seed) {
    if (!host || host.querySelector(".il-ribbon")) return;
    var r = document.createElement("div");
    r.className = "il-ribbon"; r.setAttribute("data-path", path || "sweep"); r.setAttribute("data-seed", String(seed || 3));
    host.insertBefore(r, host.firstChild);
    function go() { if (window.ILRibbon) window.ILRibbon.mount(r); }
    if (window.ILRibbon) go();
    else if (!document.getElementById("il-ribbon-js")) {
      var sc = document.createElement("script"); sc.id = "il-ribbon-js"; sc.src = "/il-ribbon.js"; sc.defer = true;
      sc.onload = function () { IL.$$(".il-ribbon").forEach(function (x) { if (!x.__ilr && window.ILRibbon) window.ILRibbon.mount(x); }); };
      document.head.appendChild(sc);
    }
  };

  /* ── Score tone ──────────────────────────────────────────────────────── */
  IL.scoreTone = function (s) { s = Number(s); return !isFinite(s) ? "" : s >= 7 ? "good" : s >= 4 ? "mid" : "bad"; };
  IL.gradeTone = function (g) {
    g = String(g || "").charAt(0);
    return g === "A" ? "var(--gain)" : g === "B" ? "var(--grade-b)" : g === "C" ? "var(--amber)" : g ? "var(--loss)" : "var(--text3)";
  };
  IL.gradeFill = function (g) {
    var map = { "A+": 98, "A": 92, "A-": 86, "A−": 86, "B+": 78, "B": 70, "B-": 63, "B−": 63, "C+": 55, "C": 47, "C-": 40, "C−": 40, "D+": 32, "D": 24, "D-": 18, "D−": 18, "F": 10 };
    return map[String(g || "").trim()] || 0;
  };
})();
