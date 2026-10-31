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
      mePromise = IL.api("/api/auth/me").then(function (res) {
        var u = res.ok && res.data && res.data.user ? res.data.user : null;
        if (u) u.plan = u.effectivePlan || u.plan || "free";
        IL.user = u;
        return u;
      });
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

  /* ── Shell: top bar, bottom bar, footer ─────────────────────────────── */
  var NAV = [
    { key: "home", label: "Home", href: "/", icon: "home" },
    { key: "research", label: "Research", href: "/research", icon: "research" },
    { key: "screener", label: "Screener", href: "/?view=tool&section=screener", icon: "screener" },
    { key: "watchlist", label: "Watchlist", href: "/?view=tool&section=workspace&workspace_tab=watchlist", icon: "star" },
    { key: "learn", label: "Learn", href: "/learn", icon: "learn" },
    { key: "pricing", label: "Pricing", href: "/pricing", icon: "arrow" },
  ];

  IL.shell = function (active) {
    document.body.classList.add("il-app");
    var top = document.getElementById("il-top");
    if (top) {
      top.className = "il-top";
      top.innerHTML =
        '<div class="il-top-in">' +
          '<a class="il-brand" href="/" aria-label="ImpliedLens home"><img src="/logo-mark-68.png" width="28" height="28" alt=""><span class="il-brand-word">ImpliedLens</span></a>' +
          '<nav class="il-nav" aria-label="Main">' + NAV.map(function (n) {
            return '<a href="' + n.href + '" data-k="' + n.key + '"' + (n.key === active ? ' aria-current="page"' : "") + ">" + n.label + "</a>";
          }).join("") + "</nav>" +
          '<div class="il-search" role="search">' +
            '<label class="il-search-box">' + IL.icon("search") +
              '<input id="il-q" type="search" autocomplete="off" spellcheck="false" placeholder="Search a company or ticker" aria-label="Search a company or ticker" role="combobox" aria-expanded="false" aria-controls="il-sugg" aria-autocomplete="list">' +
              '<span class="il-kbd" aria-hidden="true">/</span>' +
            "</label>" +
            '<div class="il-sugg" id="il-sugg" role="listbox" hidden></div>' +
          "</div>" +
          '<div class="il-acct" id="il-acct"></div>' +
        "</div>";
      wireSearch(IL.$("#il-q"), IL.$("#il-sugg"));
    }
    var bottom = document.getElementById("il-bottom");
    if (bottom) {
      bottom.className = "il-bottom";
      bottom.setAttribute("aria-label", "Main");
      bottom.innerHTML = NAV.slice(0, 4).map(function (n) {
        return '<a href="' + n.href + '"' + (n.key === active ? ' aria-current="page"' : "") + ">" + IL.icon(n.icon, 22) + "<span>" + n.label + "</span></a>";
      }).join("");
    }
    var foot = document.getElementById("il-foot");
    if (foot) {
      foot.className = "il-foot";
      foot.innerHTML =
        "<span>© " + new Date().getFullYear() + " ImpliedLens. Research, not investment advice.</span>" +
        '<a href="/data-sources">Data sources</a><a href="/pricing">Pricing</a><a href="/learn">Learn</a>' +
        '<a href="/privacy">Privacy</a><a href="/terms">Terms</a><a href="/support">Support</a>';
    }
    IL.me().then(renderAccount);
    document.addEventListener("keydown", function (e) {
      if (e.key !== "/" || e.metaKey || e.ctrlKey || e.altKey) return;
      var t = e.target;
      if (t && (t.tagName === "INPUT" || t.tagName === "TEXTAREA" || t.tagName === "SELECT" || t.isContentEditable)) return;
      var q = IL.$("#il-q"); if (!q) return;
      e.preventDefault(); q.focus(); q.select();
    });
  };

  function renderAccount(user) {
    var box = IL.$("#il-acct"); if (!box) return;
    var pricingTab = IL.$('.il-nav [data-k="pricing"]');
    if (pricingTab) pricingTab.hidden = IL.isPro(user);
    var themeBtn = '<button class="il-iconbtn il-theme" id="il-theme" type="button" aria-label="Switch to ' + (IL.theme() === "dark" ? "light" : "dark") + ' theme">' + IL.icon(IL.theme() === "dark" ? "sun" : "moon", 18) + "</button>";
    if (!user) {
      box.innerHTML = themeBtn +
        '<a class="btn ghost sm" href="' + IL.loginHref() + '">Log in</a>' +
        '<a class="btn primary sm il-signup" href="' + IL.signupHref() + '">Sign up free</a>';
    } else {
      var initial = (user.username || user.email || "?").trim().charAt(0).toUpperCase();
      var plan = user.plan === "pro" ? '<span class="il-plan">PRO</span>' : user.plan === "trial" ? '<span class="il-plan trial">PRO TRIAL</span>' : '<a class="btn sm" href="/pricing">Upgrade</a>';
      box.style.position = "relative";
      box.innerHTML = plan + themeBtn +
        '<button class="il-avatar" id="il-avatar" type="button" aria-haspopup="menu" aria-expanded="false" aria-label="Account">' + IL.h(initial) + "</button>" +
        '<div class="il-menu" id="il-menu" role="menu" hidden>' +
          '<div class="il-menu-head"><strong>' + IL.h(user.username || "Your account") + "</strong>" + (user.plan === "pro" ? "Pro member" : user.plan === "trial" ? "Pro trial" : "Free plan") + "</div>" +
          '<a role="menuitem" href="/?view=tool&section=workspace">' + IL.icon("folder") + "Saved work</a>" +
          '<a role="menuitem" href="/?view=tool&section=projection">' + IL.icon("research") + "Valuation Lab</a>" +
          '<a role="menuitem" href="/?account=1">' + IL.icon("user") + "Account settings</a>" +
          '<button role="menuitem" type="button" id="il-billing">' + IL.icon("doc") + (IL.isPro(user) ? "Subscription and billing" : "See Pro plans") + "</button>" +
          '<button role="menuitem" type="button" id="il-theme2">' + IL.icon(IL.theme() === "dark" ? "sun" : "moon") + (IL.theme() === "dark" ? "Light theme" : "Dark theme") + "</button>" +
          "<hr>" +
          '<button role="menuitem" type="button" id="il-logout">' + IL.icon("out") + "Log out</button>" +
        "</div>";
      var av = IL.$("#il-avatar"), menu = IL.$("#il-menu");
      av.addEventListener("click", function (e) {
        e.stopPropagation();
        var open = menu.hidden;
        menu.hidden = !open; av.setAttribute("aria-expanded", String(open));
      });
      document.addEventListener("click", function (e) { if (!menu.contains(e.target)) { menu.hidden = true; av.setAttribute("aria-expanded", "false"); } });
      document.addEventListener("keydown", function (e) { if (e.key === "Escape" && !menu.hidden) { menu.hidden = true; av.focus(); } });
      IL.$("#il-theme2").addEventListener("click", function () { IL.setTheme(IL.theme() === "dark" ? "light" : "dark"); renderAccount(user); });
      IL.$("#il-billing").addEventListener("click", function () {
        if (!IL.isPro(user)) { location.href = "/pricing"; return; }
        IL.api("/api/stripe/portal", { method: "POST", body: {} }).then(function (res) {
          if (res.ok && res.data && res.data.url) location.href = res.data.url;
          else location.href = "mailto:support@impliedlens.com?subject=ImpliedLens%20billing";
        });
      });
      IL.$("#il-logout").addEventListener("click", function () {
        IL.api("/api/auth/logout", { method: "POST", body: {} }).then(function () { location.href = "/"; });
      });
    }
    IL.$("#il-theme").addEventListener("click", function () {
      IL.setTheme(IL.theme() === "dark" ? "light" : "dark");
      renderAccount(user);
    });
  }

  /* ── Search with suggestions ─────────────────────────────────────────── */
  IL.go = function (sym) {
    sym = String(sym || "").trim().toUpperCase().replace(/[^A-Z0-9.^-]/g, "");
    if (sym) location.href = "/research/" + encodeURIComponent(sym);
  };

  function wireSearch(input, list) {
    if (!input || !list) return;
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
      else if (e.key === "Enter") { e.preventDefault(); IL.go(sel >= 0 && items[sel] ? items[sel].symbol : input.value); }
      else if (e.key === "Escape") { close(); input.blur(); }
    });
    list.addEventListener("mousedown", function (e) { e.preventDefault(); });
    list.addEventListener("click", function (e) {
      var b = e.target.closest("[data-sym]"); if (b) IL.go(b.getAttribute("data-sym"));
    });
    input.addEventListener("blur", function () { setTimeout(close, 120); });
  }
  IL.wireSearch = wireSearch;

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
