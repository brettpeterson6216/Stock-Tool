/* ═══════════════════════════════════════════════════════════════════════════
   The site shell: one top bar, one phone tab bar, one account menu, one
   sign-in check, for every page on the site.

   The bar is drawn once, here, and reaches the page two ways:

     1. On the server. lib/asset-stamp.js calls ILShellMarkup.render(tab) and
        writes the finished bar into every page as declarative shadow DOM
        (<il-top><template shadowrootmode="open">…). It is part of the HTML,
        so it paints in the first frame of every page — no blank bar, no tab
        that appears and then disappears while a script catches up.
     2. In the browser, this file adds the behaviour: search suggestions, the
        account menu, the theme button, the signed-in name. If a page arrives
        without the server markup, it draws the same markup itself.

   It lives in a shadow root, so no page stylesheet can restyle it: every
   page's bar is the same pixels. The only thing that changes from page to
   page is which tab is marked as the current one.

   What depends on sign-in or theme is decided by the page's own CSS
   (shell.css) through ::part(), keyed on classes theme-bootstrap.js puts on
   <html> before the first paint:
     visitor     → "Log in" and "Sign up free"
     free plan   → "Upgrade"
     Pro / trial → nothing to sell; the Pricing tab is hidden
   Page content follows the same rule through data-show (see shell.css).
   ═══════════════════════════════════════════════════════════════════════════ */
(function () {
  "use strict";

  var NAV = [
    { key: "home", label: "Home", href: "/" },
    { key: "research", label: "Research", href: "/research" },
    { key: "screener", label: "Screener", href: "/screener" },
    { key: "watchlist", label: "Watchlist", href: "/watchlist" },
    { key: "learn", label: "Learn", href: "/learn" },
    { key: "pricing", label: "Pricing", href: "/pricing" },
  ];
  /* Phone tab bar: five places, drawn as simple outlines. */
  var TAB_ICON = {
    home: '<path d="M4 10.5 12 4l8 6.5V20a1 1 0 0 1-1 1h-5v-6h-4v6H5a1 1 0 0 1-1-1z"/>',
    research: '<path d="M4 19V5"/><path d="M4 19h16"/><path d="m7 15 4-4 3 3 5-6"/>',
    screener: '<path d="M4 6h16"/><path d="M7 12h10"/><path d="M10 18h4"/>',
    watchlist: '<path d="m12 3 2.7 5.6 6.1.9-4.4 4.3 1 6.1L12 17l-5.4 2.9 1-6.1-4.4-4.3 6.1-.9z"/>',
    learn: '<path d="M3 7l9-4 9 4-9 4z"/><path d="M7 9v5c0 1.5 2.5 3 5 3s5-1.5 5-3V9"/>',
  };
  var SEARCH_ICON = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" aria-hidden="true"><path d="M11 18a7 7 0 1 0 0-14 7 7 0 0 0 0 14Z"/><path d="m20 20-3.5-3.5"/></svg>';
  var SUN = '<svg part="sun" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" aria-hidden="true"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg>';
  var MOON = '<svg part="moon" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" aria-hidden="true"><path d="M20 14.5A8 8 0 0 1 9.5 4 8 8 0 1 0 20 14.5Z"/></svg>';

  var CSS = String.raw`:host{all:initial;display:block;box-sizing:border-box;
  font-family:Inter,system-ui,-apple-system,"Segoe UI",sans-serif;font-size:14px;line-height:1.5;color:var(--sh-text);
  -webkit-font-smoothing:antialiased;-moz-osx-font-smoothing:grayscale;text-rendering:optimizeLegibility}
*,*::before,*::after{box-sizing:border-box}
a{color:inherit;text-decoration:none}
button{font:inherit;color:inherit}
svg{display:block}
[hidden]{display:none !important}
:focus-visible{outline:2px solid var(--sh-gold);outline-offset:2px;border-radius:8px}

/* Top bar */
.bar{padding-top:env(safe-area-inset-top,0px);background:color-mix(in srgb,var(--sh-ground) 90%,transparent);
  -webkit-backdrop-filter:saturate(1.3) blur(10px);backdrop-filter:saturate(1.3) blur(10px);border-bottom:1px solid var(--sh-line)}
.in{height:60px;display:flex;align-items:center;gap:24px;padding:0 max(32px,env(safe-area-inset-right,0px)) 0 max(32px,env(safe-area-inset-left,0px))}
.brand{display:flex;align-items:center;gap:10px;flex:none;color:var(--sh-text);font-weight:700;font-size:17px;letter-spacing:-.01em}
.brand img{display:block;width:28px;height:28px}
.accent{font-family:"Instrument Serif",Georgia,serif;font-style:italic;font-weight:400;color:var(--sh-gold-text);font-size:1.12em;padding-left:1px}
.nav{display:flex;gap:2px;flex:none}
.nav a{padding:7px 12px;border-radius:8px;color:var(--sh-text2);font-weight:500;white-space:nowrap}
.nav a:hover{color:var(--sh-text);background:var(--sh-raised)}
.nav a[aria-current="page"]{color:var(--sh-gold-text);background:var(--sh-gold-soft)}

.search{position:relative;flex:1 1 260px;max-width:420px;min-width:0}
.box{display:flex;align-items:center;gap:8px;height:38px;margin:0;padding:0 10px 0 12px;border:1px solid var(--sh-line2);border-radius:10px;background:var(--sh-surface);color:var(--sh-text3);cursor:text}
.box:focus-within{border-color:var(--sh-gold);box-shadow:0 0 0 3px var(--sh-gold-soft)}
.box svg{flex:none}
input{flex:1;min-width:0;height:auto;margin:0;padding:0;border:0;background:transparent;color:var(--sh-text);font:inherit;font-size:14px;outline:none;box-shadow:none;-webkit-appearance:none;appearance:none}
input::placeholder{color:var(--sh-text3);opacity:1}
input::-webkit-search-cancel-button{display:none}
.kbd{font-weight:600;font-size:11px;line-height:1.4;color:var(--sh-text3);border:1px solid var(--sh-line2);border-radius:5px;padding:0 6px}

.acct{margin-left:auto;display:flex;align-items:center;gap:10px;flex:none;position:relative}
.btn{display:inline-flex;align-items:center;height:34px;padding:0 14px;border-radius:9px;font-size:13.5px;font-weight:600;white-space:nowrap;border:1px solid transparent}
.ghost{color:var(--sh-text);border-color:var(--sh-line2)}
.ghost:hover{background:var(--sh-raised)}
.gold{background:var(--sh-gold);color:var(--sh-gold-ink)}
.gold:hover{filter:brightness(1.06)}
.plan{font-size:11px;font-weight:700;letter-spacing:.06em;color:var(--sh-gold-text);border:1px solid color-mix(in srgb,var(--sh-gold) 45%,transparent);border-radius:999px;padding:2px 9px}
.theme{width:36px;height:36px;padding:0;margin:0;border-radius:9px;border:1px solid transparent;background:transparent;color:var(--sh-text2);display:grid;place-items:center;cursor:pointer}
.theme:hover{background:var(--sh-raised);color:var(--sh-text)}
.avatar{width:34px;height:34px;padding:0;margin:0;border-radius:999px;border:1px solid var(--sh-line2);background:var(--sh-raised);color:var(--sh-text);font-weight:600;font-size:13px;cursor:pointer;display:grid;place-items:center}
.avatar:empty::before{content:var(--il-initial,"")}

/* Search suggestions */
.sugg{position:absolute;left:0;right:0;top:calc(100% + 6px);z-index:2;background:var(--sh-surface);border:1px solid var(--sh-line2);border-radius:12px;box-shadow:var(--sh-shadow);padding:6px;max-height:min(420px,70vh);overflow:auto}
.item{display:flex;align-items:center;gap:12px;width:100%;padding:9px 10px;margin:0;border-radius:8px;border:0;background:transparent;text-align:left;cursor:pointer;font-size:14px}
.item[aria-selected="true"],.item:hover{background:var(--sh-raised)}
.sym{font-weight:700;min-width:58px}
.name{color:var(--sh-text2);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.empty{padding:12px;color:var(--sh-text2);font-size:13px}

/* Account menu */
.menu{position:absolute;right:0;top:calc(100% + 8px);min-width:230px;z-index:3;background:var(--sh-surface);border:1px solid var(--sh-line2);border-radius:12px;box-shadow:var(--sh-shadow);padding:6px}
.menu a,.menu button{display:flex;align-items:center;gap:10px;width:100%;padding:9px 10px;margin:0;border-radius:8px;border:0;background:transparent;font-size:13.5px;text-align:left;cursor:pointer}
.menu a:hover,.menu button:hover{background:var(--sh-raised)}
.menu hr{border:0;border-top:1px solid var(--sh-line);margin:6px 4px}
.head{padding:8px 10px 10px;font-size:12.5px;color:var(--sh-text2)}
.head strong{display:block;color:var(--sh-text);font-size:13.5px;font-weight:600}

/* Phone tab bar */
.tabs{display:grid;grid-template-columns:repeat(5,1fr);height:calc(62px + env(safe-area-inset-bottom,0px));padding-bottom:env(safe-area-inset-bottom,0px);
  background:color-mix(in srgb,var(--sh-surface) 94%,transparent);-webkit-backdrop-filter:blur(12px);backdrop-filter:blur(12px);border-top:1px solid var(--sh-line)}
.tabs a{display:flex;flex-direction:column;align-items:center;justify-content:center;gap:3px;color:var(--sh-text3);font-size:11px;font-weight:600}
.tabs a[aria-current="page"]{color:var(--sh-gold-text)}

@media (max-width:760px){
  .in{gap:12px;padding:0 max(16px,env(safe-area-inset-right,0px)) 0 max(16px,env(safe-area-inset-left,0px))}
  .nav,.word,.kbd,.plan,.theme,.acct .ghost{display:none}
  .search{max-width:none}
}`;

  function esc(s) { return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) { return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]; }); }

  /* Which tab a URL belongs to. Pages that are not a tab mark none. */
  function activeFor(path) {
    path = String(path || "/");
    if (path === "/" || path === "/index.html") return "home";
    if (/^\/(research|compare|lens-score|stock)(\/|$|\?)/.test(path)) return "research";
    if (/^\/screener/.test(path)) return "screener";
    if (/^\/watchlist/.test(path)) return "watchlist";
    if (/^\/learn/.test(path)) return "learn";
    if (/^\/pricing/.test(path)) return "pricing";
    return "";
  }

  /* ── The markup. Pure strings, so the server can draw it too. ───────────
     Every account state is in the markup; the page's CSS shows the right
     one (::part) from the first frame. */
  function topHTML(active) {
    return '<div class="bar" role="banner"><div class="in">' +
      '<a class="brand" href="/" aria-label="ImpliedLens home"><img src="/logo-mark-68.png" width="28" height="28" alt=""><span class="word">Implied<span class="accent">Lens</span></span></a>' +
      '<nav class="nav" aria-label="Main">' + NAV.map(function (n) {
        return '<a href="' + n.href + '" data-k="' + n.key + '"' + (n.key === active ? ' aria-current="page"' : "") + (n.key === "pricing" ? ' part="upgrade"' : "") + ">" + n.label + "</a>";
      }).join("") + "</nav>" +
      '<div class="search" role="search">' +
        '<label class="box">' + SEARCH_ICON +
          '<input id="il-q" type="search" autocomplete="off" spellcheck="false" placeholder="Search a company or ticker" aria-label="Search a company or ticker" role="combobox" aria-expanded="false" aria-controls="sugg" aria-autocomplete="list">' +
          '<span class="kbd" aria-hidden="true">/</span>' +
        "</label>" +
        '<div class="sugg" id="sugg" role="listbox" aria-label="Matching companies" hidden></div>' +
      "</div>" +
      '<div class="acct" id="acct">' +
        '<span class="plan" id="plan" part="pro">PRO</span>' +
        '<a class="btn gold" part="free" href="/pricing">Upgrade</a>' +
        '<button class="theme" id="theme" type="button" aria-label="Switch theme">' + SUN + MOON + "</button>" +
        '<a class="btn ghost" part="guest" id="login" href="/login">Log in</a>' +
        '<a class="btn gold" part="guest" id="signup" href="/signup">Sign up free</a>' +
        '<button class="avatar" part="member" id="avatar" type="button" aria-haspopup="menu" aria-expanded="false" aria-controls="menu" aria-label="Account menu"></button>' +
        '<div class="menu" id="menu" role="menu" hidden>' +
          '<div class="head" id="mhead"></div>' +
          '<a role="menuitem" href="/watchlist">Watchlist and saved work</a>' +
          '<a role="menuitem" href="/compare">Compare stocks</a>' +
          '<a role="menuitem" href="/?account=1">Account settings</a>' +
          '<button role="menuitem" type="button" id="billing">See Pro plans</button>' +
          "<hr>" +
          '<button role="menuitem" type="button" id="logout">Log out</button>' +
        "</div>" +
      "</div>" +
    "</div></div>";
  }
  function tabsHTML(active) {
    return '<nav class="tabs" aria-label="Main">' + NAV.filter(function (n) { return TAB_ICON[n.key]; }).map(function (n) {
      return '<a href="' + n.href + '"' + (n.key === active ? ' aria-current="page"' : "") + '><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' + TAB_ICON[n.key] + "</svg><span>" + n.label + "</span></a>";
    }).join("") + "</nav>";
  }
  /* The finished elements, as declarative shadow DOM, for the server. */
  function render(active) {
    var style = "<style>" + CSS + "</style>";
    return {
      top: '<il-top id="il-top"><template shadowrootmode="open">' + style + topHTML(active) + "</template></il-top>",
      tabs: '<il-tabbar id="il-bottom"><template shadowrootmode="open">' + style + tabsHTML(active) + "</template></il-tabbar>",
    };
  }

  var markup = { NAV: NAV, CSS: CSS, activeFor: activeFor, topHTML: topHTML, tabsHTML: tabsHTML, render: render };
  if (typeof document === "undefined") { if (typeof module !== "undefined") module.exports = markup; return; }
  if (window.ILShell) return;

  function $(sel, root) { return (root || document).querySelector(sel); }

  /* ── Who is signed in ──────────────────────────────────────────────────
     One request per page, shared with the app (IL.me reuses it). The answer
     is remembered so theme-bootstrap.js can mark the next page before it
     paints. */
  var HINT = "il-shell-auth";
  var mePromise = null;
  function me() {
    if (!mePromise) {
      mePromise = fetch("/api/auth/me", { credentials: "same-origin", headers: { Accept: "application/json" } })
        .then(function (r) { return r.ok ? r.json() : null; })
        .then(function (j) {
          var u = j && j.user ? j.user : null;
          if (u) u.plan = u.effectivePlan || u.plan || "free";
          return u;
        })
        .catch(function () { return null; });
    }
    return mePromise;
  }
  function tier(u) { return !u ? "guest" : (u.plan === "pro" || u.plan === "trial") ? "pro" : "free"; }
  function setTier(t) {
    var root = document.documentElement;
    root.classList.remove("il-guest", "il-free", "il-pro", "il-auth-pending");
    root.classList.add("il-" + t);
    try { localStorage.setItem(HINT, t); } catch (_) {}
  }
  /* theme-bootstrap.js normally does this before paint; repeated for pages
     that do not load it. */
  (function hint() {
    var c = document.documentElement.classList;
    if (c.contains("il-guest") || c.contains("il-free") || c.contains("il-pro") || c.contains("il-auth-pending")) return;
    var t = null;
    try { t = localStorage.getItem(HINT); } catch (_) {}
    c.add(t === "guest" || t === "free" || t === "pro" ? "il-" + t : "il-auth-pending");
  })();

  /* ── Search ────────────────────────────────────────────────────────── */
  function goTicker(sym) {
    sym = String(sym || "").trim().toUpperCase();
    if (sym) location.href = "/research/" + encodeURIComponent(sym);
  }
  function wireSearch(input, list) {
    var items = [], sel = -1, seq = 0, timer = null;
    function close() { list.hidden = true; input.setAttribute("aria-expanded", "false"); input.removeAttribute("aria-activedescendant"); sel = -1; }
    function paint() {
      list.innerHTML = items.length
        ? items.map(function (it, i) {
            return '<button type="button" role="option" class="item" id="sugg-' + i + '" data-sym="' + esc(it.symbol) + '" aria-selected="' + (i === sel) + '">' +
              '<span class="sym">' + esc(it.symbol) + '</span><span class="name">' + esc(it.name || "") + "</span></button>";
          }).join("")
        : '<div class="empty">No match. Press Enter to open ' + esc(input.value.trim().toUpperCase()) + " anyway.</div>";
      list.hidden = false; input.setAttribute("aria-expanded", "true");
      if (sel >= 0) input.setAttribute("aria-activedescendant", "sugg-" + sel); else input.removeAttribute("aria-activedescendant");
    }
    function query() {
      var q = input.value.trim(); if (!q) { close(); return; }
      var my = ++seq;
      fetch("/api/search?q=" + encodeURIComponent(q), { credentials: "same-origin", headers: { Accept: "application/json" } })
        .then(function (r) { return r.ok ? r.json() : null; }).catch(function () { return null; })
        .then(function (j) { if (my !== seq) return; items = (j && j.results ? j.results : []).slice(0, 8); sel = items.length ? 0 : -1; paint(); });
    }
    input.addEventListener("input", function () { clearTimeout(timer); timer = setTimeout(query, 110); });
    input.addEventListener("focus", function () { if (input.value.trim()) query(); });
    input.addEventListener("keydown", function (e) {
      if (e.key === "ArrowDown" && items.length) { e.preventDefault(); sel = (sel + 1) % items.length; paint(); }
      else if (e.key === "ArrowUp" && items.length) { e.preventDefault(); sel = (sel - 1 + items.length) % items.length; paint(); }
      else if (e.key === "Enter") { e.preventDefault(); goTicker(sel >= 0 && items[sel] ? items[sel].symbol : input.value); }
      else if (e.key === "Escape") { close(); input.blur(); }
    });
    list.addEventListener("mousedown", function (e) { e.preventDefault(); });
    list.addEventListener("click", function (e) { var b = e.target.closest("[data-sym]"); if (b) goTicker(b.getAttribute("data-sym")); });
    input.addEventListener("blur", function () { setTimeout(close, 120); });
  }

  /* ── Theme ─────────────────────────────────────────────────────────── */
  function theme() { return document.documentElement.getAttribute("data-theme") === "dark" ? "dark" : "light"; }
  function setTheme(t) {
    if (t === theme()) return;
    /* The old app recolours its charts in its own toggle; use it there. */
    if (document.documentElement.classList.contains("il-shell-legacy") && typeof window.toggleTheme === "function") { window.toggleTheme(); return; }
    if (t === "dark") document.documentElement.setAttribute("data-theme", "dark");
    else document.documentElement.removeAttribute("data-theme");
    try { localStorage.setItem("il-theme", t); } catch (_) {}
    if (window.syncBrowserChrome) window.syncBrowserChrome();
    document.dispatchEvent(new CustomEvent("il:theme", { detail: t }));
  }

  /* ── Mounting ──────────────────────────────────────────────────────── */
  function shadowFor(host, part, html) {
    var root = host.shadowRoot;
    if (!root) {
      root = host.attachShadow({ mode: "open" });
      root.innerHTML = "<style>" + CSS + "</style>" + html;
    }
    host.setAttribute("data-part", part);
    return root;
  }
  function markActive(root, active) {
    Array.prototype.forEach.call(root.querySelectorAll("a[aria-current]"), function (a) { a.removeAttribute("aria-current"); });
    if (!active) return;
    var nav = root.querySelectorAll(".nav a, .tabs a");
    Array.prototype.forEach.call(nav, function (a) {
      var k = a.getAttribute("data-k") || activeFor(a.getAttribute("href"));
      if (k === active) a.setAttribute("aria-current", "page");
    });
  }

  function post(path) {
    return fetch("/api/csrf", { credentials: "same-origin" }).then(function (r) { return r.json(); }).catch(function () { return {}; })
      .then(function (c) {
        return fetch(path, { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json", Accept: "application/json", "X-CSRF-Token": c && c.token ? c.token : "" }, body: "{}" });
      })
      .then(function (r) { return r.json().catch(function () { return null; }); })
      .catch(function () { return null; });
  }

  function wireAccount(top) {
    var menu = top.getElementById("menu"), av = top.getElementById("avatar"), themeBtn = top.getElementById("theme");
    var here = encodeURIComponent(location.pathname + location.search);
    top.getElementById("login").href = "/login?next=" + here;
    top.getElementById("signup").href = "/signup?next=" + here;
    function label() { themeBtn.setAttribute("aria-label", "Switch to " + (theme() === "dark" ? "light" : "dark") + " theme"); }
    label();
    themeBtn.addEventListener("click", function () { setTheme(theme() === "dark" ? "light" : "dark"); });
    new MutationObserver(label).observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });

    function setMenu(open) { menu.hidden = !open; av.setAttribute("aria-expanded", String(open)); }
    av.addEventListener("click", function () { setMenu(menu.hidden); });
    /* Clicks inside the shadow root reach the page retargeted to the host,
       so "outside" is decided from the event's composed path. */
    document.addEventListener("click", function (e) {
      if (menu.hidden) return;
      var path = e.composedPath ? e.composedPath() : [];
      if (path.indexOf(menu) < 0 && path.indexOf(av) < 0) setMenu(false);
    });
    document.addEventListener("keydown", function (e) { if (e.key === "Escape" && !menu.hidden) { setMenu(false); av.focus(); } });
    top.getElementById("logout").addEventListener("click", function () {
      try { localStorage.setItem(HINT, "guest"); localStorage.removeItem("il-shell-initial"); } catch (_) {}
      post("/api/auth/logout").then(function () { location.href = "/"; });
    });
    var currentTier = "guest";
    top.getElementById("billing").addEventListener("click", function () {
      if (currentTier !== "pro") { location.href = "/pricing"; return; }
      post("/api/stripe/portal").then(function (j) { location.href = j && j.url ? j.url : "mailto:support@impliedlens.com?subject=ImpliedLens%20billing"; });
    });
    return function fill(u) {
      currentTier = tier(u);
      if (!u) return;
      var name = String(u.username || u.email || "Your account");
      var initial = name.trim().charAt(0).toUpperCase();
      av.textContent = initial;
      try { localStorage.setItem("il-shell-initial", initial); } catch (_) {}
      top.getElementById("mhead").innerHTML = "<strong>" + esc(name) + "</strong>" + (u.plan === "pro" ? "Pro member" : u.plan === "trial" ? "Pro trial" : "Free plan");
      top.getElementById("plan").textContent = u.plan === "trial" ? "PRO TRIAL" : "PRO";
      top.getElementById("billing").textContent = currentTier === "pro" ? "Subscription and billing" : "See Pro plans";
    };
  }

  var mounted = false, topRoot = null;
  function mount(opts) {
    if (mounted) return me();
    mounted = true;
    opts = opts || {};
    var active = opts.active != null ? opts.active : activeFor(location.pathname);
    var fill = null;
    var top = document.getElementById("il-top");
    if (top) {
      topRoot = shadowFor(top, "top", topHTML(active));
      markActive(topRoot, active);
      wireSearch(topRoot.getElementById("il-q"), topRoot.getElementById("sugg"));
      fill = wireAccount(topRoot);
    }
    var bottom = document.getElementById("il-bottom");
    if (bottom) markActive(shadowFor(bottom, "tabs", tabsHTML(active)), active);
    document.documentElement.classList.add("il-shell-on");
    document.addEventListener("keydown", function (e) {
      if (e.key !== "/" || e.metaKey || e.ctrlKey || e.altKey) return;
      var t = e.composedPath ? e.composedPath()[0] : e.target;
      if (t && (t.tagName === "INPUT" || t.tagName === "TEXTAREA" || t.tagName === "SELECT" || t.isContentEditable)) return;
      var q = topRoot && topRoot.getElementById("il-q"); if (!q) return;
      e.preventDefault(); q.focus(); q.select();
    });
    return me().then(function (u) {
      setTier(tier(u));
      if (fill) fill(u);
      return u;
    });
  }

  window.ILShell = { mount: mount, me: me, tier: tier, activeFor: activeFor, setTheme: setTheme, theme: theme, markup: markup };

  /* Older pages carry data-auto on the script tag and mount themselves;
     the app pages mount through IL.shell() with their own active tab. */
  var self = document.currentScript;
  if (self && self.hasAttribute("data-auto")) {
    if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", function () { mount(); });
    else mount();
  }
})();
