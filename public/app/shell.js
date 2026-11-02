/* ═══════════════════════════════════════════════════════════════════════════
   The site shell: one top bar, one phone tab bar, one account menu, one
   sign-in check, for every page on the site.

   Every page gets exactly the same bar. The only thing that changes from
   page to page is which tab is marked as the current one. The rebuilt app
   pages call ILShell.mount() through IL.shell(); every older page (landing,
   Learn and the lessons, Pricing, LensToolkit, About, the policy pages)
   gets it injected by lib/asset-stamp.js, which also hides the old bar.
   The bar is drawn inside a shadow root (<il-top>, <il-tabbar>), so no
   page stylesheet can reach in and make one page's bar differ.

   Sign-in decides the calls to action, everywhere, by one rule:
     visitor     → "Log in" and "Sign up free"
     free plan   → "Upgrade"
     Pro / trial → nothing to sell
   Page content follows the same rule through data-show="guest" (visitors
   only), data-show="free" (free accounts only) and data-show="upgrade"
   (anyone not on Pro), data-show="pro" and data-show="member". See shell.css.
   ═══════════════════════════════════════════════════════════════════════════ */
(function () {
  "use strict";
  if (window.ILShell) return;

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
  var SUN = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" aria-hidden="true"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg>';
  var MOON = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" aria-hidden="true"><path d="M20 14.5A8 8 0 0 1 9.5 4 8 8 0 1 0 20 14.5Z"/></svg>';

  function esc(s) { return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) { return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]; }); }
  function $(sel, root) { return (root || document).querySelector(sel); }

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

  /* ── Who is signed in ──────────────────────────────────────────────────
     One request per page, shared with the app (IL.me reuses it), with the
     last answer remembered so a signed-in member never sees "Sign up" flash
     before the request returns. */
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
    syncHosts();
  }
  (function hint() {
    var t = null;
    try { t = localStorage.getItem(HINT); } catch (_) {}
    if (t === "guest" || t === "free" || t === "pro") document.documentElement.classList.add("il-" + t);
    else document.documentElement.classList.add("il-auth-pending");
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

  /* ── The bar ─────────────────────────────────────────────────────────
     Drawn inside a shadow root, so no page stylesheet can restyle it. The
     look lives here, in CSS, next to the markup it styles. */
  var CSS = String.raw`:host{all:initial;display:block;box-sizing:border-box;
  --sh-ground:#F7F5EF;--sh-surface:#FFFFFF;--sh-raised:#F0EEE9;--sh-line:#E4E0D7;--sh-line2:#D6D1C6;
  --sh-text:#16171A;--sh-text2:#4E535B;--sh-text3:#7A7F87;--sh-gold:#C9952F;--sh-gold-text:#8E6414;--sh-gold-soft:rgba(201,149,47,.12);--sh-gold-ink:#17130A;
  --sh-shadow:0 12px 32px -12px rgba(30,24,10,.25);
  font-family:Inter,system-ui,-apple-system,"Segoe UI",sans-serif;font-size:14px;line-height:1.5;color:var(--sh-text);
  -webkit-font-smoothing:antialiased;-moz-osx-font-smoothing:grayscale;text-rendering:optimizeLegibility}
:host([data-theme="dark"]){
  --sh-ground:#0E0F11;--sh-surface:#15171A;--sh-raised:#1F2328;--sh-line:#22262B;--sh-line2:#33383E;
  --sh-text:#EDEEF0;--sh-text2:#A3A9B1;--sh-text3:#7D848D;--sh-gold:#E5B65A;--sh-gold-text:#E5B65A;--sh-gold-soft:rgba(229,182,90,.12);--sh-gold-ink:#17130A;
  --sh-shadow:0 16px 40px -16px rgba(0,0,0,.8)}
*,*::before,*::after{box-sizing:border-box}
a{color:inherit;text-decoration:none}
button{font:inherit;color:inherit}
svg{display:block}
[hidden]{display:none !important}
:host([data-tier="pro"]) [data-show="upgrade"]{display:none !important}
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
.iconbtn{width:36px;height:36px;padding:0;margin:0;border-radius:9px;border:1px solid transparent;background:transparent;color:var(--sh-text2);display:grid;place-items:center;cursor:pointer}
.iconbtn:hover{background:var(--sh-raised);color:var(--sh-text)}
.avatar{width:34px;height:34px;padding:0;margin:0;border-radius:999px;border:1px solid var(--sh-line2);background:var(--sh-raised);color:var(--sh-text);font-weight:600;font-size:13px;cursor:pointer;display:grid;place-items:center}

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
  .nav,.word,.kbd,.plan,#theme,.acct .ghost{display:none}
  .search{max-width:none}
}`;
  var hosts = [];
  function shadow(host, part) {
    var root = host.shadowRoot || host.attachShadow({ mode: "open" });
    host.setAttribute("data-part", part);
    root.innerHTML = "<style>" + CSS + "</style>";
    hosts.push(host);
    syncHost(host);
    return root;
  }
  function syncHost(host) {
    if (theme() === "dark") host.setAttribute("data-theme", "dark"); else host.removeAttribute("data-theme");
    var t = currentTier();
    if (t) host.setAttribute("data-tier", t); else host.removeAttribute("data-tier");
  }
  function currentTier() {
    var c = document.documentElement.classList;
    return c.contains("il-pro") ? "pro" : c.contains("il-free") ? "free" : c.contains("il-guest") ? "guest" : "";
  }
  function syncHosts() { hosts.forEach(syncHost); }

  function loginHref() { return "/login?next=" + encodeURIComponent(location.pathname + location.search); }
  function signupHref() { return "/signup?next=" + encodeURIComponent(location.pathname + location.search); }

  var topRoot = null;
  function render(host, active) {
    var root = topRoot = shadow(host, "top");
    var bar = document.createElement("div");
    bar.className = "bar";
    bar.setAttribute("role", "banner");
    bar.innerHTML =
      '<div class="in">' +
        '<a class="brand" href="/" aria-label="ImpliedLens home"><img src="/logo-mark-68.png" width="28" height="28" alt=""><span class="word">Implied<span class="accent">Lens</span></span></a>' +
        '<nav class="nav" aria-label="Main">' + NAV.map(function (n) {
          return '<a href="' + n.href + '"' + (n.key === active ? ' aria-current="page"' : "") + (n.key === "pricing" ? ' data-show="upgrade"' : "") + ">" + n.label + "</a>";
        }).join("") + "</nav>" +
        '<div class="search" role="search">' +
          '<label class="box">' + SEARCH_ICON +
            '<input id="il-q" type="search" autocomplete="off" spellcheck="false" placeholder="Search a company or ticker" aria-label="Search a company or ticker" role="combobox" aria-expanded="false" aria-controls="sugg" aria-autocomplete="list">' +
            '<span class="kbd" aria-hidden="true">/</span>' +
          "</label>" +
          '<div class="sugg" id="sugg" role="listbox" aria-label="Matching companies" hidden></div>' +
        "</div>" +
        '<div class="acct" id="acct"></div>' +
      "</div>";
    root.appendChild(bar);
    wireSearch(root.getElementById("il-q"), root.getElementById("sugg"));
  }

  function renderBottom(host, active) {
    var root = shadow(host, "tabs");
    var nav = document.createElement("nav");
    nav.className = "tabs";
    nav.setAttribute("aria-label", "Main");
    nav.innerHTML = NAV.filter(function (n) { return TAB_ICON[n.key]; }).map(function (n) {
      return '<a href="' + n.href + '"' + (n.key === active ? ' aria-current="page"' : "") + '><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' + TAB_ICON[n.key] + "</svg><span>" + n.label + "</span></a>";
    }).join("");
    root.appendChild(nav);
  }

  var menuWired = false, menuState = { menu: null, av: null };
  function renderAccount(box, u) {
    var t = tier(u);
    var themeBtn = '<button class="iconbtn" id="theme" type="button" aria-label="Switch to ' + (theme() === "dark" ? "light" : "dark") + ' theme">' + (theme() === "dark" ? SUN : MOON) + "</button>";
    menuState.menu = menuState.av = null;
    if (t === "guest") {
      box.innerHTML = themeBtn + '<a class="btn ghost" href="' + loginHref() + '">Log in</a><a class="btn gold" href="' + signupHref() + '">Sign up free</a>';
    } else {
      var name = String(u.username || u.email || "Your account");
      var initial = name.trim().charAt(0).toUpperCase();
      box.innerHTML = (t === "free" ? '<a class="btn gold" href="/pricing">Upgrade</a>' : '<span class="plan">' + (u.plan === "trial" ? "PRO TRIAL" : "PRO") + "</span>") + themeBtn +
        '<button class="avatar" id="avatar" type="button" aria-haspopup="menu" aria-expanded="false" aria-controls="menu" aria-label="Account menu">' + esc(initial) + "</button>" +
        '<div class="menu" id="menu" role="menu" hidden>' +
          '<div class="head"><strong>' + esc(name) + "</strong>" + (u.plan === "pro" ? "Pro member" : u.plan === "trial" ? "Pro trial" : "Free plan") + "</div>" +
          '<a role="menuitem" href="/watchlist">Watchlist and saved work</a>' +
          '<a role="menuitem" href="/compare">Compare stocks</a>' +
          '<a role="menuitem" href="/?account=1">Account settings</a>' +
          '<button role="menuitem" type="button" id="billing">' + (t === "pro" ? "Subscription and billing" : "See Pro plans") + "</button>" +
          "<hr>" +
          '<button role="menuitem" type="button" id="logout">Log out</button>' +
        "</div>";
      var av = $("#avatar", box), menu = $("#menu", box);
      menuState.menu = menu; menuState.av = av;
      av.addEventListener("click", function () { setMenu(menu.hidden); });
      $("#billing", box).addEventListener("click", function () {
        if (t !== "pro") { location.href = "/pricing"; return; }
        post("/api/stripe/portal").then(function (j) { location.href = j && j.url ? j.url : "mailto:support@impliedlens.com?subject=ImpliedLens%20billing"; });
      });
      $("#logout", box).addEventListener("click", function () {
        try { localStorage.setItem(HINT, "guest"); } catch (_) {}
        post("/api/auth/logout").then(function () { location.href = "/"; });
      });
      if (!menuWired) {
        menuWired = true;
        /* Clicks inside the shadow root reach the page retargeted to the host,
           so "outside" is decided from the event's composed path. */
        document.addEventListener("click", function (e) {
          var m = menuState.menu; if (!m || m.hidden) return;
          var path = e.composedPath ? e.composedPath() : [];
          if (path.indexOf(m) < 0 && path.indexOf(menuState.av) < 0) setMenu(false);
        });
        document.addEventListener("keydown", function (e) {
          var m = menuState.menu;
          if (e.key === "Escape" && m && !m.hidden) { setMenu(false); menuState.av.focus(); }
        });
      }
    }
    $("#theme", box).addEventListener("click", function () { setTheme(theme() === "dark" ? "light" : "dark"); });
  }
  function setMenu(open) {
    if (!menuState.menu) return;
    menuState.menu.hidden = !open;
    menuState.av.setAttribute("aria-expanded", String(open));
  }

  function post(path) {
    return fetch("/api/csrf", { credentials: "same-origin" }).then(function (r) { return r.json(); }).catch(function () { return {}; })
      .then(function (c) {
        return fetch(path, { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json", Accept: "application/json", "X-CSRF-Token": c && c.token ? c.token : "" }, body: "{}" });
      })
      .then(function (r) { return r.json().catch(function () { return null; }); })
      .catch(function () { return null; });
  }

  var mounted = false, lastUser = null;
  function mount(opts) {
    if (mounted) return me();
    mounted = true;
    opts = opts || {};
    var active = opts.active != null ? opts.active : activeFor(location.pathname);
    var top = document.getElementById("il-top");
    if (top) render(top, active);
    var bottom = document.getElementById("il-bottom");
    if (bottom) renderBottom(bottom, active);
    document.documentElement.classList.add("il-shell-on");
    /* The theme can change from anywhere (this bar, an older page's own
       toggle, another tab); the bar follows the page. */
    new MutationObserver(function () {
      syncHosts();
      var box = topRoot && topRoot.getElementById("acct");
      if (box && box.firstChild) renderAccount(box, lastUser);
    }).observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });
    document.addEventListener("keydown", function (e) {
      if (e.key !== "/" || e.metaKey || e.ctrlKey || e.altKey) return;
      var t = e.composedPath ? e.composedPath()[0] : e.target;
      if (t && (t.tagName === "INPUT" || t.tagName === "TEXTAREA" || t.tagName === "SELECT" || t.isContentEditable)) return;
      var q = topRoot && topRoot.getElementById("il-q"); if (!q) return;
      e.preventDefault(); q.focus(); q.select();
    });
    return me().then(function (u) {
      lastUser = u;
      setTier(tier(u));
      var box = topRoot && topRoot.getElementById("acct");
      if (box) renderAccount(box, u);
      return u;
    });
  }

  window.ILShell = { mount: mount, me: me, tier: tier, activeFor: activeFor, setTheme: setTheme, theme: theme };

  /* Older pages carry data-il-shell on the script tag and mount themselves;
     the app pages mount through IL.shell() with their own active tab. */
  var self = document.currentScript;
  if (self && self.hasAttribute("data-auto")) {
    if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", function () { mount(); });
    else mount();
  }
})();
