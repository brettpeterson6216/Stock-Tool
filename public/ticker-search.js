/* ============================================================
   Ticker / company search — one behaviour, every search box
   ============================================================
   There were four search inputs on the site and each one did something
   slightly different: the header form posted a raw string, the research input
   took a symbol on Enter, the workspace one took a symbol and cleared itself.
   None of them accepted a company name, none had a way to clear, and typing
   lowercase silently produced a lookup that failed.

   This upgrades every one of them in place. It adds no markup to any page —
   the header block is byte-identical across ~15 documents and a test enforces
   that — so the listbox and the clear button are created here at runtime.

   Selection never reimplements what each input already does on Enter: it sets
   the symbol and then submits the form, or dispatches the Enter the existing
   handler is already listening for. One code path to break, not four.
   ============================================================ */
(function () {
  "use strict";

  var TARGETS = ["#nav-ticker-input", "#main-ticker", "#il-quick-ticker", "[data-ticker-search]"];
  var DEBOUNCE_MS = 160;
  var MIN_CHARS = 1;
  var LIMIT = 7;

  var cache = new Map();
  var seq = 0;
  var openBox = null;

  function normalize(value) {
    return String(value == null ? "" : value).trim().replace(/\s+/g, " ").toUpperCase().slice(0, 48);
  }

  function fetchSuggestions(query) {
    if (cache.has(query)) return Promise.resolve(cache.get(query));
    return fetch("/api/search?q=" + encodeURIComponent(query) + "&limit=" + LIMIT, {
      headers: { Accept: "application/json" },
    })
      .then(function (r) { return r.ok ? r.json() : { results: [] }; })
      .then(function (payload) {
        var results = (payload && payload.results) || [];
        if (cache.size > 200) cache.clear();
        cache.set(query, results);
        return results;
      })
      .catch(function () { return []; });
  }

  /* Matched characters marked up as nodes, never as HTML: these strings come
     from EDGAR and from a vendor, and one of them will eventually contain an
     ampersand-something that is not a company name. */
  function markMatch(text, query) {
    var frag = document.createDocumentFragment();
    var at = text.toUpperCase().indexOf(query);
    if (at < 0 || !query) { frag.appendChild(document.createTextNode(text)); return frag; }
    if (at > 0) frag.appendChild(document.createTextNode(text.slice(0, at)));
    var mark = document.createElement("mark");
    mark.textContent = text.slice(at, at + query.length);
    frag.appendChild(mark);
    if (at + query.length < text.length) frag.appendChild(document.createTextNode(text.slice(at + query.length)));
    return frag;
  }

  function Combobox(input) {
    this.input = input;
    this.wrap = input.closest("form, .il-quick-search, .ticker-input-wrap, .search-row") || input.parentElement;
    this.list = null;
    this.rows = [];
    this.active = -1;
    this.query = "";
    this.timer = 0;
    this.id = "ts-list-" + (++seq);
    this.install();
  }

  Combobox.prototype.install = function () {
    var self = this;
    var input = this.input;

    input.setAttribute("role", "combobox");
    input.setAttribute("aria-autocomplete", "list");
    input.setAttribute("aria-expanded", "false");
    input.setAttribute("aria-controls", this.id);
    input.setAttribute("autocomplete", "off");
    input.setAttribute("autocapitalize", "characters");
    input.setAttribute("spellcheck", "false");
    input.classList.add("ts-input");
    if (this.wrap) this.wrap.classList.add("ts-wrap");

    // A search box with text in it and no way to empty it reads as stuck.
    this.clear = document.createElement("button");
    this.clear.type = "button";
    this.clear.className = "ts-clear";
    this.clear.setAttribute("aria-label", "Clear search");
    this.clear.hidden = true;
    this.clear.innerHTML = '<svg viewBox="0 0 16 16" aria-hidden="true" focusable="false"><path d="M4 4l8 8M12 4l-8 8" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/></svg>';
    this.clear.addEventListener("mousedown", function (e) { e.preventDefault(); });
    this.clear.addEventListener("click", function () {
      input.value = "";
      self.syncClear();
      self.close();
      input.focus();
    });
    if (this.wrap) this.wrap.appendChild(this.clear);

    input.addEventListener("input", function () {
      self.uppercase();
      self.syncClear();
      self.schedule();
    });
    input.addEventListener("focus", function () { if (input.value.trim()) self.schedule(); });
    input.addEventListener("blur", function () { setTimeout(function () { self.close(); }, 120); });
    input.addEventListener("keydown", function (e) { self.onKeydown(e); });
    this.syncClear();
  };

  /* Caps-only. The server matches case-insensitively, so a company name still
     resolves — this is about the field never looking half-typed. */
  Combobox.prototype.uppercase = function () {
    var input = this.input;
    var upper = input.value.toUpperCase();
    if (upper === input.value) return;
    var start = input.selectionStart;
    var end = input.selectionEnd;
    input.value = upper;
    try { input.setSelectionRange(start, end); } catch (e) {}
  };

  Combobox.prototype.syncClear = function () {
    var has = !!this.input.value.length;
    this.clear.hidden = !has;
    if (this.wrap) this.wrap.classList.toggle("ts-has-value", has);
  };

  Combobox.prototype.schedule = function () {
    var self = this;
    clearTimeout(this.timer);
    var query = normalize(this.input.value);
    if (query.length < MIN_CHARS) { this.close(); return; }
    this.timer = setTimeout(function () {
      fetchSuggestions(query).then(function (results) {
        if (normalize(self.input.value) !== query) return;   // typed on since
        if (document.activeElement !== self.input) return;
        self.query = query;
        self.render(results);
      });
    }, DEBOUNCE_MS);
  };

  Combobox.prototype.ensureList = function () {
    if (this.list) return this.list;
    var list = document.createElement("div");
    list.className = "ts-list";
    list.id = this.id;
    list.setAttribute("role", "listbox");
    list.hidden = true;
    // Body-mounted and fixed: the header is a 63px bar and several of these
    // inputs sit inside panels that clip their overflow.
    document.body.appendChild(list);
    this.list = list;
    return list;
  };

  Combobox.prototype.render = function (results) {
    var self = this;
    var list = this.ensureList();
    list.textContent = "";
    this.rows = [];
    this.active = -1;

    if (!results.length) {
      var empty = document.createElement("div");
      empty.className = "ts-empty";
      empty.textContent = "No match for “" + this.query + "”";
      list.appendChild(empty);
    } else {
      results.forEach(function (hit, i) {
        var row = document.createElement("div");
        row.className = "ts-row";
        row.id = self.id + "-" + i;
        row.setAttribute("role", "option");
        row.setAttribute("aria-selected", "false");

        var sym = document.createElement("span");
        sym.className = "ts-sym";
        sym.appendChild(markMatch(hit.symbol, self.query));

        var name = document.createElement("span");
        name.className = "ts-name";
        name.appendChild(markMatch(hit.name || "", self.query));

        row.appendChild(sym);
        row.appendChild(name);
        row.addEventListener("mousedown", function (e) { e.preventDefault(); self.choose(hit.symbol); });
        row.addEventListener("mouseenter", function () { self.setActive(i); });
        list.appendChild(row);
        self.rows.push({ el: row, symbol: hit.symbol });
      });
    }
    this.open();
  };

  Combobox.prototype.position = function () {
    if (!this.list || this.list.hidden) return;
    var anchor = (this.wrap || this.input).getBoundingClientRect();
    // Inside the masthead the field is 34px tall in a 63px bar, so hanging the
    // list off the field itself tucked its first row behind the bar. Hang it
    // off the bar.
    var bar = this.input.closest("nav#main-nav, nav.il-global-nav, header");
    var top = anchor.bottom;
    if (bar) top = Math.max(top, bar.getBoundingClientRect().bottom);
    var width = Math.max(228, Math.min(360, anchor.width < 228 ? 288 : anchor.width));
    var left = Math.min(Math.max(8, anchor.left), window.innerWidth - width - 8);
    this.list.style.top = Math.round(top + 6) + "px";
    this.list.style.left = Math.round(left) + "px";
    this.list.style.width = Math.round(width) + "px";
  };

  Combobox.prototype.open = function () {
    var self = this;
    if (openBox && openBox !== this) openBox.close();
    openBox = this;
    this.list.hidden = false;
    this.input.setAttribute("aria-expanded", "true");
    this.position();
    if (!this._bound) {
      this._bound = function () { self.position(); };
      window.addEventListener("scroll", this._bound, true);
      window.addEventListener("resize", this._bound);
    }
  };

  Combobox.prototype.close = function () {
    clearTimeout(this.timer);
    if (this.list) this.list.hidden = true;
    this.input.setAttribute("aria-expanded", "false");
    this.input.removeAttribute("aria-activedescendant");
    this.active = -1;
    if (this._bound) {
      window.removeEventListener("scroll", this._bound, true);
      window.removeEventListener("resize", this._bound);
      this._bound = null;
    }
    if (openBox === this) openBox = null;
  };

  Combobox.prototype.setActive = function (i) {
    if (!this.rows.length) return;
    this.rows.forEach(function (row) {
      row.el.classList.remove("ts-active");
      row.el.setAttribute("aria-selected", "false");
    });
    this.active = ((i % this.rows.length) + this.rows.length) % this.rows.length;
    var row = this.rows[this.active];
    row.el.classList.add("ts-active");
    row.el.setAttribute("aria-selected", "true");
    this.input.setAttribute("aria-activedescendant", row.el.id);
    if (row.el.scrollIntoView) row.el.scrollIntoView({ block: "nearest" });
  };

  Combobox.prototype.onKeydown = function (e) {
    var openNow = this.list && !this.list.hidden;
    if (e.key === "ArrowDown") {
      if (!openNow) { this.schedule(); return; }
      e.preventDefault();
      this.setActive(this.active + 1);
      return;
    }
    if (e.key === "ArrowUp") {
      if (!openNow) return;
      e.preventDefault();
      this.setActive(this.active - 1);
      return;
    }
    if (e.key === "Escape") {
      if (openNow) { e.preventDefault(); this.close(); return; }
      return;                                  // let the input's own handler run
    }
    if (e.key === "Tab") { this.close(); return; }
    if (e.key === "Enter") {
      if (openNow && this.active >= 0) {
        e.preventDefault();
        this.choose(this.rows[this.active].symbol);
        return;
      }
      // Nothing highlighted: if what was typed is a name rather than a symbol,
      // resolve it before the existing handler turns it into a lookup that
      // cannot succeed.
      var typed = normalize(this.input.value);
      var top = cache.get(typed) && cache.get(typed)[0];
      if (top && top.symbol !== typed && /[^A-Z0-9.^-]/.test(typed)) {
        e.preventDefault();
        this.choose(top.symbol);
        return;
      }
      this.close();
    }
  };

  /* Set the symbol, then let the input do whatever it already does on Enter.
     The header input lives in a real form with a no-JS action, so that one is
     submitted rather than faked. */
  Combobox.prototype.choose = function (symbol) {
    var input = this.input;
    input.value = symbol;
    this.syncClear();
    this.close();
    var form = input.form;
    if (form) {
      if (typeof form.requestSubmit === "function") form.requestSubmit();
      else form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
      return;
    }
    input.dispatchEvent(new Event("change", { bubbles: true }));
    input.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true, cancelable: true }));
  };

  function upgrade(root) {
    (root || document).querySelectorAll(TARGETS.join(",")).forEach(function (input) {
      if (!input || input.dataset.tsReady === "1") return;
      if (input.type === "hidden" || input.disabled) return;
      input.dataset.tsReady = "1";
      new Combobox(input);
    });
  }

  function init() {
    upgrade(document);
    // #il-quick-ticker and the research input are injected by the SPA well
    // after load, so watch for them rather than guessing at a delay.
    if (typeof MutationObserver === "function") {
      var observer = new MutationObserver(function () { upgrade(document); });
      observer.observe(document.documentElement, { childList: true, subtree: true });
    }
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();

  window.ilTickerSearch = { upgrade: upgrade, _cache: cache };
}());
