/* Landing market strip — Top Movers.
 *
 * Uses GET /api/market/movers?type=gainers|losers|active, which is the free,
 * unmetered endpoint (2-minute server cache, no checkAnalysisLimit middleware).
 * Deliberately NOT /api/quote/:ticker — that one runs through
 * checkAnalysisLimit, so putting it on the landing would spend a visitor's
 * free analysis quota just for loading the home page.
 *
 * Every number rendered here comes from the API. Nothing is placeholder.
 */
(function () {
  'use strict';

  var root = document.getElementById('il-movers');
  if (!root) return;

  var listEl = root.querySelector('.ilm-list');
  var tabs = root.querySelectorAll('.ilm-tab');
  var cache = {};
  var current = 'gainers';

  function fmtPct(n) {
    if (typeof n !== 'number' || !isFinite(n)) return '—';
    return (n >= 0 ? '+' : '') + n.toFixed(2) + '%';
  }
  function fmtPrice(n) {
    if (typeof n !== 'number' || !isFinite(n)) return '—';
    return n.toFixed(2);
  }

  function skeleton() {
    listEl.setAttribute('aria-busy', 'true');
    listEl.innerHTML = '';
    for (var i = 0; i < 5; i++) {
      var r = document.createElement('div');
      r.className = 'ilm-row is-load';
      r.innerHTML = '<span class="ilm-sym"></span><span class="ilm-name"></span><span class="ilm-chg"></span>';
      listEl.appendChild(r);
    }
  }

  function render(items) {
    listEl.setAttribute('aria-busy', 'false');
    listEl.innerHTML = '';
    if (!items || !items.length) {
      var e = document.createElement('p');
      e.className = 'ilm-empty';
      e.textContent = 'Market data is unavailable right now.';
      listEl.appendChild(e);
      return;
    }
    items.slice(0, 5).forEach(function (it) {
      var up = (it.chgPct || 0) >= 0;
      var row = document.createElement('a');
      row.className = 'ilm-row';
      row.href = '/?view=tool&section=analyze&ticker=' + encodeURIComponent(it.symbol);

      var sym = document.createElement('span');
      sym.className = 'ilm-sym';
      sym.textContent = it.symbol;

      var name = document.createElement('span');
      name.className = 'ilm-name';
      name.textContent = it.name || '';

      var price = document.createElement('span');
      price.className = 'ilm-price';
      price.textContent = fmtPrice(it.price);

      var chg = document.createElement('span');
      chg.className = 'ilm-chg ' + (up ? 'is-up' : 'is-dn');
      chg.textContent = fmtPct(it.chgPct);

      row.appendChild(sym); row.appendChild(name);
      row.appendChild(price); row.appendChild(chg);
      listEl.appendChild(row);
    });
  }

  function load(type) {
    current = type;
    if (cache[type]) { render(cache[type]); return; }
    skeleton();
    fetch('/api/market/movers?type=' + encodeURIComponent(type), { headers: { Accept: 'application/json' } })
      .then(function (r) { return r.ok ? r.json() : []; })
      .then(function (items) {
        if (!Array.isArray(items)) items = [];
        cache[type] = items;
        if (current === type) render(items);
      })
      .catch(function () { if (current === type) render([]); });
  }

  Array.prototype.forEach.call(tabs, function (tab) {
    tab.addEventListener('click', function () {
      Array.prototype.forEach.call(tabs, function (t) {
        t.classList.remove('on');
        t.setAttribute('aria-selected', 'false');
      });
      tab.classList.add('on');
      tab.setAttribute('aria-selected', 'true');
      load(tab.dataset.type);
    });
  });

  // Only fetch once the strip is actually near the viewport — the landing
  // should not spend a request on content nobody has scrolled to.
  if ('IntersectionObserver' in window) {
    var io = new IntersectionObserver(function (entries) {
      if (entries.some(function (e) { return e.isIntersecting; })) {
        io.disconnect();
        load('gainers');
      }
    }, { rootMargin: '200px' });
    io.observe(root);
  } else {
    load('gainers');
  }
})();
