/* Reference-matched landing market terminal.
 * Every visible value comes from /api/market/landing-summary. No synthetic
 * fallback values are rendered when a provider is unavailable.
 */
(function () {
  'use strict';

  var root = document.getElementById('il-movers');
  var hero = document.getElementById('il-hero-live');
  // The hero and the lower terminal are two views of one request. Either can
  // be absent; the fetch still runs if the other is present.
  if (!root && !hero) return;

  function number(value, digits) {
    return Number.isFinite(Number(value))
      ? Number(value).toLocaleString('en-US', { minimumFractionDigits: digits, maximumFractionDigits: digits })
      : '—';
  }

  function pct(value) {
    if (!Number.isFinite(Number(value))) return '—';
    var n = Number(value);
    return (n >= 0 ? '+' : '') + n.toFixed(2) + '%';
  }

  function sparkPath(values, width, height) {
    var nums = (Array.isArray(values) ? values : []).map(Number).filter(Number.isFinite);
    if (nums.length < 2) return '';
    var min = Math.min.apply(Math, nums);
    var max = Math.max.apply(Math, nums);
    var span = max - min || 1;
    return nums.map(function (value, index) {
      var x = (index / (nums.length - 1)) * width;
      var y = height - 3 - ((value - min) / span) * (height - 7);
      return (index ? 'L' : 'M') + x.toFixed(2) + ' ' + y.toFixed(2);
    }).join(' ');
  }

  function setDirection(element, value) {
    if (!element) return;
    element.classList.remove('is-up', 'is-dn');
    if (Number.isFinite(Number(value))) element.classList.add(Number(value) >= 0 ? 'is-up' : 'is-dn');
  }

  function renderOverview(overview) {
    if (!root) return;
    var priceEl = document.getElementById('ilm-index-price');
    var changeEl = document.getElementById('ilm-index-change');
    var line = root.querySelector('.ilm-market-line');
    var fill = root.querySelector('.ilm-market-fill');
    if (!overview) {
      document.getElementById('ilm-market-status').textContent = 'Unavailable';
      return;
    }
    priceEl.textContent = number(overview.price, 2);
    changeEl.textContent = pct(overview.changePct);
    setDirection(changeEl, overview.changePct);
    var path = sparkPath(overview.closes, 260, 62);
    line.setAttribute('d', path);
    fill.setAttribute('d', path ? path + ' L260 62 L0 62 Z' : '');
  }

  function renderSectors(sectors) {
    var list = document.getElementById('ilm-sector-list');
    list.innerHTML = '';
    var items = (Array.isArray(sectors) ? sectors : []).filter(function (item) {
      return item && Number.isFinite(Number(item.changePct));
    }).slice(0, 6);
    if (!items.length) {
      list.innerHTML = '<p class="ilm-unavailable">Sector data unavailable.</p>';
      return;
    }
    var maxAbs = Math.max.apply(Math, items.map(function (item) { return Math.abs(Number(item.changePct)); }).concat([1]));
    items.forEach(function (item) {
      var change = Number(item.changePct);
      var row = document.createElement('div');
      row.className = 'ilm-sector-row';
      var name = document.createElement('span');
      name.textContent = item.name;
      var track = document.createElement('i');
      var bar = document.createElement('b');
      bar.style.width = Math.max(8, Math.min(100, Math.abs(change) / maxAbs * 100)) + '%';
      bar.className = change >= 0 ? 'is-up' : 'is-dn';
      track.appendChild(bar);
      var value = document.createElement('em');
      value.textContent = pct(change);
      value.className = change >= 0 ? 'is-up' : 'is-dn';
      row.appendChild(name); row.appendChild(track); row.appendChild(value);
      list.appendChild(row);
    });
  }

  function renderBreadth(data) {
    var score = Number(data.breadth);
    var gauge = document.getElementById('ilm-gauge');
    var scoreEl = document.getElementById('ilm-breadth-score');
    var labelEl = document.getElementById('ilm-breadth-label');
    var countEl = document.getElementById('ilm-breadth-count');
    if (!Number.isFinite(score)) {
      labelEl.textContent = 'Unavailable';
      return;
    }
    gauge.style.setProperty('--breadth', Math.max(0, Math.min(100, score)));
    scoreEl.textContent = Math.round(score);
    labelEl.textContent = score >= 67 ? 'Bullish' : score <= 33 ? 'Bearish' : 'Balanced';
    countEl.textContent = String(data.advancing || 0) + '/' + String(data.measured || 0);
  }

  function ageLabel(epochSeconds) {
    if (!Number.isFinite(Number(epochSeconds))) return '';
    var minutes = Math.max(0, Math.floor((Date.now() / 1000 - Number(epochSeconds)) / 60));
    if (minutes < 60) return minutes <= 1 ? 'now' : minutes + 'm ago';
    var hours = Math.floor(minutes / 60);
    return hours < 24 ? hours + 'h ago' : Math.floor(hours / 24) + 'd ago';
  }

  function renderNews(news) {
    var list = document.getElementById('ilm-news-list');
    list.innerHTML = '';
    var items = (Array.isArray(news) ? news : []).slice(0, 3);
    if (!items.length) {
      var links = [
        ['Build a repeatable stock thesis', '/research-process', 'Research process'],
        ['See where every number comes from', '/data-sources', 'Data sources'],
        ['Read quality, value, and setup together', '/lens-score', 'LensScore'],
      ];
      document.getElementById('ilm-source-label').textContent = 'Implied Lens';
      links.forEach(function (entry) {
        var link = document.createElement('a');
        link.href = entry[1];
        var strong = document.createElement('strong'); strong.textContent = entry[0];
        var span = document.createElement('span'); span.textContent = entry[2];
        link.appendChild(strong); link.appendChild(span); list.appendChild(link);
      });
      return;
    }
    items.forEach(function (item) {
      var link = document.createElement('a');
      link.href = item.url || '/blog';
      if (item.url) { link.target = '_blank'; link.rel = 'noopener noreferrer'; }
      var strong = document.createElement('strong'); strong.textContent = item.headline;
      var span = document.createElement('span'); span.textContent = ageLabel(item.datetime) || item.source || '';
      link.appendChild(strong); link.appendChild(span); list.appendChild(link);
    });
  }

  /* ── Live hero ───────────────────────────────────────────────────────────
     Same request, same honesty rule as the terminal below it: if a provider
     did not answer, the hero says so rather than showing a shaped number. */
  function areaPath(values, width, height) {
    var line = sparkPath(values, width, height);
    return line ? line + ' L' + width + ' ' + height + ' L0 ' + height + ' Z' : '';
  }

  function relativeTime(iso) {
    var t = Date.parse(iso || '');
    if (!Number.isFinite(t)) return '';
    var mins = Math.max(0, Math.round((Date.now() - t) / 60000));
    if (mins < 1) return 'Updated just now';
    if (mins === 1) return 'Updated 1 minute ago';
    if (mins < 60) return 'Updated ' + mins + ' minutes ago';
    var hrs = Math.round(mins / 60);
    return 'Updated ' + hrs + (hrs === 1 ? ' hour ago' : ' hours ago');
  }

  function text(id, value) {
    var el = document.getElementById(id);
    if (el) el.textContent = value;
  }

  function renderHero(data) {
    if (!hero) return;
    var overview = data && data.overview;
    var empty = document.getElementById('ihl-empty');
    var sectorWrap = document.getElementById('ihl-sectors');

    if (!overview || !Number.isFinite(Number(overview.price))) {
      var mobileEmpty = document.getElementById('il-hero-live-mobile');
      hero.classList.add('is-empty');
      if (mobileEmpty) mobileEmpty.classList.add('is-empty');
      text('ihl-state', 'Unavailable');
      text('ihl-state-m', 'Unavailable');
      text('ihl-price', '—');
      text('ihl-price-m', '—');
      text('ihl-change', '');
      text('ihl-change-m', '');
      text('ihl-asof', 'The market data provider did not respond.');
      text('ihl-asof-m', 'Market data unavailable');
      if (empty) empty.hidden = false;
      if (sectorWrap) sectorWrap.innerHTML = '';
      return;
    }

    hero.classList.remove('is-empty');
    if (empty) empty.hidden = true;
    text('ihl-state', 'Live');
    text('ihl-state-m', 'Live');
    text('ihl-price', number(overview.price, 2));
    text('ihl-price-m', number(overview.price, 2));
    text('ihl-change', pct(overview.changePct));
    text('ihl-change-m', pct(overview.changePct));
    setDirection(document.getElementById('ihl-change'), overview.changePct);
    setDirection(document.getElementById('ihl-change-m'), overview.changePct);
    var mobile = document.getElementById('il-hero-live-mobile');
    [hero, mobile].forEach(function (el) {
      if (!el) return;
      el.classList.remove('is-empty');
      el.classList.toggle('is-up', Number(overview.changePct) >= 0);
      el.classList.toggle('is-dn', Number(overview.changePct) < 0);
    });

    var pairs = [['ihl-line', 'ihl-area', 640, 168], ['ihl-line-m', 'ihl-area-m', 360, 96]];
    for (var i = 0; i < pairs.length; i++) {
      var lineEl = document.getElementById(pairs[i][0]);
      var areaEl = document.getElementById(pairs[i][1]);
      if (lineEl) lineEl.setAttribute('d', sparkPath(overview.closes, pairs[i][2], pairs[i][3]));
      if (areaEl) areaEl.setAttribute('d', areaPath(overview.closes, pairs[i][2], pairs[i][3]));
    }

    if (sectorWrap) {
      var sectors = Array.isArray(data.sectors) ? data.sectors : [];
      sectorWrap.innerHTML = sectors.slice(0, 6).map(function (s) {
        var up = Number(s.changePct) >= 0;
        return '<span class="ihl-sector ' + (Number.isFinite(Number(s.changePct)) ? (up ? 'is-up' : 'is-dn') : '') + '">' +
          '<b>' + String(s.name || s.symbol || '').replace(/[<>&]/g, '') + '</b>' +
          '<i>' + pct(s.changePct) + '</i></span>';
      }).join('');
    }

    text('ihl-asof', relativeTime(data.asOf));
    text('ihl-asof-m', relativeTime(data.asOf));
    var src = document.getElementById('ihl-src');
    if (src && data.source) src.textContent = String(data.source).replace(/[<>&]/g, '');
  }

  function render(data) {
    renderHero(data || {});
    if (!root) return;
    renderOverview(data && data.overview);
    renderSectors(data && data.sectors);
    renderBreadth(data || {});
    renderNews(data && data.news);
  }

  function load() {
    fetch('/api/market/landing-summary', { headers: { Accept: 'application/json' } })
      .then(function (response) { if (!response.ok) throw new Error('summary unavailable'); return response.json(); })
      .then(render)
      .catch(function () { render({}); });
  }

  // The hero is above the fold, so it cannot wait for an intersection.
  if (hero || !('IntersectionObserver' in window)) {
    load();
  } else {
    var observer = new IntersectionObserver(function (entries) {
      if (entries.some(function (entry) { return entry.isIntersecting; })) {
        observer.disconnect(); load();
      }
    }, { rootMargin: '250px' });
    observer.observe(root);
  }
})();
