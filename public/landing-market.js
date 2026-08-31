/* Reference-matched landing market terminal.
 * Every visible value comes from /api/market/landing-summary. No synthetic
 * fallback values are rendered when a provider is unavailable.
 */
(function () {
  'use strict';

  var root = document.getElementById('il-movers');
  if (!root) return;

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

  function render(data) {
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

  if ('IntersectionObserver' in window) {
    var observer = new IntersectionObserver(function (entries) {
      if (entries.some(function (entry) { return entry.isIntersecting; })) {
        observer.disconnect(); load();
      }
    }, { rootMargin: '250px' });
    observer.observe(root);
  } else {
    load();
  }
})();
