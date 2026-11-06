/* /methodology — how the LensScore is made, and whether it works.
   Everything on this page comes from /api/lens-method, which reads the same
   code that grades, so the page cannot drift from what the grades do. Test
   results are shown as they came out, good or bad. */
(function () {
  "use strict";
  var IL = window.IL, h = IL.h, F = IL.fmt;
  function n(v) { return v == null ? "—" : Number(v).toLocaleString("en-US"); }

  function pctPts(v) { return v == null ? "—" : (v >= 0 ? "+" : "−") + Math.abs(v * 100).toFixed(1) + " pts"; }
  function rate(v) { return v == null ? "—" : Math.round(v * 100) + "%"; }
  function corr(rc) {
    if (!rc || rc.mean == null) return "—";
    return (rc.mean >= 0 ? "+" : "−") + Math.abs(rc.mean).toFixed(3) + (rc.t != null ? ' <span class="faint">(t ' + F.num(rc.t, 1) + ", " + rc.n + " dates)</span>" : "");
  }
  function card(title, sub, body, id) {
    return '<section class="card" ' + (id ? 'id="' + id + '"' : "") + '><div class="card-h"><h2 class="card-t">' + h(title) + "</h2>" + (sub ? '<span class="card-sub">' + sub + "</span>" : "") + '</div><div class="meth-body">' + body + "</div></section>";
  }

  function hero(d) {
    var u = d.universe || {};
    var size = u.graded ? n(u.graded) + " companies graded" : "Universe filling";
    return '<div class="card prime meth-hero"><div class="stack" style="gap:10px">' +
      '<h1 class="display">How the LensScore is made</h1>' +
      '<p class="muted meth-lede">Five grades, A+ to F, each a percentile against the company’s own industry, built from SEC filings and licensed prices. ' +
      "One score, 0.1 to 9.9, that ranks the whole report card against about " + n(u.target || 1000) + " of the largest US-listed companies. " +
      "Every rule below is read from the code that grades. Whether it works is tested every week, and the result is published here whatever it says.</p>" +
      '<div class="row wrap meth-facts"><span><b class="num">' + h(d.version) + '</b> <span class="faint">method version</span></span>' +
      '<span><b class="num">' + h(size) + "</b></span>" +
      (u.built ? '<span><span class="faint">Universe rebuilt</span> <b class="num">' + F.date(u.built) + "</b></span>" : "") + "</div></div></div>";
  }

  function bandTable(bands) {
    return '<div class="tbl-wrap"><table class="tbl meth-band"><thead><tr><th>Score band</th><th>Observations</th><th>Average vs S&amp;P 500</th><th>Median vs S&amp;P 500</th><th>Beat the S&amp;P 500</th></tr></thead><tbody>' +
      bands.map(function (b) {
        return "<tr><td>" + h(b.label) + '</td><td>' + n(b.observations) + '</td><td class="' + F.cls(b.meanExcess) + '">' + pctPts(b.meanExcess) + '</td><td class="' + F.cls(b.medianExcess) + '">' + pctPts(b.medianExcess) + "</td><td>" + rate(b.beatRate) + "</td></tr>";
      }).join("") + "</tbody></table></div>";
  }

  function evidence(d) {
    var bt = d.backtest, st = d.backtestStatus || {};
    if (!bt || !bt.grades || !bt.grades.horizons) {
      return card("Does it work?", "The weekly test",
        '<p>' + (st.running ? "The first full test is running now." : "The first full test runs this week, once the universe has filled.") +
        " It grades every company at each past month-end using only the SEC figures filed by that date, then measures what each score band did over the next three and six months against the S&amp;P 500.</p>" +
        '<p class="muted">Until it reports, nothing on this site claims that a higher LensScore leads to higher returns. The grades describe a company against its peers today; they are not a forecast.</p>' +
        liveRecord(d), "evidence");
    }
    var g = bt.grades, h3 = g.horizons[63] || {}, h6 = g.horizons[126] || {};
    var body =
      '<p class="meth-verdict">' + h(g.verdict && g.verdict[63] || "") + '</p>' +
      '<p class="muted">' + n(bt.companies) + " companies, graded at " + g.months + " month-ends from " + F.date(bt.window.from) + " to " + F.date(bt.window.to) +
      " using only figures filed by each date. Returns are price returns against the S&amp;P 500 (SPY), before dividends and costs. Last run " + F.date(bt.at) + ".</p>" +
      '<h3 class="meth-h3">Next three months</h3>' + bandTable(h3.bands || []) +
      '<div class="meth-stats"><span><span class="faint">Rank correlation, score vs return</span> <b class="num">' + corr(h3.rankCorrelation) + '</b></span>' +
      '<span><span class="faint">Top fifth minus bottom fifth</span> <b class="num ' + F.cls(h3.topMinusBottomQuintile && h3.topMinusBottomQuintile.mean) + '">' + pctPts(h3.topMinusBottomQuintile && h3.topMinusBottomQuintile.mean) + "</b>" +
      (h3.topMinusBottomQuintile ? ' <span class="faint">positive in ' + h3.topMinusBottomQuintile.positiveMonths + " of " + h3.topMinusBottomQuintile.n + " months</span>" : "") + "</span></div>" +
      '<h3 class="meth-h3">Next six months</h3><p class="muted">' + h(g.verdict && g.verdict[126] || "") + "</p>" + bandTable(h6.bands || []) +
      '<div class="meth-stats"><span><span class="faint">Rank correlation</span> <b class="num">' + corr(h6.rankCorrelation) + "</b></span></div>" +
      '<h3 class="meth-h3">What this test cannot tell you</h3><ul class="meth-list">' + (bt.limits || []).map(function (l) { return "<li>" + h(l) + "</li>"; }).join("") + "</ul>" +
      liveRecord(d);
    return card("Does it work?", "Point-in-time backtest, run weekly", body, "evidence");
  }

  function liveRecord(d) {
    var lr = d.liveRecord;
    if (!lr || !lr.record || !lr.record.bands) return "";
    return '<h3 class="meth-h3">Live record since ' + F.date(lr.since) + '</h3><p class="muted">Every graded company’s score is saved after each close. This is how each starting band has moved since, survivors and losers alike.</p>' +
      '<div class="tbl-wrap"><table class="tbl"><thead><tr><th>Starting band</th><th>Companies</th><th>Average price change</th></tr></thead><tbody>' +
      lr.record.bands.map(function (b) { return "<tr><td>" + h(b.label) + "</td><td>" + n(b.count) + '</td><td class="' + F.cls(b.averageReturn) + '">' + F.spct(b.averageReturn) + "</td></tr>"; }).join("") + "</tbody></table></div>";
  }

  function timing(d) {
    var t = d.backtest && d.backtest.timing;
    var intro = "<p>The LensToolkit page shows a Lens Timing gauge (0 stretched, 10 pulled back) and a setup score; the chart draws buyer and seller zones from LensSetup. These are separate from the LensScore and do not change any grade.</p>";
    if (!t || !t.scorers || !t.scorers.gauge) {
      return card("Is the timing read tested?", "LensToolkit", intro +
        '<p class="muted">An earlier test of the setup score, on 15 large stocks, found no relationship with the next one or three months (rank correlation about zero). Every timing read is now retested each week across the whole universe, and the results appear here. Until they show an edge, read the gauge as a description of where the price sits, not a signal to buy or sell.</p>', "timing");
    }
    var g = t.scorers.gauge, g1 = g.horizons[21], g3 = g.horizons[63];
    return card("Is the timing read tested?", "Walk-forward, each reading sees only earlier prices", intro +
      '<p class="meth-verdict">Lens Timing gauge: ' + h(g.verdict && g.verdict[63] || "") + "</p>" +
      '<p class="muted">' + n(t.observations) + " readings across " + n(t.tickers) + " companies, sampled monthly.</p>" +
      '<div class="tbl-wrap"><table class="tbl meth-gauge"><thead><tr><th>Gauge reading</th><th>Readings</th><th>Next month vs S&amp;P 500</th><th>Next 3 months vs S&amp;P 500</th></tr></thead><tbody>' +
      g3.buckets.map(function (b, i) { var b1 = g1.buckets[i] || {}; return "<tr><td>" + h(b.range) + "</td><td>" + n(b.observations) + '</td><td class="' + F.cls(b1.meanExcess) + '">' + pctPts(b1.meanExcess) + '</td><td class="' + F.cls(b.meanExcess) + '">' + pctPts(b.meanExcess) + "</td></tr>"; }).join("") +
      "</tbody></table></div>" +
      '<h3 class="meth-h3">Every timing read, side by side</h3>' +
      '<div class="tbl-wrap"><table class="tbl"><thead><tr><th>Read</th><th>Rank correlation, next month</th><th>Next 3 months</th><th style="text-align:left">Verdict</th></tr></thead><tbody>' +
      Object.keys(t.scorers).map(function (k) { var x = t.scorers[k]; return "<tr><td>" + h(x.label) + "</td><td>" + corr(x.horizons[21].rankCorrelation) + "</td><td>" + corr(x.horizons[63].rankCorrelation) + '</td><td class="sub" style="text-align:left;white-space:normal">' + h(x.verdict && x.verdict[63] || "") + "</td></tr>"; }).join("") +
      "</tbody></table></div>", "timing");
  }

  function grades(d) {
    var rows = d.factors.map(function (f) {
      return '<tr class="meth-fh"><td colspan="3"><b>' + h(f.label) + '</b> <span class="faint">' + Math.round((d.weights[f.key] || 0) * 100) + "% of the score · " + h(f.question) + "</span></td></tr>" +
        f.metrics.map(function (m) {
          var where = m.only ? "Only " + m.only.map(sector).join(", ") : m.skip ? "Not for " + m.skip.map(sector).join(", ") : "All";
          return '<tr><td style="white-space:normal">' + h(m.label) + '<div class="faint meth-why">' + h(m.why || "") + '</div></td><td>' + h(m.better) + " is better" + (m.weight !== 1 ? " · " + m.weight + "×" : "") + '</td><td class="sub">' + h(where) + "</td></tr>";
        }).join("");
    }).join("");
    return card("The five grades", "Each metric is a percentile among peers; a grade is their weighted average",
      '<div class="tbl-wrap"><table class="tbl meth-tbl"><thead><tr><th>Metric</th><th>Direction and weight</th><th>Applies to</th></tr></thead><tbody>' + rows + "</tbody></table></div>" +
      '<p class="note">Letter cut-offs: A+ from the 90th percentile, A 80, A− 73, B+ 67, B 60, B− 53, C+ 47, C 40, C− 33, D+ 27, D 20, D− 13, F below. A loss counts as the most expensive possible P/E; negative equity as the worst debt ratio. A grade needs at least two of its metrics, and a score needs four of the five grades.</p>', "grades");
  }
  function sector(s) { return { "Finance": "Financials", "Real Est.": "Real Estate" }[s] || s; }

  function score(d) {
    var w = d.weights;
    return card("From grades to one score", "",
      '<p>The score is a weighted blend of the five grades: Profitability ' + Math.round(w.profitability * 100) + "%, Value " + Math.round(w.value * 100) + "%, Growth " + Math.round(w.growth * 100) + "%, Momentum " + Math.round(w.momentum * 100) + "%, Financial health " + Math.round(w.health * 100) + "%. " +
      "That blend is then ranked across every graded company: a 7.5 means the report card beats about 75% of them. It never reads 0 or 10, because a rank is relative to the companies we cover, not a certainty.</p>" +
      '<h3 class="meth-h3">Caps</h3><ul class="meth-list">' + d.caps.map(function (c) { return "<li>" + h(c) + "</li>"; }).join("") + "</ul>" +
      '<p class="note">The weights are a judgement, not fitted to past returns. They will only change if the weekly test shows a better set holds up on years it was not fitted to, and any change is listed in the log below.</p>', "score");
  }

  function peers(d) {
    var p = d.peers, u = d.universe || {};
    var bySector = {};
    p.groups.forEach(function (g) { (bySector[g.sector] = bySector[g.sector] || []).push(g.label); });
    return card("Who a company is compared with", "",
      "<p>A company is graded against its own industry when we grade at least " + p.minIndustry + " of them: chipmakers against chipmakers, banks against banks, REITs against REITs. With fewer, its sector is used (at least " + p.minSector + " companies), and failing that every company we grade. The report card always says which.</p>" +
      "<p>The companies we rank against are fixed: about " + n(u.target || 1000) + " of the largest US-listed companies by public float (the market value of shares held by outside investors, from each company’s annual report), rebuilt every week from SEC data, plus a list of popular names. Anyone can open any stock and get a grade; stocks outside the list are graded against it but never join it, so no one’s rank moves because someone else looked up an obscure company.</p>" +
      '<div class="tbl-wrap"><table class="tbl"><thead><tr><th>Sector</th><th style="text-align:left">Industry groups</th></tr></thead><tbody>' +
      Object.keys(bySector).map(function (s) { return "<tr><td>" + h(s) + '</td><td class="sub" style="text-align:left;white-space:normal">' + h(bySector[s].join(", ")) + "</td></tr>"; }).join("") +
      "</tbody></table></div>", "peers");
  }

  function sources(d) {
    return card("Where the numbers come from", "",
      '<div class="tbl-wrap"><table class="tbl"><tbody>' + d.sources.map(function (s) { return '<tr><td><b>' + h(s.name) + '</b></td><td class="sub" style="text-align:left;white-space:normal">' + h(s.use) + "</td></tr>"; }).join("") + "</tbody></table></div>" +
      '<p class="note">Sectors and industries come from each company’s SEC industry code, with a short list of large companies placed by hand where the code misfiles them (Alphabet and Meta in Communication, Amazon and Tesla in Consumer Discretionary, Visa and Mastercard in Financials). <a class="link" href="/data-sources">All data sources</a></p>', "sources");
  }

  function log(d) {
    return card("Change log", "",
      '<div class="tbl-wrap"><table class="tbl"><thead><tr><th>Date</th><th>Version</th><th style="text-align:left">What changed</th></tr></thead><tbody>' +
      d.log.map(function (l) { return "<tr><td>" + F.date(l.date) + "</td><td>" + h(l.version) + '</td><td class="sub" style="text-align:left;white-space:normal">' + h(l.change) + "</td></tr>"; }).join("") +
      "</tbody></table></div>", "log");
  }

  function render(d) {
    var main = document.getElementById("main");
    main.innerHTML = hero(d) + evidence(d) + grades(d) + score(d) + peers(d) + timing(d) + sources(d) + log(d) +
      '<p class="note">Research, not investment advice. The LensScore describes a company against its peers from public filings; it does not know your situation and is not a recommendation to buy or sell.</p>';
  }

  function boot() {
    IL.shell(null);
    IL.api("/api/lens-method").then(function (res) {
      if (!res.ok || !res.data) {
        document.getElementById("main").innerHTML = '<section class="card"><div class="empty">The method details could not load. Please try again in a minute.</div></section>';
        return;
      }
      render(res.data);
      if (location.hash) { var el = document.getElementById(location.hash.slice(1)); if (el) el.scrollIntoView(); }
    });
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", boot); else boot();
})();
