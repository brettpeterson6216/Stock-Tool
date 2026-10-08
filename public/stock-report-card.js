/* ═══════════════════════════════════════════════════════════════════════════
   Report card on the Research stock page, and the Alert button.

   When a company loads, its LensScore report card sits right under the price:
   the 0–10 score, the five grades against sector peers, a one-line verdict,
   the next earnings date and the analyst mix. It links to the full card in
   LensToolkit. The Alert button next to Watch opens a small dialog for price,
   buy-zone and grade-change email alerts (same /api/alerts as LensToolkit).

   The card uses /api/lens-score/:ticker?card=1. The daily analysis limit
   counts each ticker once a day, so loading the card next to the quote does
   not use a second analysis.
   ═══════════════════════════════════════════════════════════════════════════ */
(function () {
  "use strict";

  const SHORT = { value: "Value", growth: "Growth", profitability: "Profit", health: "Health", momentum: "Momentum" };
  const TIMING = {
    "maximum-opportunity": "Sharp pullback", favorable: "Pulled back", "mildly-favorable": "Slight pullback",
    balanced: "Neutral", extended: "Stretched", "maximum-risk": "Very stretched",
  };
  const cache = new Map();
  let current = null;      // { ticker, data }
  let seq = 0;

  const $ = (sel, root = document) => root.querySelector(sel);
  function el(tag, cls, text) {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = text;
    return n;
  }
  const money = v => `$${Number(v).toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
  const state = () => window.IL_STATE || window.S || {};

  function host() {
    let box = $("#il-stock-card");
    if (box) return box;
    const anchor = $("#quote-source") || $("#metrics-grid");
    if (!anchor) return null;
    box = el("section", "il-sc");
    box.id = "il-stock-card";
    box.setAttribute("aria-label", "LensScore report card");
    box.hidden = true;
    anchor.insertAdjacentElement("afterend", box);
    return box;
  }

  function skeleton(box, ticker) {
    box.hidden = false;
    box.className = "il-sc is-loading";
    box.replaceChildren();
    const s = el("div", "il-sc-score");
    s.append(el("b", null, "–"), el("span", null, "/10"));
    const body = el("div", "il-sc-body");
    body.append(el("div", "il-sc-kicker", `Grading ${ticker} against its sector…`));
    const row = el("div", "il-sc-grades");
    Object.values(SHORT).forEach(name => { const c = el("span", "il-sc-g"); c.append(el("small", null, name), el("b", null, "·")); row.append(c); });
    body.append(row);
    box.append(s, body);
  }

  function render(box, ticker, d) {
    const g = d && d.grades;
    box.replaceChildren();
    box.className = "il-sc";
    if (!g || g.status !== "graded") {
      box.classList.add("is-empty");
      const p = el("p", "il-sc-empty");
      p.append(el("i", "ti ti-info-circle"));
      p.firstChild.setAttribute("aria-hidden", "true");
      p.append(document.createTextNode(` ${ticker} has no report card yet. Funds and ETFs are not graded, and very small or new companies may be missing the data we need.`));
      box.append(p);
      return;
    }
    const scoreBox = el("a", "il-sc-score");
    scoreBox.href = `/lens-score?ticker=${encodeURIComponent(ticker)}`;
    scoreBox.dataset.tone = g.tone || "neutral";
    scoreBox.setAttribute("aria-label", `LensScore ${g.score.toFixed(1)} out of 10, ${g.label}. Open the full report card.`);
    scoreBox.append(el("b", null, g.score.toFixed(1)), el("span", null, "/10"), el("em", null, g.label));

    const body = el("div", "il-sc-body");
    const top = el("div", "il-sc-top");
    top.append(el("span", "il-sc-kicker", "LensScore report card"));
    if (g.rank && g.rank.position) top.append(el("span", "il-sc-rank", `#${g.rank.position} of ${g.rank.of} in ${g.rank.sectorName || g.sectorName || "its sector"}`));
    body.append(top);

    const row = el("div", "il-sc-grades");
    row.setAttribute("role", "list");
    g.factors.forEach(f => {
      const c = el("span", "il-sc-g");
      c.setAttribute("role", "listitem");
      c.dataset.tone = f.tone || "unknown";
      c.title = Number.isFinite(f.percentile) ? `${f.label}: better than ${f.percentile}% of ${g.sectorName || "sector"} peers` : `${f.label}: not enough data`;
      c.append(el("small", null, SHORT[f.key] || f.label), el("b", null, f.grade || "–"));
      row.append(c);
    });
    body.append(row);
    if (g.verdict) body.append(el("p", "il-sc-verdict", g.verdict));
    if (g.caps && g.caps.length) {
      const cap = el("p", "il-sc-cap");
      cap.append(el("i", "ti ti-alert-triangle"));
      cap.firstChild.setAttribute("aria-hidden", "true");
      cap.append(document.createTextNode(` ${g.caps[0]}`));
      body.append(cap);
    }

    const meta = el("div", "il-sc-meta");
    const st = g.street || {};
    if (st.nextEarnings) {
      const n = st.nextEarnings;
      const date = new Date(`${n.date}T12:00:00Z`).toLocaleDateString("en-US", { month: "short", day: "numeric", timeZone: "UTC" });
      const when = n.days === 0 ? "today" : n.days === 1 ? "tomorrow" : `in ${n.days} days`;
      meta.append(chip("ti-calendar-event", `Earnings ${date}${n.when === "before the open" ? " (pre-market)" : n.when === "after the close" ? " (after close)" : ""} · ${when}`, n.days <= 7 ? "soon" : ""));
    }
    if (st.ratings) meta.append(chip("ti-users", `Analysts: ${st.ratings.label} (${st.ratings.total})`));
    if (st.earnings) {
      const of = st.earnings.of != null ? st.earnings.of : (st.earnings.quarters || []).length;
      if (of) meta.append(chip("ti-target-arrow", `Beat estimates ${st.earnings.beats} of last ${of}`));
    }
    if (d.timing && TIMING[d.timing.key]) meta.append(chip("ti-gauge", `Timing: ${TIMING[d.timing.key]} (${d.timing.score.toFixed(1)})`));
    if (meta.childNodes.length) body.append(meta);

    const actions = el("div", "il-sc-actions");
    const open = el("a", "il-sc-btn il-sc-btn-gold", "Full report card");
    open.href = `/lens-score?ticker=${encodeURIComponent(ticker)}`;
    const peers = el("a", "il-sc-btn", "Compare peers");
    peers.href = `/lens-score?ticker=${encodeURIComponent(ticker)}&view=peers`;
    const alert = el("button", "il-sc-btn");
    alert.type = "button";
    alert.append(el("i", "ti ti-bell"), document.createTextNode(" Alert"));
    alert.firstChild.setAttribute("aria-hidden", "true");
    alert.addEventListener("click", () => openAlert());
    actions.append(open, peers, alert);

    box.append(scoreBox, body, actions);
  }

  function chip(icon, text, cls) {
    const c = el("span", `il-sc-chip${cls ? ` ${cls}` : ""}`);
    const i = el("i", `ti ${icon}`);
    i.setAttribute("aria-hidden", "true");
    c.append(i, document.createTextNode(` ${text}`));
    return c;
  }

  async function load(ticker) {
    ticker = String(ticker || "").toUpperCase();
    const box = host();
    if (!box || !ticker) return;
    const mine = ++seq;
    const hit = cache.get(ticker);
    if (hit && Date.now() - hit.at < 5 * 60 * 1000) { current = { ticker, data: hit.data }; render(box, ticker, hit.data); return; }
    skeleton(box, ticker);
    try {
      const r = await fetch(`/api/lens-score/${encodeURIComponent(ticker)}?card=1`, { credentials: "same-origin" });
      if (mine !== seq) return;
      if (r.status === 429) { box.hidden = true; return; }
      const data = r.ok ? await r.json() : null;
      if (mine !== seq) return;
      if (data) cache.set(ticker, { at: Date.now(), data });
      current = { ticker, data };
      render(box, ticker, data);
    } catch (_) {
      if (mine === seq) box.hidden = true;
    }
  }

  /* ── Alert dialog ─────────────────────────────────────────────────────── */
  async function csrf() {
    const S = state();
    if (S.csrfToken) return S.csrfToken;
    try { const r = await fetch("/api/csrf", { credentials: "same-origin" }); const j = await r.json(); return j.token || ""; } catch (_) { return ""; }
  }

  function dialog() {
    let d = $("#il-alert-dialog");
    if (d) return d;
    d = el("dialog", "il-alert-dialog");
    d.id = "il-alert-dialog";
    d.setAttribute("aria-labelledby", "il-alert-title");
    d.innerHTML = `
      <form method="dialog" class="il-ad-head"><h2 id="il-alert-title">Email alert</h2><button class="il-ad-x" aria-label="Close"><i class="ti ti-x" aria-hidden="true"></i></button></form>
      <p class="il-ad-sub" id="il-ad-sub"></p>
      <div class="il-ad-quick" id="il-ad-quick"></div>
      <form class="il-ad-form" id="il-ad-form">
        <label class="il-ad-lab" for="il-ad-kind">Or pick a price</label>
        <div class="il-ad-row">
          <select id="il-ad-kind" aria-label="Alert when the price"><option value="below">Falls to</option><option value="above">Rises to</option></select>
          <input id="il-ad-level" type="number" inputmode="decimal" step="0.01" min="0" placeholder="Price" aria-label="Price level">
          <button type="submit" class="il-sc-btn il-sc-btn-gold">Save</button>
        </div>
      </form>
      <p class="il-ad-status" id="il-ad-status" role="status" aria-live="polite"></p>
      <ul class="il-ad-list" id="il-ad-list"></ul>
      <p class="il-ad-fine">Prices are checked every 10 minutes while US markets are open. Price alerts switch off after they fire; grade alerts keep watching. Manage every alert in <a href="/lens-score">LensToolkit</a>.</p>`;
    document.body.append(d);
    d.addEventListener("click", e => { if (e.target === d) d.close(); });
    $("#il-ad-form", d).addEventListener("submit", e => {
      e.preventDefault();
      const level = Number($("#il-ad-level", d).value);
      if (!(level > 0)) { status("Enter a price above zero."); return; }
      save($("#il-ad-kind", d).value, level);
    });
    return d;
  }
  const status = (t, html) => { const s = $("#il-ad-status"); if (!s) return; if (html) { s.replaceChildren(html); } else s.textContent = t; };

  let alertsCache = null;
  async function refreshList(ticker) {
    const ul = $("#il-ad-list");
    if (!ul) return;
    try {
      const r = await fetch("/api/alerts", { credentials: "same-origin" });
      if (!r.ok) return;
      alertsCache = await r.json();
    } catch (_) { return; }
    drawList(ticker);
  }
  function drawList(ticker) {
    const ul = $("#il-ad-list");
    if (!ul || !alertsCache) return;
    ul.replaceChildren();
    const active = (alertsCache.alerts || []).filter(a => a.active);
    active.filter(a => a.ticker === ticker).forEach(a => {
      const txt = a.kind === "score" ? "Any grade change" : a.kind === "buy_zone" ? `Buy zone at ${money(a.level)}` : `${a.kind === "above" ? "Rises to" : "Falls to"} ${money(a.level)}`;
      const li = el("li");
      li.append(el("span", null, txt));
      const del = el("button", "il-ad-del", "Remove");
      del.type = "button";
      del.setAttribute("aria-label", `Remove alert: ${txt}`);
      del.addEventListener("click", () => remove(a.id, ticker));
      li.append(del);
      ul.append(li);
    });
    const sub = $("#il-ad-sub");
    if (sub && alertsCache.limit) sub.dataset.count = `${active.length} of ${alertsCache.limit} alerts in use`;
    const used = $("#il-ad-used");
    if (used) used.textContent = alertsCache.limit ? `${active.length} of ${alertsCache.limit} alerts in use` : "";
  }

  async function save(kind, level) {
    const ticker = current && current.ticker || state().ticker;
    if (!ticker) return;
    status("Saving…");
    try {
      const r = await fetch("/api/alerts", {
        method: "POST", credentials: "same-origin",
        headers: { "Content-Type": "application/json", "X-CSRF-Token": await csrf() },
        body: JSON.stringify({ ticker, kind, level }),
      });
      const j = await r.json().catch(() => ({}));
      if (r.status === 401) { status("Log in to set alerts."); return; }
      if (!r.ok) {
        if (j.upgrade) {
          const span = el("span", null, `${j.error} `);
          const a = el("a", null, "See Pro");
          a.href = "#";
          a.addEventListener("click", e => { e.preventDefault(); dialog().close(); window.showUpgradeModal?.(false, "alerts_limit"); });
          span.append(a);
          status("", span);
          return;
        }
        throw new Error(j.error || "Could not save the alert.");
      }
      alertsCache = { ...(alertsCache || {}), alerts: j.alerts || (alertsCache && alertsCache.alerts) || [] };
      drawList(ticker);
      status(j.duplicate ? "You already have that alert." : "Saved. We will email you when it happens.");
      try { window.track?.("alert_created", { ticker, kind, source: "research" }); } catch (_) {}
    } catch (e) { status(e.message); }
  }
  async function remove(id, ticker) {
    try {
      const r = await fetch(`/api/alerts/${encodeURIComponent(id)}`, { method: "DELETE", credentials: "same-origin", headers: { "X-CSRF-Token": await csrf() } });
      const j = await r.json().catch(() => ({}));
      if (r.ok) { alertsCache = { ...(alertsCache || {}), alerts: j.alerts || [] }; drawList(ticker); status("Alert removed."); }
    } catch (_) { status("Could not remove the alert."); }
  }

  function openAlert() {
    const S = state();
    const ticker = (current && current.ticker) || S.ticker;
    if (!ticker) { window.toast?.("Load a company first", "red"); return; }
    if (S.authReady && !S.loggedIn) {
      if (typeof window.startGuestSignup === "function") { window.startGuestSignup("alert_button"); return; }
      location.href = `/signup?source=alert_button&next=${encodeURIComponent(location.pathname + location.search)}`;
      return;
    }
    const d = dialog();
    const price = Number(S.data && S.data.meta && S.data.meta.regularMarketPrice);
    $("#il-alert-title", d).textContent = `Alert me about ${ticker}`;
    const sub = $("#il-ad-sub", d);
    sub.replaceChildren(document.createTextNode(price > 0 ? `Last price ${money(price)}. ` : ""));
    const used = el("span", "il-ad-used");
    used.id = "il-ad-used";
    sub.append(used);
    const quick = $("#il-ad-quick", d);
    quick.replaceChildren();
    const data = current && current.ticker === ticker ? current.data : null;
    if (data && data.buyZone && data.buyZone.upper > 0) {
      const b = el("button", "il-ad-opt");
      b.type = "button";
      b.append(el("i", "ti ti-target"), el("strong", null, "Buy zone"), el("span", null, `when it falls to ${money(data.buyZone.upper)}`));
      b.firstChild.setAttribute("aria-hidden", "true");
      b.addEventListener("click", () => save("buy_zone", Math.round(data.buyZone.upper * 100) / 100));
      quick.append(b);
    }
    if (data && data.grades && data.grades.status === "graded") {
      const b = el("button", "il-ad-opt");
      b.type = "button";
      b.append(el("i", "ti ti-chart-dots-3"), el("strong", null, "Grade change"), el("span", null, "when the score moves 1 point or a grade changes"));
      b.firstChild.setAttribute("aria-hidden", "true");
      b.addEventListener("click", () => save("score", null));
      quick.append(b);
    }
    quick.hidden = !quick.childNodes.length;
    const input = $("#il-ad-level", d);
    input.value = price > 0 ? (price * 0.95).toFixed(2) : "";
    status("");
    $("#il-ad-list", d).replaceChildren();
    if (typeof d.showModal === "function") d.showModal(); else d.setAttribute("open", "");
    refreshList(ticker);
  }

  function addHeaderButton() {
    const actions = $("#app-section-hdr .ash-actions");
    if (!actions || $("#ash-alert-btn")) return;
    const b = el("button", "ash-btn");
    b.id = "ash-alert-btn";
    b.type = "button";
    b.title = "Email me about this stock";
    b.setAttribute("aria-label", "Set an email alert");
    b.append(el("i", "ti ti-bell"), document.createTextNode("Alert"));
    b.addEventListener("click", openAlert);
    const watch = actions.firstElementChild;
    if (watch) watch.insertAdjacentElement("afterend", b); else actions.append(b);
  }

  /* Grades for many tickers at once (watchlist, dashboard). One request per
     batch of unseen tickers; results are kept for ten minutes. */
  const gradeCache = new Map();
  let gradeSince = null;
  async function grades(tickers) {
    const list = [...new Set((tickers || []).map(t => String(t || "").toUpperCase()).filter(Boolean))];
    const fresh = t => { const h = gradeCache.get(t); return h && Date.now() - h.at < 10 * 60 * 1000; };
    const need = list.filter(t => !fresh(t));
    if (need.length) {
      try {
        const r = await fetch(`/api/lens-grades?tickers=${encodeURIComponent(need.slice(0, 60).join(","))}`, { credentials: "same-origin" });
        if (r.ok) {
          const j = await r.json();
          gradeSince = j.since || gradeSince;
          Object.entries(j.grades || {}).forEach(([t, g]) => gradeCache.set(t, { at: Date.now(), g }));
        }
      } catch (_) { /* grades are an extra; rows render without them */ }
    }
    const out = {};
    list.forEach(t => { out[t] = gradeCache.has(t) ? gradeCache.get(t).g : undefined; });
    return { since: gradeSince, grades: out };
  }
  const LETTERS = [["value", "V"], ["growth", "G"], ["profitability", "P"], ["health", "H"], ["momentum", "M"]];
  /* Small HTML pill: score, tone colour and the weekly change. */
  function pill(g, since) {
    if (g === undefined) return "";
    if (!g) return '<span class="il-ls is-none" title="Not graded: funds and very small companies are not covered">–</span>';
    const ch = Number.isFinite(g.change) && g.change !== 0 ? g.change : null;
    const sinceTxt = since ? ` since ${new Date(`${since}T12:00:00Z`).toLocaleDateString("en-US", { month: "short", day: "numeric", timeZone: "UTC" })}` : " this week";
    const letters = LETTERS.map(([k, l]) => `${l} ${g.grades && g.grades[k] || "–"}`).join(" · ");
    const title = `LensScore ${g.score.toFixed(1)} (${g.label})${ch != null ? `, ${ch > 0 ? "up" : "down"} ${Math.abs(ch).toFixed(1)}${sinceTxt}` : ""}. ${letters}`;
    return `<span class="il-ls" data-tone="${g.tone || "neutral"}" title="${title.replace(/"/g, "&quot;")}">${g.score.toFixed(1)}${ch != null ? `<em class="${ch > 0 ? "up" : "dn"}">${ch > 0 ? "▲" : "▼"}${Math.abs(ch).toFixed(1)}</em>` : ""}</span>`;
  }
  function letters(g) {
    if (!g) return "";
    return LETTERS.map(([k, l]) => `${l}\u00a0${g.grades && g.grades[k] || "–"}`).join(" ");
  }
  window.ILGrades = { get: grades, pill, letters };

  /* ── Compare: open prefilled with the company and its sector leaders ──── */
  async function prefillCompare() {
    const ids = ["cmp1", "cmp2", "cmp3", "cmp4"];
    const inputs = ids.map(id => document.getElementById(id));
    if (inputs.some(i => !i) || inputs.some(i => i.value.trim())) return;
    const S = state();
    const ticker = S.ticker;
    if (!ticker) return;
    let data = current && current.ticker === ticker ? current.data : (cache.get(ticker) || {}).data;
    if (!data) {
      try { const r = await fetch(`/api/lens-score/${encodeURIComponent(ticker)}?card=1`, { credentials: "same-origin" }); data = r.ok ? await r.json() : null; } catch (_) { data = null; }
    }
    if (inputs.some(i => i.value.trim())) return;   // the user started typing meanwhile
    const pro = S.userPlan === "pro" || S.userPlan === "trial";
    const peers = ((data && data.grades && data.grades.peers) || [])
      .filter(p => p && !p.self).map(p => (typeof p === "string" ? p : p.ticker)).filter(t => t && t !== ticker).slice(0, pro ? 3 : 1);
    inputs[0].value = ticker;
    peers.forEach((t, i) => { inputs[i + 1].value = t; });
    const sector = data && data.grades && (data.grades.sectorName || (data.grades.rank && data.grades.rank.sectorName));
    let note = $("#cmp-prefill-note");
    if (!note) {
      note = el("p", "cmp-prefill-note");
      note.id = "cmp-prefill-note";
      const row = $(".cmp-inputs");
      if (row) row.insertAdjacentElement("afterend", note);
    }
    note.textContent = peers.length
      ? `Filled in with ${ticker} and ${peers.length === 1 ? "the top-rated company" : `the ${peers.length} top-rated companies`} in ${sector || "its sector"}. Change any ticker, then press Compare.`
      : `Filled in with ${ticker}. Add a competitor, then press Compare.`;
  }

  /* LensScore and the five grades as the first rows of the compare table. */
  async function decorateCompare() {
    const table = document.getElementById("cmp-table");
    if (!table || table.querySelector(".cmp-ls-row")) return;
    const tickers = [...table.querySelectorAll("thead th.cmp-hdr")].map(th => th.textContent.trim().toUpperCase());
    if (!tickers.length) return;
    const { since, grades: g } = await grades(tickers);
    const body = table.querySelector("tbody");
    if (!body || table.querySelector(".cmp-ls-row")) return;
    const rows = [["LensScore", t => g[t] ? pill(g[t], since) : "–", t => g[t] ? g[t].score : null]];
    LETTERS.forEach(([k]) => rows.push([`${SHORT[k] === "Profit" ? "Profitability" : SHORT[k]} grade`, t => g[t] && g[t].grades ? (g[t].grades[k] || "–") : "–", null]));
    const frag = document.createDocumentFragment();
    rows.forEach(([label, cell, raw], i) => {
      const tr = el("tr", `cmp-ls-row${i === rows.length - 1 ? " cmp-ls-last" : ""}`);
      tr.append(el("td", null, label));
      tickers.forEach(t => {
        const td = el("td");
        td.innerHTML = cell(t);
        if (raw && raw(t) != null) td.dataset.raw = String(raw(t));
        tr.append(td);
      });
      frag.append(tr);
    });
    body.prepend(frag);
  }

  function hookApp() {
    if (typeof window.openSection === "function" && !window.openSection.__ilPrefill) {
      const orig = window.openSection;
      const wrapped = function (id) { const out = orig.apply(this, arguments); if (id === "compare") prefillCompare(); return out; };
      wrapped.__ilPrefill = true;
      window.openSection = wrapped;
    }
    if (typeof window.buildCompareTable === "function" && !window.buildCompareTable.__ilLs) {
      const orig = window.buildCompareTable;
      const wrapped = function () { const out = orig.apply(this, arguments); decorateCompare(); return out; };
      wrapped.__ilLs = true;
      window.buildCompareTable = wrapped;
    }
  }

  window.ILStockCard = { load, openAlert };
  const init = () => { addHeaderButton(); hookApp(); };
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
