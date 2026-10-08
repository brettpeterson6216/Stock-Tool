/* ═══════════════════════════════════════════════════════════════════════════
   CSV export (Pro). Turns a rendered table into a CSV download.

   Cells can carry the exact number in data-raw (financial statements do), so
   the file has 391035000000 rather than "$391.04B". Everything else is the
   cell's visible text. Buttons are added with ILExport.button(); on pages
   without the app state (LensToolkit) the plan comes from /api/auth/me.
   Free accounts get the upgrade prompt instead of the file.
   ═══════════════════════════════════════════════════════════════════════════ */
(function () {
  "use strict";

  let planPromise = null;
  function plan() {
    const S = window.IL_STATE;
    if (S && S.authReady) return Promise.resolve(S.userPlan || "free");
    if (!planPromise) {
      planPromise = fetch("/api/auth/me", { credentials: "same-origin" })
        .then(r => r.json()).then(j => (j && j.user && (j.user.effectivePlan || j.user.plan)) || "guest")
        .catch(() => "guest");
    }
    return planPromise;
  }
  const isPro = p => p === "pro" || p === "trial";

  function cellText(cell) {
    if (cell.dataset && cell.dataset.raw != null && cell.dataset.raw !== "") return cell.dataset.raw;
    // The screener's five grade chips become five columns.
    if (cell.classList.contains("scr-grades-th")) return ["Value", "Growth", "Profitability", "Health", "Momentum"];
    const chips = cell.querySelectorAll(".scr-g");
    if (chips.length) return [...chips].map(c => c.textContent.trim());
    if (cell.classList.contains("scr-grades-cell")) return ["", "", "", "", ""];
    const clone = cell.cloneNode(true);
    clone.querySelectorAll(".sr-only, [aria-hidden='true'], i.ti, .il-csv-btn").forEach(n => n.remove());
    return (clone.textContent || "").replace(/\s+/g, " ").trim();
  }
  function quote(v) {
    let s = String(v == null ? "" : v);
    if (/^(—|–|-{1,2})$/.test(s)) s = "";          // "no value" markers become empty cells
    // A cell starting with = or @ (or + / - not followed by a number) would
    // run as a formula in Excel; prefix it so it stays text.
    if (/^[=@]/.test(s) || /^[+-](?![\d.$])/.test(s)) s = `'${s}`;
    return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  }
  function rowsFromTable(table) {
    return [...table.querySelectorAll("tr")]
      .filter(tr => tr.style.display !== "none" && !tr.querySelector("td[colspan]"))
      .map(tr => [...tr.children].flatMap(c => [].concat(cellText(c))))
      .filter(r => r.some(c => c !== ""));
  }
  function download(rows, filename) {
    const csv = "﻿" + rows.map(r => r.map(quote).join(",")).join("\r\n");
    const url = URL.createObjectURL(new Blob([csv], { type: "text/csv;charset=utf-8" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = filename.endsWith(".csv") ? filename : `${filename}.csv`;
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 2000);
  }
  function upgrade(source) {
    if (typeof window.showUpgradeModal === "function") { window.showUpgradeModal(false, source); return; }
    location.href = `/pricing?source=${encodeURIComponent(source)}`;
  }
  async function exportTable(getTable, filename, source) {
    const p = await plan();
    if (!isPro(p)) { upgrade(source || "csv_export"); return; }
    const table = typeof getTable === "function" ? getTable() : getTable;
    if (!table) { window.toast?.("Nothing to export yet", "red"); return; }
    const rows = rowsFromTable(table);
    if (rows.length < 2) { window.toast?.("Nothing to export yet", "red"); return; }
    const stamp = new Date().toISOString().slice(0, 10);
    download(rows, `${typeof filename === "function" ? filename() : filename}-${stamp}`);
    try { window.track?.("csv_exported", { source }); } catch (_) {}
  }
  /* A small "CSV" button. host: element to append to. */
  function button(host, getTable, filename, source, label) {
    if (!host || host.querySelector(".il-csv-btn")) return null;
    const b = document.createElement("button");
    b.type = "button";
    b.className = "il-csv-btn";
    b.title = "Download as CSV (Pro)";
    b.innerHTML = `<i class="ti ti-file-spreadsheet" aria-hidden="true"></i><span>${label || "Export CSV"}</span>`;
    b.addEventListener("click", () => exportTable(getTable, filename, source));
    host.append(b);
    return b;
  }

  /* Research app (index.html): screener, financial statements, compare. */
  function wireApp() {
    const S = () => window.IL_STATE || {};
    const scr = document.querySelector(".screener-summary");
    if (scr && document.getElementById("scr-table")) button(scr, () => document.getElementById("scr-table"), "impliedlens-screener", "csv_screener");
    const finBar = document.querySelector(".fin-tab-btn") && document.querySelector(".fin-tab-btn").parentElement;
    if (finBar) {
      const visible = () => [...document.querySelectorAll(".fin-subtab")].find(d => d.style.display !== "none");
      const b = button(finBar, () => visible() && visible().querySelector("table"), () => `${S().ticker || "company"}-${(visible() && visible().id || "fin-statement").replace(/^fin-/, "")}`, "csv_financials");
      if (b) b.classList.add("il-csv-right");
    }
    const cmpSave = document.querySelector("#cmp-results .chart-save-btn");
    if (cmpSave) button(cmpSave.parentElement, () => document.getElementById("cmp-table"), () => `compare-${["cmp1", "cmp2", "cmp3", "cmp4"].map(id => (document.getElementById(id) || {}).value).filter(Boolean).join("-").toUpperCase()}`, "csv_compare");
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", wireApp);
  else wireApp();

  window.ILExport = { button, exportTable, download, rowsFromTable, _quote: quote };
})();
