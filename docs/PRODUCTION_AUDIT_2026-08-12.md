# Implied Lens production audit

Audit date: 2026-08-12  
Scope: repository architecture, product hierarchy, financial logic, data, authentication, billing, persistence, security, performance, accessibility, responsive UI, SEO, and launch operations.

## Executive finding

Implied Lens has substantially more real infrastructure than a prototype: server-enforced entitlements, durable accounts and saves, Stripe webhook reconciliation, CSRF protection, provider provenance, tested valuation engines, responsive styles, and a broad automated suite. Its largest remaining risk is not missing feature volume. It is cohesion and ownership: a 6,900-line page, a legacy controller with many responsibilities, overlapping browser state, and product language that previously presented ten separate tools instead of one research decision.

The correct strategy is incremental extraction around a stable product contract. A full rewrite would create financial-regression and billing risk.

## Changes completed in this pass

- Extracted the two large executable blocks from `index.html` into `public/app-navigation.js` and `public/app-legacy.js` without changing calculation behavior.
- Extracted theme initialization into `public/theme-bootstrap.js`.
- Removed inline executable scripts from the home application and removed `'unsafe-inline'` from `script-src`. Legacy inline event attributes remain isolated under `script-src-attr` for the next migration.
- Reframed the landing page from “ten tools” into four connected product areas: understand, expectations, scenarios, and value/save/monitor.
- Simplified the global product navigation to Home, Research, LensScore, Scenarios, Compare, Saved, and About; made it consistent on LensScore, About, legal, data-source, research-process, blog, and calculator pages.
- Added `/readyz`, which reports launch-critical capabilities without revealing configuration values.
- Removed ten tracked scratch/shim/preview artifacts that were not referenced by runtime code or tests.
- Updated the vulnerable transitive `undici` dependency; `npm audit` reports zero known vulnerabilities after the update.

## Architecture inventory

### Frontend

- Static HTML/CSS/JavaScript, with one main application shell and separate LensScore, account, legal, and editorial pages.
- Main state begins in `public/app-legacy.js` and is shared as `window.IL_STATE` / `window.S`.
- Projection, valuation, research, product, and workspace modules extend the main shell through public window APIs.
- Local/session storage supports guest saves, theme, transient acquisition context, labs, notes, and education progress. Signed-in saves and workspace entities sync through server APIs.
- Chart.js, local vendor bundles, and custom chart interactions power technical analysis.

### Backend

- Express entrypoint mounts authentication, billing, market-data, financial-data, LensScore, workspace, and stock-landing route modules.
- Turso/libSQL tables cover users, sessions, saves, usage, Stripe events, verification/reset tokens, analytics, theses, positions, watchlists, portfolio profiles, and lifecycle-email idempotency.
- Mutating authenticated routes use CSRF validation. Authentication and selected public endpoints are rate limited.
- Stripe webhooks are signature verified and idempotently recorded.

### Data sources

- SEC EDGAR company tickers, company facts/XBRL, submissions, and filing links.
- Yahoo Finance chart/screener endpoints with query-host and CSV fallbacks.
- Finnhub for profiles, estimates, metrics, earnings, analyst information, ownership, calls, and fallback quote history.
- Stooq as a historical-price fallback.
- Provider-health observations and visible provenance/freshness structures already exist, but not every legacy panel consumes them uniformly.

## Financial formula inventory

The production math is centralized in `public/model-math.js`; the LensScore engine is separately versioned under `labs/lens-score/lens-score-engine.js` and server wrappers.

- Scenario price projection: current EPS inferred from price/current P/E, compounded earnings, share dilution adjustment, exit P/E, and accumulated dividends.
- EPS DCF: five years at stage-one growth, five at stage-two growth, then a Gordon-growth terminal value discounted to present.
- Operating model: revenue growth -> gross profit -> EBIT -> taxes/net income; diluted shares compound separately; FCFF is calculated from NOPAT + D&A - capex - working-capital investment - SBC.
- FCFF DCF: discounted explicit FCFF plus Gordon terminal value (or exit EV/EBITDA fallback), less net debt, divided by current diluted shares.
- Exit P/E: terminal EPS times exit P/E, discounted by the configured rate.
- Exit EV/EBITDA: terminal EBITDA times multiple, less net debt, divided by terminal diluted shares, discounted.
- Scenario valuation: Bear/Base/Bull fair values are probability weighted.
- Reverse valuation: bisection solves revenue growth, year-five operating margin, exit P/E, or exit EV/EBITDA required to match the current price.
- Sensitivity: a two-driver grid re-runs the same valuation engine at each input pair.

No formula was changed in this pass.

## Priority findings

### P0 — launch gates

1. Production configuration was not represented by one auditable gate. `/readyz` now exposes database, market data, session security, billing, transactional email, and public URL readiness without secrets. Deployment must not be declared launch-ready until it returns HTTP 200.
2. A high-severity transitive `undici` advisory existed through the test DOM dependency. Updated; audit is clean.
3. Public launch still depends on real provider reliability and entitlement testing in the deployed environment. Local success cannot certify third-party keys, Stripe products/webhooks, Resend domain verification, or Turso latency.

### P1 — financial correctness and explainability

1. The operating-model FCFF treatment of SBC needs a finance review. Operating margin may already include SBC while the model also subtracts `sbcPct`; the current comment and implementation do not fully prove that double counting is impossible. Preserve behavior until fixtures and methodology are agreed.
2. Net debt is held constant through terminal calculations. That is a simplifying assumption and must be labeled, or replaced by an explicit cash/debt schedule in a versioned model.
3. Exit P/E is discounted using the configured WACC. Equity valuation conventionally uses cost of equity; the current choice must be labeled and validated before changing.
4. Bear/Bull defaults use fixed multipliers and margin deltas. They are useful starting points but are not sector aware and must be labeled `Implied Lens default`, never consensus.
5. `annualizedReturn` is a one-year convergence proxy while `expectedAnnualReturn` uses the scenario horizon. The first label should be clarified before it is surfaced broadly.
6. Sector-aware method selection is not implemented. Banks, insurers, REITs, pre-profit firms, cyclicals, and mature cash generators need explicit templates and validation rules.

### P1 — product and UX

1. Research still exposes too many peer-level sidebar entries. The next UI migration should group them under Overview, Fundamentals, Expectations, Scenarios, Valuation, and Evidence, with advanced panels progressively disclosed.
2. LensScore and reverse-implied expectations are adjacent concepts but not yet one evidence trail. LensScore should link each component to the underlying chart/fundamental evidence and to the priced-in requirement it affects.
3. Origin labels are not yet uniform across every table and card. Introduce one source/origin component and require it in new financial UI.
4. Guest local saves and authenticated cloud saves intentionally coexist, but conflict/merge behavior should be surfaced to the user when the same model changes on two devices.

### P1 — architecture and performance

1. `public/app-legacy.js` remains approximately 269 KB and owns unrelated domains. Extraction made ownership possible; it did not finish the migration. Split by company overview, charts, financials, compare/screener, account/billing UI, and saves, one tested slice at a time.
2. Styles remain spread across several large, layered files, especially `legacy-app.css`. Establish a token/base/layout/component order, then remove superseded selectors with visual regression coverage.
3. Provider caches are per process. Multi-instance deployment will duplicate requests and produce inconsistent warm/cold latency. Move cache and request locks to shared infrastructure before horizontal scaling.
4. Financials and research routes sometimes call overlapping provider endpoints independently. Add a shared provider-client layer with normalized timeouts, retry policy, cache keys, provenance, and telemetry.

### P2 — security, accessibility, SEO, operations

1. Hundreds of inline event attributes still require `script-src-attr 'unsafe-inline'`. Migrate by surface to delegated listeners, then set `script-src-attr 'none'`.
2. Authentication, billing, and CSRF controls are strong for the current architecture, but a production security review should add dependency automation, secret scanning, SAST, and abuse tests for provider-cost endpoints.
3. Keyboard and screen-reader semantics are inconsistent in legacy clickable `div` elements. New UI must use native buttons/links; legacy migrations need automated axe-style checks and manual keyboard passes.
4. Stock landing pages, sitemap, canonical tags, metadata, and legal pages exist. Structured data and page descriptions should be updated whenever the product hierarchy changes, and 404s should use a dedicated page rather than the application shell.
5. Logging is mostly console/provider snapshots and database analytics. Add structured request IDs, error classes, latency/provider dimensions, retention policy, and alerting before paid acquisition.

## Release gates

A public paid launch is allowed only when all of the following are true:

- CI syntax, unit, integration, DOM contract, calibration, and security checks pass.
- `npm audit --audit-level=moderate` reports no unresolved production vulnerability.
- `/healthz` and `/readyz` return 200 on the exact deployed commit.
- Stripe monthly/annual Checkout, webhook reconciliation, portal, cancel/resubscribe, and failed-payment paths are tested in the deployed environment.
- Signup, verification, reset, login, logout, save, edit, delete, and cross-device reload are tested with a real mailbox and database.
- At least one live profitable company, one unprofitable company, one financial company, one ETF, and one invalid ticker are checked for data provenance and graceful unavailable states.
- Home, Research, LensScore, Scenarios, Compare, Saved, About, signup, and login pass desktop/mobile, light/dark, keyboard, loading, empty, error, and slow-network checks.
- Every released score/model shows methodology version, evidence date, retrieval time, confidence/coverage, and an assumptions trail.

## Next implementation order

1. Add a shared `data-origin` UI component and apply it to Research, LensScore, Scenarios, and Valuation.
2. Extract the company overview and saves controller from `app-legacy.js` with parity tests.
3. Introduce versioned sector templates and validation rules without changing the existing default model.
4. Add observation history and shared cache infrastructure for monitoring and scale.
5. Remove inline event attributes and close the remaining CSP exception.
6. Run deployed billing/email/provider E2E and make `/readyz` a deployment gate.

