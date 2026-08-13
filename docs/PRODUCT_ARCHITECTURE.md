# Implied Lens product and architecture contract

Last reviewed: 2026-08-12

## Product promise

Implied Lens helps an investor understand what expectations are already priced into a stock, evaluate whether the underlying business can deliver, test realistic scenarios, and estimate what those scenarios imply for valuation.

Every primary feature must help answer at least one of these questions:

1. What is happening with this company?
2. What expectations are priced into the stock?
3. What must happen fundamentally for the stock to outperform or underperform?
4. What could the company reasonably be worth under different scenarios?

The canonical journey is:

`Search company -> Understand business -> Analyze fundamentals -> Read market expectations -> Build scenarios -> Estimate valuation -> Save, compare, and monitor`

Market dashboards, education, and planning utilities are supporting surfaces. They must not displace the company-research journey in primary navigation.

## Information hierarchy

| Product area | User question | Current implementation owner | Direction |
| --- | --- | --- | --- |
| Research | What is happening? | `index.html`, `public/app-legacy.js`, `public/research-system.js` | Become one company overview with progressive disclosure. |
| LensScore / Expectations | What is priced in, and how attractive is the setup? | `labs/lens-score/*`, `routes/lens-score.js`, `lib/lens-score-engine.js` | Keep tactical and long-term lenses independent; add reverse-valuation outputs to the same evidence trail. |
| Scenarios | What must happen? | `public/projection-lab.js`, `public/model-math.js` | Keep Bear/Base/Bull, label every value by origin, and add sector-aware inputs incrementally. |
| Valuation | What could it be worth? | `public/valuation-lab.js`, `public/model-math.js` | Preserve visible assumptions, support appropriate methods by company type, and never hide invalid models. |
| Compare | Is the thesis stronger than alternatives? | comparison section in `public/app-legacy.js` | Compare growth, margins, cash flow, balance-sheet quality, valuation, and expectations—not decorative scores. |
| Saved / Monitor | What changed? | `public/workspace-system.js`, `routes/workspace.js`, `routes/auth.js` | Persist companies, models, assumptions, notes, and review triggers; later calculate material changes. |

## Runtime architecture

- Delivery: Node 20+, Express 4, static multi-surface web application.
- Persistence: Turso/libSQL through `lib/db.js`; Express sessions use a Turso-backed store.
- Authentication: username/email plus bcrypt password hashes, verification tokens, password-reset tokens, CSRF protection on mutations, HttpOnly/SameSite cookies.
- Billing: Stripe Checkout, signed webhooks with idempotent event storage, customer portal, durable subscription state.
- Entitlements: `lib/plan.js`; daily guest/free usage is stored in `analysis_usage`; Pro gating is enforced server-side.
- Market research: API routes aggregate Yahoo Finance chart endpoints, Finnhub, SEC EDGAR/XBRL, Stooq fallback, and FINRA-related datasets.
- Caching: bounded in-process response caches with route-specific TTLs; LensScore also coalesces concurrent requests. This improves a single instance but is not shared across horizontally scaled instances.
- Analytics: first-party events stored in `analytics_events`; no third-party product analytics dependency.
- Deployment: GitHub CI plus the existing repository-driven hosting path. `/healthz` is liveness; `/readyz` is the public-launch configuration gate.

## Frontend ownership

- `index.html`: markup and section mounts only. It must not regain large executable script blocks.
- `public/theme-bootstrap.js`: pre-render theme and browser chrome.
- `public/app-navigation.js`: global navigation, authentication shell, CSRF bootstrap, account UI.
- `public/app-legacy.js`: existing application controller. This is an explicit migration boundary, not the destination architecture.
- `public/model-math.js`: pure financial math. It must remain DOM-free and independently tested.
- `public/projection-lab.js`: projection UI and model state.
- `public/valuation-lab.js`: operating-model valuation UI.
- `public/research-system.js`: research extensions such as calls and educational utilities.
- `public/workspace-system.js`: thesis, watchlist, portfolio, reporting, and member workspace.
- `public/product-system.js`: cross-cutting product enhancements. New domain logic should not be added here.

New work should move one bounded responsibility at a time out of `app-legacy.js` into an explicitly named module. Avoid a framework rewrite while behavior is still being mapped.

## Data and assumption contract

Every financial value shown to a user must carry one of these origins:

- `Reported`: company filing or primary-source reported value.
- `Market data`: current or historical market-provider observation.
- `Consensus`: analyst estimate with provider and estimate period.
- `Implied Lens default`: generated starting assumption, including the rule used.
- `User assumption`: explicitly changed or entered by the user.
- `Calculated`: output derived from named inputs and a visible formula.

Required metadata is provider, evidence date/period, retrieval time, unit/currency, and freshness state. Missing or stale evidence must produce `Not Rated` or an explicit unavailable state; it must never be replaced with synthetic facts.

## Financial-logic change policy

Do not modify a production formula as a cleanup task. A formula change requires:

1. a written statement of the old and new formulas;
2. fixtures for representative profitable, unprofitable, financial, cyclical, and high-growth companies;
3. boundary and invalid-input tests;
4. historical or cross-sectional calibration evidence where the output is a score;
5. a methodology/version change visible to users;
6. release notes and migration handling for saved models.

## Scaling boundaries

Before horizontal scaling, move provider caches and request coalescing to a shared cache, add background refresh jobs, retain provider observations with `as_of` dates, and version saved model schemas. Before alerts, introduce an append-only observation/change table so notifications are based on evidence changes rather than page loads.

