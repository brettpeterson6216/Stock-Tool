# Implied Lens — Full Product, Code, UX, and Market Audit

**Audit date:** July 22, 2026  
**Production site:** https://impliedlens.com  
**Repository audited:** `C:\Users\clash\Downloads\Stock Tool`  
**Production commit observed:** `061016689ae92fcec836d6dd460394fbb271a8c9`  
**Audience:** product owner, designer, engineer, security reviewer, or successor AI agent  
**Decision:** **Do not treat the present build as premium-ready. Stabilize the product contract and frontend foundation before adding more features.**

---

## 1. Executive verdict

Implied Lens has the beginnings of a differentiated investing product: a calm visual direction, useful valuation and projection models, source-aware financial data, thesis and review concepts, and unusually thoughtful language around uncertainty. The strongest potential position is not “another broad market terminal.” It is a **source-linked decision journal for self-directed fundamental investors**: evidence, assumptions, valuation, thesis, and scheduled review in one traceable workflow.

The deployed product does not yet deliver that promise consistently. It feels like several generations of the application layered together:

- a very large legacy single-page application;
- a newer marketing site and market dashboard;
- external “premium,” product, workspace, projection, and valuation systems;
- multiple unfinished or disconnected navigation models;
- a growing pile of CSS overrides and inline behavior.

The result is feature breadth without dependable continuity. Production presents dead workspace destinations, loses some deep-link state, loads extensive hidden data work on the landing page, breaks its navigation around tablet widths, and uses marketing language that is more confident than the underlying feeds or algorithms justify. The current automated suite also fails, while most tests are source-pattern contracts rather than real-browser behavioral tests.

### Overall assessment

| Area | Status | Summary |
|---|---|---|
| Core math and model logic | Promising | Substantive modules and good unit coverage; assumptions still need clearer product presentation. |
| Product reliability | Critical | Important source modules are not shipped; dead journeys and deep-link failures are live. |
| Information architecture | Weak | Market, research, projections, planner, learn, saved, workspace, and reports overlap without one coherent mental model. |
| Visual design | Inconsistent | Some strong cards and palette choices, but landing, tool, auth, and legal surfaces feel like different products. |
| Responsive behavior | Critical | Phone is constrained but usable; 768 px navigation visibly collides; mobile toolbars require hidden horizontal scrolling. |
| Accessibility | Needs work | Landing scores well in automated testing, but the application relies on nonsemantic clickable `div`s, unlabeled controls, and dense hidden DOM. |
| Performance | Critical | Mobile Lighthouse performance 59; LCP 13.8 s; oversized hero and hidden dashboard requests dominate. |
| Security foundation | Fair | Good baseline headers, CSRF, password hashing, validation, and Stripe signature handling; CSP and unsafe rendering patterns need structural remediation. |
| Data trust | Needs work | Data-source page is candid, but “live” claims, labeling errors, stale samples, and a deterministic feature branded as AI undermine trust. |
| Operations | Immature | No durable job worker, versioned migrations, end-to-end observability, documented recovery plan, or meaningful browser-level release gate. |

### The three highest-leverage moves

1. **Make the shipped product match the repository.** Integrate or deliberately remove the unreferenced product/workspace/dashboard systems; repair deep links and every navigation destination.
2. **Replace the legacy page shell with route-level modules and a small design system.** Stop extending the 6,661-line HTML file and override-heavy stylesheets.
3. **Make trust a product feature.** Use accurate feed labels, source/as-of metadata, explicit modeled versus reported values, visible assumption changes, and legally accurate product language.

---

## 2. Scope, method, and limitations

### What was audited

- All first-party application code, server routes, database initialization, configuration, tests, workflows, public marketing/legal pages, and tracked artifacts.
- Live guest journeys on the production website: landing, Market, Research, Projections, Planner, Learn, Saved, login, signup, stock landing pages, and direct URLs.
- Responsive layouts at **320×568, 375×812, 390×844, 768×1024, 1024×768, 1366×768, 1440×900, and 1920×1080**.
- Browser console behavior, live DOM structure, network behavior, response headers, endpoint health, copy, pricing, data labeling, and accessibility semantics.
- Automated code checks, tests, package audit/outdated status, and Lighthouse mobile performance/accessibility/best-practice/SEO results.
- Competitor capabilities and patterns from current official product/help pages.

### What was not changed or destructively tested

- No production account was created.
- No email, password-reset, paid trial, Stripe charge, cancellation, or authenticated data mutation was executed.
- No penetration testing, load testing, provider entitlement review, legal opinion, financial-model certification, or assistive-technology session with a human user was performed.
- Authenticated and billing behavior was reviewed through code and automated tests only.
- The existing uncommitted `index.html` work was preserved and is not part of this report.

### Commands and checks run

- `npm run check` — passed.
- `npm test` — **132 tests: 128 passed, 3 failed, 1 skipped**.
- `npm audit` — **1 low-severity dependency finding**.
- `npm outdated` — several major-version gaps; see §12.
- Live browser inspection and responsive screenshots.
- Mobile Lighthouse against the production homepage.
- Live HTTP/header/health/sitemap/robots/public-page checks.
- Repository structure, script-reference, code-size, event-handler, style, and test-coverage inventory.

---

## 3. Release blockers — fix before calling the product premium

### P0-01 — Major product systems exist but are not loaded

**Evidence**

`public/product-system.js`, `public/workspace-system.js`, and `public/dashboard-system.js` contain substantial production-oriented behavior, but `index.html` does not reference them. The page does reference model, projection, valuation, research, and tool-launch scripts. Tests and copy describe capabilities implemented in the omitted files.

**Live impact**

- Saved → Thesis clears the main content and leaves the user in a blank state.
- Workspace, portfolio, watchlist, trust/provenance, onboarding, decision-spine, and URL-state behavior are present in source but absent or incomplete in production.
- A direct URL such as `/?view=tool&section=projection&symbol=AAPL` loads AAPL and rewrites itself to `section=analyze`, losing the requested destination.
- Product copy promises an integrated workspace that users cannot reliably reach.

**Required decision**

Either:

1. integrate these modules deliberately, test their initialization order, and make them the canonical implementation; or
2. remove them, remove every related promise, and rebuild the journeys in the chosen architecture.

Do not merely add three script tags and ship. Their overlapping navigation/state assumptions need integration tests.

**Acceptance criteria**

- Every visible navigation item resolves to meaningful content for both guest and authenticated states.
- Direct URLs retain `view`, `section`, `symbol`, and workspace tab after initial data load and refresh.
- Back/forward navigation restores the exact view without duplicate data loading.
- No source module that defines a marketed feature is silently absent from the production bundle.

### P0-02 — The release test suite is red

Current failures:

1. mobile chart-header contract no longer matches the locally edited indicator logic;
2. expected primary-navigation copy is missing;
3. homepage contract expects `workspace-system.js` but the production document does not include it.

One Projection Lab DOM suite is skipped because `jsdom` is not installed.

**Impact:** the repository cannot distinguish intentional product changes from regressions, and the one failure that detects missing workspace integration describes a real production defect.

**Acceptance criteria**

- All tests pass from a clean install.
- No product-critical suite is conditionally skipped due to an undeclared optional dependency.
- Replace brittle string/regex contracts with DOM, API integration, and Playwright behavior checks where possible.

### P0-03 — Tablet navigation is visibly broken

At 768×1024 the desktop navigation is enabled, but the available width cannot contain all destinations plus theme, login, and trial controls. Items overlap and crowd each other. Phone bottom navigation is disabled at this width, leaving no viable responsive alternative.

**Acceptance criteria**

- Header has defined compact/tablet/desktop states rather than a phone/desktop binary.
- No overlap at 600–1,024 px, 200% zoom, or increased system text size.
- Every destination is keyboard accessible and has a visible focus state.

### P0-04 — Core guest workspace destinations fail silently

The sidebar uses clickable `div.sb-item` elements. Selecting Thesis during live testing removed the active content without an error or recovery message. A premium product must never respond to a primary navigation action with a blank canvas.

**Acceptance criteria**

- Route-level error boundary and explicit loading/empty/error states exist.
- Missing module or failed request produces an actionable message, not blank content.
- Navigation smoke test clicks every primary and secondary destination at all supported widths.

---

## 4. Product experience audit

### 4.1 Landing page

**What works**

- The product proposition—making assumptions and evidence visible—is differentiated and understandable.
- Pricing is simple, and the calm gold/neutral direction can support a premium research brand.
- The research workflow has a logical sequence and avoids overt trading hype.

**What does not work**

1. The visual hero is a 1.73 MB raster image containing important text. On phone, its internal text is too small to read. On desktop, it dominates the first viewport and pushes the real interactive headline below the fold.
2. The actual `h1` is visually clipped to approximately 1×1 px while the visible message is embedded in the image. This makes the page feel like a mockup placed inside a website rather than a finished product.
3. At 1366×768 the real hero heading begins around y=990; at 1920×1080 it begins around y=1127. The first viewport is mostly a static illustration.
4. “Nine research tools. One ticker away” creates breadth, but not a guided starting point. Premium tools reduce initial choice anxiety with a strong default journey.
5. “No account needed to look” clashes with cards that open gated sample states rather than a consistent live guest preview.
6. Landing initializes market data for hidden content, making the marketing page slower and more failure-prone than it needs to be.

**Recommendation: rebuild, not patch.** Use a native HTML/CSS hero with one sentence, ticker search, a real interactive evidence/model preview, and a concise trust strip. Move the full process diagram lower. Use responsive AVIF/WebP only for nonessential illustrations.

### 4.2 Market

This is the strongest-looking current surface: the card system, index panels, movers, analyst block, and watchlist create useful density. It should inform the future application shell.

Problems:

- “Your Watchlist” shows a hard-coded curated set for guests, which implies personalization that does not exist. Label it “Popular watchlist” or show a true sign-in empty state.
- Advancing, Declining, New Highs, New Lows, and Volume remain dashes because no breadth feed populates them. Large empty premium-looking modules lower perceived reliability.
- “Nasdaq 100” is backed by `^IXIC`, the Nasdaq Composite, which is a materially incorrect label.
- The timestamp appends “ET” to the browser-local `Date` rather than formatting explicitly in `America/New_York`.
- A five-company recommendation aggregate is presented as a broad bullish percentage. It should not be mistaken for market breadth or a representative sentiment indicator.
- Movers are escaped correctly in the inspected renderer; continue this pattern consistently across all provider-backed rendering.

### 4.3 Research and ticker workflow

The research view contains substantial capability, but the experience is dense, pale, and internally fragmented.

- The left rail, top tool strip, timeframe strip, mobile section tabs, nested cards, and bottom navigation compete for orientation.
- At 390 px, three separate horizontal-scrolling controls have no strong affordance: chart toolbar (972 px content in 352 px), timeframe strip (590 px), and mobile tabs (781 px).
- No meaningful heading structure was exposed in the live tool snapshot.
- Several controls lack programmatic labels, including valuation, comparison, screener, and account-related inputs in the combined DOM.
- Bottom navigation overlaps lower content.
- Risk-label text is concatenated in the accessibility tree: examples include “Annual Returnest.”, “Alphavs S&P 500”, and “Sharpe Ratiorf 4.5%”.
- Volume renders as currency (`$38.60M`) instead of shares.
- The app combines reported history, derived metrics, modeled outputs, and sample/gated data without one persistent provenance language.

**Recommended canonical flow**

`Search company → Evidence → Model → Decision → Review`

For a ticker, use one sub-navigation:

- Overview
- Financials
- Valuation & scenarios
- Thesis
- Filings/calls
- Review history

Charts, risk metrics, and comparison should support those decisions rather than compete as top-level products.

### 4.4 Projections and valuation

The model modules are among the best technical assets in the repository. They should become the product’s center of gravity, but need a stronger trust and workflow layer.

- Direct projection links do not reliably preserve the projection destination.
- Guests can reach a detailed sample, then hit Pro gating inconsistently depending on entry route.
- Inputs need visible units, source/default provenance, last-updated dates, reset-to-source actions, sensitivity explanations, and a change log.
- Output should separate “historical,” “consensus,” “user assumption,” and “calculated result” visually and semantically.
- Every saved model should preserve exact inputs, data snapshot/as-of time, model version, and output so a later review is reproducible.

### 4.5 Planner

The wealth planner works as a guest calculator, but appears inside stock-analysis chrome. It inherits the AAPL ticker and Watch/Save/Export-analysis actions, which are unrelated to a long-range contribution plan.

**Recommendation:** keep Planner as a separate product route with its own identity, saved scenarios, inflation/tax caveats, goal progress, and assumption history—or remove it from primary navigation until it reaches that standard.

### 4.6 Learn

Learn currently behaves like a single static lesson (“Build a stock thesis”) while occupying a primary navigation slot. It also inherits ticker and analysis actions that do not belong.

**Recommendation:** either build a structured, contextual curriculum tied to the current workflow, or move the one lesson into contextual help. A premium app should teach at the point of decision, not maintain a thin parallel content area.

### 4.7 Saved/workspace

Saved Analyses has a usable guest/local concept. Thesis, Portfolio, Watchlist, Guide, trust, reminders, and reviews are the strategic differentiation—but their production integration is broken.

The future workspace should answer three questions immediately:

1. What decisions am I actively evaluating?
2. What changed since I last reviewed them?
3. What requires action or renewed evidence now?

Avoid a generic dashboard-builder unless customer research demonstrates demand. A carefully opinionated decision queue is more valuable than movable widgets for this product.

### 4.8 Authentication, pricing, and account lifecycle

- Signup says “Your password is encrypted.” The implementation correctly hashes passwords with bcrypt; the copy should say “securely hashed,” not encrypted.
- The signup screen does not place Terms, Privacy, trial-renewal, or cancellation links/consent near the CTA.
- “Free forever. No credit card. Live data...” overstates feed freshness and does not explain email verification.
- Guest allowance (2/day), free account allowance (5/day), Pro gating, sample data, and preview behavior are not explained as one consistent entitlement model.
- No visible self-service account deletion, data export, email change, MFA, session/device management, or breached-password control was found.
- A $7.99 Pro price may be attractive, but licensed global data and reliable transcripts/estimates are expensive. Validate unit economics and entitlements before promising competitor-level coverage.

---

## 5. Responsive and visual design audit

### Observed breakpoint results

| Viewport | Result |
|---|---|
| 320×568 | No document overflow; hero illustration is only ~210×140 and unreadable; bottom nav consumes scarce height. |
| 375×812 / 390×844 | Basic phone shell works; research has multiple nested horizontal scrollers and bottom-content overlap. |
| 768×1024 | **Broken:** desktop header enabled too early; nav/account controls collide. |
| 1024×768 | Header fits narrowly; hero still dominates and primary value/content remains low in the page. |
| 1366×768 | Large blank/illustration-led first viewport; real heading below fold. |
| 1440×900 | Research density is high with nested scroll regions and low-contrast typography. |
| 1920×1080 | Hero image grows to roughly 1,360×907, worsening content displacement. |

### Visual-system problems

- `public/legacy-app.css`: ~400 KB source, 8,109 lines, **1,908 `!important` declarations**.
- `public/premium.css`: ~77 KB source, 1,382 lines, **505 `!important` declarations**.
- `index.html` contains hundreds of inline styles and event handlers.
- The style cascade is being negotiated through overrides rather than governed through tokens/components.
- Marketing, research, auth, legal, and workspace concepts vary in typography, spacing, elevation, density, and interaction behavior.
- Pale beige surfaces and tiny secondary text reduce legibility in dense research contexts.
- Footer “Lens” text failed automated color contrast at approximately 2.85:1 where 4.5:1 is expected for normal text.

### Required design-system reset

Create a small, documented system with:

- semantic color roles for background/surface/border/text/accent/positive/negative/warning/data states;
- type scale with minimum body and data-label sizes;
- 4/8 px spacing scale;
- radii, elevation, focus ring, motion, and density tokens;
- canonical Button, Link, Input, Select, Tabs, Card, Table, Metric, EmptyState, ErrorState, SourceBadge, AsOf, Gate, Toast, and Dialog components;
- chart palette and number-format rules;
- compact and comfortable density modes only if genuinely necessary.

Set a migration target of fewer than 20 justified `!important` rules and zero inline event attributes in production markup.

---

## 6. Accessibility audit

The production landing page scored **96** in automated Lighthouse accessibility, but that score does not represent the application workflow. The combined single-page DOM hides large surfaces rather than removing them, and many tool controls are not semantic.

### Key findings

- Sidebar destinations use clickable `div`s without native button/link semantics, keyboard behavior, or consistent focusability.
- The active research experience did not expose a useful heading hierarchy.
- Numerous form controls in the tool DOM lack programmatic labels.
- Horizontally scrollable tab/tool strips do not announce overflow or provide previous/next affordances.
- Risk metric labels merge in accessible text.
- Hidden routes remain in a DOM containing roughly 2,000 elements and around 150 buttons during a research session; hidden-state management must be verified for the accessibility tree.
- Icon-only controls need reliable accessible names and larger phone hit targets.
- Footer contrast fails.
- Dense data color cannot be the sole signal for positive/negative/state meaning.

### Accessibility acceptance standard

- Native interactive elements by default; ARIA only when a native element cannot express the behavior.
- One visible `h1` per route and logical heading sequence.
- Every input has a `label`/accessible name, help text association, unit, error association, and keyboard-operable increment behavior where relevant.
- All dialogs trap/restore focus and close with Escape.
- All routes pass axe with zero serious/critical violations.
- Manual keyboard, 200% zoom, Windows High Contrast, reduced motion, and screen-reader smoke tests are release gates.
- Target WCAG 2.2 AA, including focus appearance, target size, and accessible authentication requirements.

---

## 7. Performance audit

### Production mobile Lighthouse

| Metric | Result | Target |
|---|---:|---:|
| Performance score | **59** | ≥90 lab; monitor p75 field data |
| Accessibility | 96 | 100 where automatable |
| Best Practices | 100 | 100 |
| SEO | 100 | 100 |
| FCP | 3.5 s | ≤1.8 s |
| LCP | **13.8 s** | ≤2.5 s p75 |
| TBT | 160 ms | ≤200 ms |
| CLS | 0.007 | ≤0.1 |
| Speed Index | 8.2 s | ≤3.4 s |
| Time to Interactive | 15.8 s | ≤3.8 s lab target |
| Transfer | ~2.81 MB | ≤750 KB initial route |

### Primary causes

1. `hero-process.png` is approximately **1.73 MB**, 1536×1024, and displayed around 307×205 on mobile. Lighthouse estimated roughly 1.72 MB avoidable image transfer. It is the LCP element.
2. The landing page requests quote data for AAPL, NVDA, MSFT, TSLA, AMZN, META, GOOGL, and SPY twice, plus indices, VIX, movers, news, analyst signals, auth state, CSRF, and tracking—even though much of the market dashboard is hidden.
3. The icon font transfers roughly 458 KB; most icon CSS is unused.
4. About 84% of loaded legacy CSS and substantial homepage/Chart JavaScript were unused during the tested route.
5. Main-thread work was around 3.2 s, including ~893 ms style/layout and ~767 ms script evaluation.
6. The longest observed dependency chain included `/api/me/limit` at around 3.15 s.

### Performance remediation order

1. Remove the raster-text hero. If an illustration remains, produce responsive AVIF/WebP variants under 100 KB and set explicit dimensions/preload only for the chosen LCP asset.
2. Initialize only the active route. No market quotes, movers, news, charts, or workspace calls should occur on the marketing homepage unless the visible component requires them.
3. Add a shared client request cache/deduper; never fetch the same symbol/range twice during one route load.
4. Route-split charts, valuation, projection, workspace, and market code.
5. Replace the full icon font with inline SVG components or a small subset.
6. Remove dead CSS and migrate active styles into component bundles.
7. Render only the current route; do not retain entire applications in hidden DOM.

### Proposed budgets

- Homepage initial compressed transfer ≤750 KB; application shell ≤1 MB before user-requested data.
- Initial JS ≤200 KB gzip; route chunks ≤100 KB gzip unless justified.
- LCP asset ≤100 KB on mobile.
- Active-route DOM ≤800 elements under ordinary use.
- Zero duplicate identical API requests during initial navigation.
- CI fails if Lighthouse mobile LCP >3.0 s, performance <85, or bundle budgets regress by >10%; tighten after the rebuild.

---

## 8. Data quality, trust, and financial correctness

### Strengths to preserve

- The data-sources page distinguishes reported, derived, and modeled values.
- SEC filing links and unavailable-state language are directionally right.
- Model code has substantive tests and does not appear to rely on hidden third-party calculation services.
- The brand guidance explicitly prefers evidence and “latest available” over unsupported real-time claims.

### Trust defects

| ID | Finding | Severity | Required correction |
|---|---|---:|---|
| DATA-01 | Landing/signup say “Live data” / “Live exchange data,” while the data-source page says Yahoo prices are typically delayed ~15 minutes. | P1 | Replace with “latest available market data” and expose delay/as-of metadata from the actual feed. |
| DATA-02 | Code infers a `delayed` state from requested interval, not exchange entitlement or actual feed timing. | P1 | Provider response must return source, as-of, market session, entitlement/delay classification, and fallback status. |
| DATA-03 | `^IXIC` is labeled Nasdaq 100. | P1 | Label Nasdaq Composite or use the correct Nasdaq-100 instrument/source. |
| DATA-04 | Volume is formatted as currency (`$38.60M`). | P1 | Use shares with compact number formatting and explicit unit. |
| DATA-05 | Market timestamp labels local browser time as ET. | P1 | Format with `timeZone: 'America/New_York'` or display the user’s actual zone accurately. |
| DATA-06 | Market breadth cards are permanently unavailable yet look like active premium features. | P2 | Implement a licensed feed, label delayed/unavailable, or remove the cards. |
| DATA-07 | Financial-statement preview uses FY2023/FY2024 sample values in 2026. | P2 | Use a current generated sample, show a prominent sample watermark, and state its frozen as-of date. |
| DATA-08 | “AI Portfolio Guide” is a transparent deterministic questionnaire/scoring function in `routes/workspace.js`, not an AI system. | P1 | Rename “Portfolio Guide” or build/document a real AI subsystem with limitations, evaluations, and governance. |
| DATA-09 | Recommendation counts from five mega-cap companies are summarized as a broad bullish percentage. | P2 | Label the exact sample and methodology; do not imply market-wide sentiment. |
| DATA-10 | “Your Watchlist” is hard-coded guest content. | P2 | Rename “Popular companies” or use a true personalized state. |
| DATA-11 | Curated screener coverage can read like a market-wide universe. | P1 | State universe size, inclusion policy, refresh schedule, and missing markets before every result set. |
| DATA-12 | Reported/provider fields are sometimes interpolated into HTML without a uniform encoder. | P1 security/trust | Normalize and escape at a single render boundary; use DOM text APIs for text fields. |

### Required provenance contract

Every displayed financial datum or model output should be able to answer:

- **What is it?** Reported, adjusted, consensus, derived, modeled, or user-entered.
- **Where did it come from?** Provider and, where possible, filing/document link.
- **When was it current?** As-of timestamp and market session/time zone.
- **How was it transformed?** Formula/version and any normalization.
- **What happens when unavailable?** No silent substitution.
- **Can the decision be reproduced?** Persist source snapshot, inputs, model version, and output with saved work.

This provenance layer is the product’s best potential moat.

---

## 9. Code and architecture audit

### Current composition

- `index.html`: ~396 KB, 6,661 lines, five large inline scripts, roughly 683 function/arrow occurrences, 66 `.innerHTML` assignments, and 199 inline event attributes.
- `public/legacy-app.css`: ~400 KB / 8,109 lines.
- `public/premium.css`: ~77 KB / 1,382 lines.
- External product/workspace/projection/model modules range from ~47–80 KB each.
- Express server with route modules for auth, billing, financials, market data, stock landing, and workspace.
- libSQL/Turso database initialized and altered at runtime.

### Architectural findings

#### ARCH-01 — Monolithic page and global state (P1)

Multiple products share one document, global functions, hidden sections, and initialization side effects. This makes navigation, testing, performance, and ownership fragile.

**Action:** move to route-level modules. A framework is optional; clear module boundaries are not. Server-render public marketing/SEO pages and hydrate/load only interactive application routes.

#### ARCH-02 — Parallel unfinished systems (P0)

The repository contains newer systems that are neither canonical nor removed. Tests, production, and source disagree about the architecture.

**Action:** publish an architecture decision record identifying the canonical router, state store, design system, data client, workspace implementation, and deprecation plan.

#### ARCH-03 — CSS override debt (P1)

More than 2,400 `!important` declarations across the two main stylesheets signal uncontrolled specificity and make visual regressions likely.

**Action:** freeze legacy styling, introduce scoped components/tokens, migrate route by route, then delete the legacy selectors.

#### ARCH-04 — Inline behavior prevents a strong CSP (P1)

Helmet is configured, but production CSP permits `'unsafe-inline'` and script attributes because the page relies on inline scripts and event handlers. Privacy copy calling this a “strict CSP” is inaccurate.

**Action:** remove inline script/event attributes, use nonces/hashes only where unavoidable, and enforce a CSP without `unsafe-inline` or `script-src-attr` allowance.

#### ARCH-05 — Unsafe rendering boundary (P1)

Provider and application data are frequently rendered with template strings and `.innerHTML`. Some paths use `escapeHtml` and safe-URL helpers; others interpolate fields such as sector/period-like values without a uniform boundary. No Trusted Types policy or sanitizer was found.

**Action:** default to `textContent`/DOM creation; centralize safe templates; validate provider schemas; add adversarial rendering tests; deploy Trusted Types after inline cleanup.

#### ARCH-06 — Runtime migrations with swallowed errors (P1)

`lib/db.js` performs `ALTER TABLE` operations at startup and catches all errors without distinguishing “already exists” from real failures. There is no migration version, rollback, or deployment gate.

**Action:** adopt numbered migrations, schema-version checks, backups, rollback/runbook, and migration CI against a production-like copy.

#### ARCH-07 — No relational integrity (P2)

User-owned tables contain `user_id` fields but no foreign-key constraints were found. This permits orphaned records and complicates deletion/export.

**Action:** add foreign keys/cascade policy deliberately after data cleanup and backup verification.

#### ARCH-08 — Background email scheduling lives in the web process (P1)

Review digests are driven by `setTimeout`/`setInterval` inside the app process. Restarts and multiple instances make scheduling nondeterministic, even with some database idempotency.

**Action:** move scheduled work to a durable job runner/cron worker with locks, retries, dead-letter visibility, and metrics.

#### ARCH-09 — Tracked diagnostic artifacts (P2)

Files such as `_c.js`, `_chk.js`, `_inline_check.js`, `_k.js`, `_engine_block.js`, `_projlab_preview.html`, `_vallab_preview.html`, and shim files are tracked alongside product code.

**Action:** inventory references, move legitimate developer tooling under `scripts/`, document it, and delete abandoned previews/shims.

#### ARCH-10 — Error/empty/loading contracts are inconsistent (P1)

Blank content, dashes, static samples, refreshing messages, Pro gates, and silent fallbacks are used interchangeably.

**Action:** define route and component state machines: idle, loading, partial, stale, empty, unavailable, forbidden/gated, and error—with source/fallback context.

### Recommended target architecture

```text
Public site (SSR/static)
  /, /about, /research-process, /data-sources, /pricing, /legal, /stock/:symbol

Application shell
  /app/market
  /app/company/:symbol/overview
  /app/company/:symbol/financials
  /app/company/:symbol/model
  /app/company/:symbol/thesis
  /app/company/:symbol/evidence
  /app/workspace
  /app/planner

Shared layers
  design tokens/components
  accessible router + URL state
  typed provider/data contracts
  request cache/deduplication
  entitlement service
  provenance/model-version service
  telemetry/error boundaries

Server
  authenticated API + CSRF
  market/filing provider adapters
  versioned migrations
  durable scheduled worker
  structured logs/metrics/traces
```

The exact framework matters less than making routes, data contracts, and components independently testable.

---

## 10. Security and privacy review

### Good baseline controls

- Helmet headers, HSTS, clickjacking protection, MIME sniff protection, COOP/CORP, and secure production cookie settings.
- HTTP-only, Secure, SameSite=Lax session/guest cookies.
- CSRF token generation and timing-safe verification for state mutations.
- 64 KB JSON body limit.
- Parameterized database calls in inspected routes.
- Bcrypt hashing at 12 rounds, reset-token handling, and session invalidation after password change.
- Authentication and endpoint rate limits.
- Ticker and workspace input validation.
- Stripe raw-body webhook signature verification and event idempotency.
- Production startup checks for key secrets/providers.

### Priority risks and gaps

| ID | Finding | Priority | Recommendation |
|---|---|---:|---|
| SEC-01 | CSP permits inline scripts and inline script attributes. | P1 | Remove inline execution and enforce nonce/hash-based external scripts. |
| SEC-02 | Inconsistent `innerHTML` encoding of provider/user-derived fields. | P1 | One safe rendering boundary, provider schema validation, adversarial tests, Trusted Types. |
| SEC-03 | Public `/healthz` exposes exact commit, service version/environment, provider counts, latency, and messages. | P2 | Split a minimal public liveness endpoint from authenticated/internal readiness detail. |
| SEC-04 | Admin-secret comparisons appear to use ordinary string equality. | P2 | Hash or timing-safe compare fixed-length secrets; rotate and audit access. |
| SEC-05 | No MFA, session/device view, breached-password screen, or privileged-action reauthentication. | P2 | Add according to account-risk model, prioritizing MFA/session revocation for paid accounts. |
| SEC-06 | One low-severity `body-parser` DoS advisory is present transitively. | P2 | Update dependency chain and verify tests. |
| SEC-07 | HSTS is about 180 days and not preload-ready. | P3 | Move to one year/preload only after confirming every subdomain supports HTTPS permanently. |
| SEC-08 | No documented dependency scanning cadence, SAST/secret scanning, threat model, or incident runbook. | P1 process | Add CI/repository protections and quarterly threat-model review. |

### Privacy/legal accuracy issues

- Privacy policy says a single session cookie (`il.sid`) is used, but production also sets a persistent 90-day `il_gid` guest cookie and the frontend uses local/session storage.
- Privacy policy describes a “strict Content Security Policy,” which conflicts with the live `unsafe-inline` policy.
- Data processors and recipients need a complete current inventory: hosting/CDN, Turso/libSQL, Stripe, Resend, Yahoo/Finnhub/SEC/Stooq, font/CDN services, and any future analytics/error monitoring.
- Policies are dated June 1, 2025 and do not clearly cover the current workspace, review emails, guest identity, or expanded storage behavior.
- No legal entity/controller address was visible; support email alone is insufficient for a mature commercial product.
- Terms use vague United States law/arbitration language without a clear state, venue, rules, or class-action treatment. Have counsel review.
- Signup needs explicit Terms/Privacy assent and clear trial renewal/cancellation disclosure near the action.
- Self-service privacy export/deletion should exist in-product and be tested end to end.

This is a product audit, not legal advice; policy changes require qualified counsel.

---

## 11. Operations and engineering process

### Current process strengths

- A GitHub Actions quality workflow runs install, checks, tests, and audit.
- Server health tracks observed provider successes/failures and latency.
- Stripe events are idempotently recorded.
- Several server routes have meaningful integration tests.

### Missing premium-operability capabilities

- No browser end-to-end or visual-regression suite.
- No documented staging environment or promotion/rollback process.
- No structured logs, request correlation, error monitoring, traces, dashboards, or SLO alerts.
- No synthetic checks for signup, data retrieval, source fallback, billing portal, and saved-work retrieval.
- Provider health is reactive: it reflects traffic seen, not proactive end-to-end dependency readiness.
- Database backup/restore validation, retention, recovery point/time objectives, and incident runbooks are undocumented.
- Runtime schema changes are not deployment-controlled.
- Scheduled mail is not a durable worker.
- Commits such as “foot,” “Footer,” and “Bug fixes” do not create an auditable product/change history.
- No ownership map, release checklist, changelog, architectural decision records, or feature-flag/rollback policy was found.

### Required release gates

1. Clean install and all unit/integration tests pass.
2. Playwright smoke tests for every primary route at 375, 768, 1024, and 1440 px.
3. Direct-link, refresh, back/forward, provider-failure, unauthenticated, free, trial, Pro, expired, and cancellation states.
4. Axe and keyboard smoke on all primary routes.
5. Visual regression for landing, market, company, model, workspace, auth, and gates.
6. Lighthouse/bundle budgets.
7. API contract tests with provider fixtures and malformed/unavailable responses.
8. Stripe webhook replay/idempotency, checkout/portal, trial conversion, payment failure, cancellation, and entitlement reconciliation tests.
9. Email verification/reset/review-mail tests with a safe staging inbox.
10. Migration forward/backward rehearsal and restore drill.

---

## 12. Dependency and repository health

### Notable outdated packages observed

| Package | Current | Latest observed | Note |
|---|---:|---:|---|
| `@libsql/client` | 0.14.0 | 0.17.4 | Review release notes and Turso behavior. |
| `bcryptjs` | 2.4.3 | 3.0.3 | Major upgrade; verify hash compatibility/performance. |
| `dotenv` | 16.6.1 | 17.4.2 | Major upgrade. |
| `express` | 4.22.2 | 5.2.1 | Major server migration; do separately with route/error tests. |
| `express-rate-limit` | 7.5.1 | 8.6.0 | Major upgrade. |
| `helmet` | 7.2.0 | 8.3.0 | Major upgrade; coordinate with CSP rebuild. |
| `resend` | 6.12.3 | 6.18.0 | Minor upgrade. |
| `stripe` | 16.12.0 | 22.3.2 | Large major gap; validate API version and webhook types. |

Do not bulk-upgrade these in one change. Create grouped migrations with contract tests, especially Express, Stripe, and database dependencies.

### Configuration documentation defect

`.env.example` displays mojibake in section separators, indicating an encoding/console mismatch. More importantly, production operational variables should document ownership, rotation, validation, least-privilege permissions, and whether a restart is required.

---

## 13. Competitive benchmark

The comparison below uses official product/help sources accessed July 22, 2026. Prices and features change; verify again before making public comparison claims.

| Product | Premium expectation it sets | Lesson for Implied Lens |
|---|---|---|
| [TIKR](https://support.tikr.com/hc/en-us/articles/5365175244955-What-are-the-benefits-of-purchasing-a-TIKR-premium-plan) | Broad global company coverage, long financial histories, estimates, guided/advanced valuation, transcripts, dashboards, catalysts, and exports. | Do not compete on breadth without funded/licensed coverage. Win on decision traceability and simpler modeling. |
| [Koyfin](https://www.koyfin.com/pricing/) | Multi-asset dashboards, charting, screeners, portfolios, alerts, and professional information density across clear tiers. | Market breadth and configurable dashboards are table stakes at terminal-like positioning; avoid implying this scope unless delivered. |
| [Fiscal.ai](https://fiscal.ai/pricing/) | Global financials/KPIs, dashboards, DCF, ownership, earnings content, and AI at much higher price points. Its [data/research skill documentation](https://docs.fiscal.ai/docs/guides/mcp-skills) emphasizes source-linked, as-filed evidence. | Source-linked evidence is now an explicit category expectation. Implied Lens can make provenance simpler and more decision-oriented. |
| [TradingView](https://www.tradingview.com/features/) | Mature charts, alerts, screeners, cross-device sync, native apps, communities, and an extensible scripting ecosystem. | Do not present generic charts as the moat. Make charts subordinate to a fundamental decision workflow. |
| [Simply Wall St](https://simplywall.st/about) | Highly visual company reports and accessible portfolio storytelling at consumer scale. | Implied Lens needs a recognizable visual grammar for evidence, value, risk, and thesis—not generic cards alone. |
| [Quartr](https://quartr.com/features/index) | Focused earnings-call/document workflow across thousands of companies, synchronized transcripts, search, watchlists, and alerts. | If calls remain a Pro promise, build a genuinely excellent evidence-navigation workflow or integrate a reliable specialist source. |
| [Seeking Alpha Premium](https://help.seekingalpha.com/premium/seeking-alpha-premium-feature-list) | Ratings, contributor content, transcripts, alerts, and portfolio monitoring with continuous reasons to return. | A premium subscription needs recurring value: change detection, review queues, alerts, and decision follow-up—not only one-time calculations. |

### Patterns from premium tools outside finance

- [Linear’s conceptual model](https://linear.app/docs/conceptual-model) applies consistent actions across buttons, context menus, keyboard shortcuts, and command surfaces. Implied Lens needs one navigation/action grammar rather than separate behavior per section.
- [Stripe Dashboard search](https://docs.stripe.com/dashboard/search) and [Workbench](https://docs.stripe.com/workbench/overview) show how universal search, linkable state, logs, errors, and system health build trust in complex workflows. Implied Lens should make company search universal and every analytical state shareable/reproducible.
- [Notion templates](https://www.notion.com/help/start-with-a-template) reduce blank-canvas anxiety with role/task-oriented starters. Implied Lens should offer starter thesis/model templates by investing question, not an empty dashboard.
- [Figma’s design-system practice](https://www.figma.com/best-practices/how-figma-uses-dev-mode/) emphasizes shared tokens and design/code synchronization. Implied Lens needs this discipline before another visual layer is added.

### Recommended market position

> **Implied Lens is the calm, source-linked decision workspace that connects financial evidence, explicit assumptions, valuation, a written thesis, and scheduled review.**

That position is narrower and more credible than “terminal,” “AI advisor,” or “all-in-one investing platform.” It supports a premium experience through trust and continuity rather than expensive data breadth.

### What “premium” should mean here

- The right view always opens and can be shared.
- Every number has a source and as-of state.
- Every model assumption is visible and reversible.
- The product remembers why the user made a decision.
- Changes since the prior review are surfaced automatically.
- Loading, empty, stale, unavailable, and gated states never look broken.
- Mobile/tablet are first-class, not compressed desktop.
- The language is more precise than competitors, never more promotional than the evidence.

---

## 14. Prioritized master backlog

### P0 — Release blockers

| ID | Work | Owner | Acceptance summary |
|---|---|---|---|
| P0-01 | Resolve unshipped product/workspace/dashboard systems. | Frontend lead | Canonical modules selected; advertised features loaded or removed. |
| P0-02 | Repair Saved → Thesis/workspace blank state. | Frontend + QA | Every nav destination works for guest/free/Pro and handles errors. |
| P0-03 | Repair direct URL and history state. | Frontend | Symbol/section/tab survive initial load, refresh, back/forward, and sharing. |
| P0-04 | Restore a green test suite and install DOM test dependency. | Engineering | Clean `npm ci && npm run check && npm test` passes with no critical skips. |
| P0-05 | Rebuild tablet header/breakpoint behavior. | Design + frontend | No overlap from 320–1920 px, 200% zoom, or keyboard navigation. |

### P1 — Premium-readiness foundation

| ID | Work | Acceptance summary |
|---|---|---|
| P1-01 | Replace raster hero and route-gate landing initialization. | Mobile LCP ≤2.5 s target; no hidden market requests; real visible H1 and CTA in first viewport. |
| P1-02 | Establish canonical IA and route-level shell. | One search, one company subnav, one workspace, linkable routes. |
| P1-03 | Introduce tokens/components and freeze legacy CSS. | New work uses components; override count declines every migration. |
| P1-04 | Make all primary controls semantic and labeled. | Axe clean plus manual keyboard/zoom/screen-reader smoke. |
| P1-05 | Build typed provenance/data contracts. | Every number exposes type/source/as-of/fallback; unavailable never silently substituted. |
| P1-06 | Correct Nasdaq, volume, timezone, sample, breadth, and watchlist labeling. | Data-label regression suite passes. |
| P1-07 | Remove or substantiate “live” and “AI” claims. | All copy matches actual providers/algorithm and `BRAND.md`. |
| P1-08 | Standardize guest/free/Pro/sample/gate behavior. | Entitlement matrix documented and tested at every entry route. |
| P1-09 | Remove inline handlers and strengthen CSP. | No `unsafe-inline`/script attributes; security headers tested. |
| P1-10 | Create safe rendering boundary. | Provider/user fields cannot create markup; adversarial fixture suite passes. |
| P1-11 | Add versioned migrations and durable job worker. | Repeatable deploy/rollback; scheduled mail survives restarts/multiple instances. |
| P1-12 | Add end-to-end observability and SLOs. | Correlated logs, error tracking, provider/API metrics, synthetic journeys, alert ownership. |
| P1-13 | Update signup/account/legal/privacy flows. | Accurate consent/trial/cookie/processor language plus deletion/export. |
| P1-14 | Confirm market-data licensing and unit economics. | Documented rights, delay classifications, caching limits, attribution, and plan economics. |

### P2 — Product depth and refinement

| ID | Work | Acceptance summary |
|---|---|---|
| P2-01 | Rebuild workspace as decision/review queue. | Shows active theses, material changes, reviews due, and reproducible saved models. |
| P2-02 | Add assumption history and model versioning. | Users can compare, restore, and explain model changes. |
| P2-03 | Improve tool mobile navigation. | No mystery horizontal scrollers; bottom nav never overlaps content. |
| P2-04 | Decide Planner’s product role. | Dedicated route/workflow or removed from primary navigation. |
| P2-05 | Decide Learn’s product role. | Contextual curriculum with progression or merged into help. |
| P2-06 | Replace thin/static sample states. | Current, clearly watermarked, representative preview with consistent gate. |
| P2-07 | Add alerts/change detection. | Users receive explainable, configurable changes tied to a thesis/review. |
| P2-08 | Clean tracked shims/previews and document dev tooling. | Root contains only production/docs/config; scripts are named and owned. |
| P2-09 | Add a dedicated lightweight 404. | Helpful navigation, correct status, minimal payload. |
| P2-10 | Upgrade dependencies in isolated migrations. | Release-note review, green contracts, rollback plan. |
| P2-11 | Add account security controls. | MFA/session revocation/reauth appropriate to risk. |
| P2-12 | Refine visual hierarchy and accessible contrast. | All WCAG AA; data tables/cards readable at compact widths. |

### P3 — Later differentiation

- Filing/call change summaries tied directly to thesis claims.
- Comparable-company and scenario templates with fully visible methodology.
- Collaborative/advisor sharing only after single-user traceability is excellent.
- Mobile apps only if web retention demonstrates a notification/offline need.
- A real AI assistant only after source retrieval, citations, evaluations, privacy boundaries, and deterministic fallbacks are production-grade.

---

## 15. What to retain, rework, and remove

### Retain and strengthen

- Evidence-led, non-hype brand direction.
- Model math, projection, and valuation modules after independent assumption/correctness review.
- SEC/source links and reported/derived/modeled vocabulary.
- Thesis, decision, review-date, and portfolio-exposure concepts.
- Basic security controls: CSRF, password hashing, secure cookies, rate limits, Stripe verification.
- Market page’s clearer card grouping as a visual reference, not necessarily its data breadth.
- Simple transparent pricing, once entitlement and feed economics are validated.

### Rework substantially

- Entire frontend shell/router/state initialization.
- Landing hero and first-use journey.
- Responsive header, mobile tool tabs, and bottom navigation.
- Workspace and saved/review continuity.
- CSS/design system and interaction semantics.
- Data-fetch orchestration and provider metadata.
- Gating, previews, samples, and empty/error states.
- Signup, trial, account, privacy, and cancellation surfaces.
- Deployment/migrations/jobs/observability.

### Remove now unless an owner can justify them

- False or ambiguous “live” data claims.
- “AI” naming for the deterministic Portfolio Guide.
- Permanently empty market breadth cards.
- AAPL-specific Watch/Save/Export chrome on Planner and Learn.
- Rasterized hero copy.
- Dead dashboard/workspace/product code paths once the canonical implementation is selected.
- Abandoned root diagnostic shims and preview HTML.
- Generic primary navigation destinations that contain only one thin page.

---

## 16. Recommended delivery sequence

### Phase 0 — 0–2 weeks: stop the reliability leak

- Freeze net-new features.
- Decide the canonical product/workspace implementation.
- Fix blank routes, deep links, test failures, tablet header, volume/Nasdaq/timezone labels, and inaccurate “live/AI/password encrypted” copy.
- Add navigation/deep-link Playwright smoke tests.
- Remove the oversized hero and hidden landing data initialization.
- Add route error boundaries and explicit unavailable/gated states.

**Exit:** no dead primary journey, green CI, mobile performance materially improved, language matches reality.

### Phase 1 — 2–6 weeks: build the premium foundation

- Introduce routes, design tokens/components, typed data/provenance contracts, shared request client, and entitlement matrix.
- Migrate landing, shell, company overview, and model first.
- Remove inline handlers and deploy a stronger CSP.
- Establish telemetry, error reporting, synthetic checks, versioned migrations, and a durable job worker.
- Update legal/account lifecycle with counsel.

**Exit:** coherent shell, testable modules, reproducible models, observable operations.

### Phase 2 — 6–12 weeks: deliver the differentiator

- Rebuild Workspace around thesis → evidence → model → decision → review.
- Add “what changed” and review queue.
- Persist source snapshot, assumption history, model version, and decision notes.
- Add evidence-linked exports/reports.
- Validate pricing and retention with real cohort/product analytics.

**Exit:** the subscription has recurring value and a credible reason to choose Implied Lens over a generic screener or charting platform.

### Phase 3 — after validation

- Expand coverage/transcripts/alerts selectively.
- Consider genuine source-citing AI assistance only with evaluation and governance.
- Add collaboration or native apps only when customer evidence supports them.

---

## 17. Handoff map for the next engineer or AI agent

Start in this order:

1. `README.md` and `BRAND.md` — intended architecture and product language.
2. `index.html` — current shipped application, inline behavior, page initialization, routes, and marketing copy.
3. `public/product-system.js` — trust/onboarding/deep-link/decision concepts currently not loaded.
4. `public/workspace-system.js` and `routes/workspace.js` — thesis, portfolio, watchlist, guide, review behavior.
5. `public/model-math.js`, `public/projection-lab.js`, `public/valuation-lab.js` — strongest model assets.
6. `public/legacy-app.css`, `public/premium.css`, `public/workspace-system.css` — styling layers and override debt.
7. `server.js`, `routes/market-data.js`, `routes/financials.js` — provider orchestration, headers, caching, and public delivery.
8. `routes/auth.js`, `routes/billing.js`, `lib/plan.js`, `lib/db.js` — identity, entitlement, Stripe, sessions, schema, background lifecycle.
9. `test/` and `.github/workflows/quality.yml` — current gates and gaps.
10. Public legal/content pages under `public/` — claims that must be reconciled with code and providers.

### First implementation pull request should contain only

- canonical module-loading/deep-link/nav fixes;
- test repair plus Playwright navigation coverage;
- tablet header fix;
- critical data/copy corrections;
- hero/performance correction.

Do not combine the full architecture rewrite, dependency majors, legal rewrite, and product redesign in one pull request.

---

## 18. Definition of done for “premium-ready”

Implied Lens should not be called premium-ready until all of the following are true:

- No P0 issues remain and CI is consistently green.
- Every advertised capability is reachable and functional in the deployed build.
- All primary routes are shareable, refresh-safe, back/forward-safe, and usable at supported widths.
- Mobile p75 LCP is ≤2.5 s or has a documented, improving field-data plan; no hidden-route network storm occurs.
- WCAG 2.2 AA is met for primary journeys with automated and manual evidence.
- Reported, derived, consensus, modeled, user-entered, sample, stale, delayed, and unavailable states are visibly distinct.
- “Live,” “AI,” coverage, pricing, trial, privacy, and security language are literally accurate.
- Saved decisions can be reproduced from their data snapshot, assumptions, and model version.
- Provider failure, stale fallback, billing failure, email failure, and job retry states are observable and recoverable.
- Backup/restore, migration, rollback, incident, and dependency processes are documented and exercised.
- A new user can search a company, understand the evidence, change assumptions, record a thesis, and schedule a review without encountering a blank page or wondering what to do next.

---

## Final product recommendation

Implied Lens should narrow before it expands. The repository already contains more surface area than the current architecture and process can support reliably. The next version should remove ambiguity and make one loop exceptional:

> **Find a company → inspect source-linked evidence → model explicit assumptions → record a decision → return when the evidence changes.**

If that loop is fast, reproducible, accessible, and trustworthy across devices, Implied Lens will feel premium even with a smaller universe of features. If that loop remains split across disconnected systems, more dashboards, AI labels, and research cards will make the product feel less finished, not more.
