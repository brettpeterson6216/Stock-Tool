# Implied Lens — LensScore, Live Data, and Product Handoff

**Prepared:** July 24, 2026

**Scope:** Local production candidate in `C:\Users\clash\Downloads\Stock Tool`

**Deployment status:** Deployed to production on commit `7e3198b` on July 25, 2026
**Primary model:** LensScore 0.6.0

## Executive decision

The product now has a coherent thesis:

> Implied Lens should reduce a large amount of financial and technical evidence into one transparent 0–10 buyability score, while keeping its long-term and tactical lenses independently useful.

That thesis is implemented as:

- **LensValue (1–3 years):** company quality, valuation, expectations, balance-sheet risk, and long-term downside.
- **LensSetup (2–12 weeks):** trend, momentum, support/resistance zones, volume confirmation, volatility, and technical risk.
- **LensScore (combined):** the decision-oriented 0–10 result.
- **Golden Lens:** a rare state that requires both LensValue and LensSetup to clear demanding thresholds with no active quality or risk cap.

This is the right product direction. The prior experience exposed many tools without a clear decision hierarchy. LensScore creates the hierarchy, keeps the evidence inspectable, and gives the brand a defensible product concept that is not a copy of another creator’s indicator.

The production build is materially stronger and is now deployed as a monitored release candidate. It is **not yet appropriate for public predictive-performance claims**. The remaining work is validation-oriented: monitor production-provider coverage, acquire or reconstruct point-in-time fundamentals for full LensValue backtesting, and complete physical-device mobile QA.

## What was implemented

### 1. A canonical live research layer

`lib/stock-research.js` is the canonical server-side research service.

It combines:

- Yahoo Finance chart observations for price history and technical analysis.
- SEC EDGAR company facts for reported statements and fundamental calculations.
- Finnhub, when configured and available, for estimates, profiles, ownership, and supplemental metrics.
- FINRA OTC Transparency for delayed weekly aggregate off-exchange activity.

Rules:

- No generated price series.
- No synthetic replacement values.
- Missing provider data is returned as unavailable, not converted to zero.
- Every payload carries source and observation-date provenance.
- SEC facts are aligned to the same fiscal measurement period before ratios are calculated.
- Optional-provider failure must not suppress valid SEC or FINRA results.

Key files:

- `lib/stock-research.js`
- `routes/market-data.js`
- `routes/financials.js`
- `routes/lens-score.js`
- `routes/stock-landing.js`
- `public/data-sources.html`

### 2. LensScore production candidate

Public route:

- `/lens-score`

Development-only route:

- `/__lab/lens-score`

API:

- `GET /api/lens-score/:ticker`

The model is defined in:

- `labs/lens-score/lens-score-engine.js`
- `lib/lens-score-engine.js`

The score never silently grades missing evidence. If the minimum company, valuation, or chart evidence is absent, the result is **Not Rated**.

Quality guardrails:

- Weak company quality caps the maximum score.
- Going-concern evidence caps LensValue and LensScore below 3.
- Extreme leverage caps LensValue and LensScore below 4.
- Golden Lens cannot activate while a quality or risk cap is active.

Current labels:

| Score | LensScore label |
|---:|---|
| 9.0–10.0 | Exceptional Lens |
| 8.0–8.9 | Strong Lens |
| 7.0–7.9 | Constructive |
| 6.0–6.9 | Developing |
| 5.0–5.9 | Neutral |
| 4.0–4.9 | Unfavorable |
| 3.0–3.9 | Weak |
| Below 3.0 | Severe risk |

The labels are descriptive model states, not recommendations or promises.

### 3. Price-scenario behavior

The scenario tool now separates the long-term and tactical consequences of a changed entry price.

Observed local check for NVDA:

- Reported market price: $206.84.
- Baseline LensValue: 6.9.
- Baseline LensSetup: 6.5.
- Baseline LensScore: 6.8.
- Half-price scenario: $103.42.
- Scenario LensValue: 10.0.
- Scenario LensSetup: 6.5.
- Scenario LensScore: 8.8.

This is intentional. A lower hypothetical entry price materially improves valuation and downside protection, but it does not rewrite the historical chart. The interface explains that the result assumes the company outlook has not deteriorated.

### 4. Technical analysis

LensSetup includes:

- Confirmed support and resistance zones.
- Zone strength and confirmed reaction counts.
- 20-, 50-, and 200-period trend structure.
- RSI.
- Stochastic RSI.
- MACD.
- Volume confirmation.
- On-balance-volume context.
- ATR and realized-volatility context.
- Distance from support/resistance and trend-regime scoring.

Pivot detection uses confirmed pivots and records confirmation indexes. Historical readings receive only the prefix of data that existed at the observation date.

### 5. Financials, metrics, and earnings

Financial statements and derived metrics use SEC XBRL as the reliable base.

Implemented calculations include:

- Revenue, gross profit, operating income, net income, diluted EPS.
- Operating cash flow, capital expenditure, and free cash flow.
- Assets, liabilities, cash, debt, and equity.
- EV/operating-income proxy, EV/revenue, trailing P/E, P/B, and P/S.
- Gross, operating, and net margins.
- ROE, ROA, and ROIC.
- Revenue and EPS growth.
- Debt/equity, current ratio, quick ratio, FCF/share, and cash/share.
- Interest coverage only when a matching-period interest-expense observation exists.

Important corrections:

- Free cash flow is operating cash flow minus absolute capital expenditure.
- Quick ratio is `(current assets - inventory) / current liabilities`; it is no longer a mislabeled cash ratio.
- Old interest-expense facts are not mixed with a newer operating-income year.
- Bank scoring can use profit margin, return on equity, and capital ratio instead of forcing industrial-company assumptions.
- SEC reported EPS and optional provider estimates are visually distinct.

### 6. FINRA institutional context

The old “dark pool” description was misleading. The visible product now calls this **FINRA OTC Activity**.

The existing `/api/darkpool/:ticker` path remains only for compatibility. Its payload now contains:

- Eight recent weekly FINRA partitions.
- Aggregated reported shares.
- Aggregated trade count.
- Aggregated notional value.
- Average reported price derived from notional divided by shares.
- Reporting tier and venue-row count.

It does not claim to show real-time order flow or venue-level dark-pool activity.

### 7. Source transparency

Every critical research screen now names:

- Source.
- Observation or filing date.
- Whether optional providers were available.
- That missing data was not synthetically replaced.

Static footer notes were also corrected so they do not claim Finnhub supplied a result when only SEC or FINRA data loaded.

### 8. Theme and product integration

Completed:

- LensScore is linked from the main research workflow.
- `/lens-score` is in the sitemap.
- Public LensScore metadata and canonical tags are present.
- Light and dark modes are supported.
- Stock acquisition pages now have a theme switch and semantic `<main>`.
- Stock acquisition pages use the canonical Yahoo chart fallback if Finnhub is unavailable.
- Public/static pages have main landmarks and shared product styling.
- Score colors communicate state while keeping the broader interface restrained.

## Historical calibration

Files:

- `lib/lens-calibration.js`
- `scripts/calibrate-lens-score.js`
- `public/lens-calibration.json`

Method:

- Walk-forward.
- No lookahead.
- A score at date `t` receives only bars at or before `t`.
- 525 observations.
- 15 liquid large-cap stocks and ETFs.
- 21- and 63-trading-day forward horizons.

Latest technical diagnostic:

| Horizon | Score/return correlation | High-score average return | Low-score average return |
|---|---:|---:|---:|
| 21 trading days | 0.073 | +0.42% | -3.20% |
| 63 trading days | 0.044 | +1.63% | -0.55% |

Interpretation:

- The technical model shows weak positive separation.
- The sample is too small and too selective for a public performance claim.
- The highest bucket is not monotonically superior to every middle bucket.
- These results are useful diagnostics, not evidence of a finished predictive model.

The full LensValue and Golden Lens model cannot be honestly backtested from today’s SEC snapshots. It needs point-in-time fundamentals, estimates, shares, and filing availability dates across a survivorship-bias-free universe.

## Page-by-page status

| Area | Current state | Data behavior | Remaining work |
|---|---|---|---|
| Landing/Home | Reorganized around a repeatable research workflow | No material synthetic research data | Continue reducing secondary marketing density |
| Market | Live chart observations with provenance | Honest unavailable states | Production provider alerting |
| Research/Chart | Strong technical workspace | Yahoo chart observations | Real-device gesture QA |
| LensScore | Production candidate | Yahoo + SEC + optional Finnhub | Full point-in-time calibration |
| Financials | SEC-backed and functioning | Reported XBRL | Broader issuer taxonomy tests |
| Advanced Metrics | SEC calculations survive Finnhub failure | Missing metrics show `—` | Sector-specific ratio expansion |
| Earnings | SEC actuals; optional estimates | Different bases disclosed | Add split-normalized comparison dataset |
| Call Research | Graceful unavailable state | Optional transcript provider | Transcript provider and coverage monitoring |
| SEC Filings | Direct official filing links | SEC EDGAR | No launch blocker identified |
| Institutional | FINRA works without Finnhub | Delayed aggregate activity | Configure optional ownership feed |
| Compare | Existing comparison workflow | Yahoo + optional fundamentals | Apply LensScore comparison later |
| Screener | Existing provider-dependent workflow | Coverage can vary | Replace hard provider dependency or clearly gate it |
| Projection Lab | Assumption model remains distinct from observed data | User assumptions are labeled | Continue simplifying dense controls |
| Planner | Functionally separate from LensScore | User-entered data | No LensScore dependency required |
| Learn | Thesis-oriented workflow | Editorial/user data | Continue tightening lesson hierarchy |
| Saved/Workspace | Persistent research records | User data | Add LensScore snapshot/version to saved records |
| Auth/Account | Existing flows retained | Application database | Production email/Stripe configuration verification |
| Static/legal/data pages | Shared light/dark system and landmarks | Methodology updated | Legal review before broad launch |
| Stock acquisition pages | Theme-safe and live-price capable | Finnhub or Yahoo chart | Validate production canonical host |

## Competitive positioning

The product should not try to be a smaller copy of TradingView, Koyfin, Finviz, or a creator-specific indicator.

| Product pattern | What users value | Implied Lens response |
|---|---|---|
| TradingView | Best-in-class chart interaction and indicator depth | Keep robust technical evidence, but make LensSetup the readable conclusion |
| Koyfin / TIKR | Dense professional financial data and comparisons | Keep SEC-backed evidence and transparent calculations; avoid unexplained data walls |
| Finviz | Fast scanning and screening | Eventually add LensValue/LensSetup filters to the screener |
| Simply Wall St | Visual explanations for non-professionals | Use plain-English causal explanations without hiding assumptions |
| Morningstar-style ratings | A memorable, comparable grade | Own LensScore, but expose model version, confidence, evidence, and guardrails |
| Premium non-finance tools | One obvious job, progressive disclosure, excellent states | Make LensScore the entry point; reveal raw metrics only when the user asks why |

The differentiator is:

> A transparent bridge between long-term business value and near-term price setup, with both lenses independently usable and an explicit signal only when they agree.

## Launch blockers and required release gates

### Blockers before public launch

1. Configure a valid production `SEC_USER_AGENT`.
2. Configure and verify the desired optional Finnhub plan, or remove features whose only value depends on it.
3. Confirm `APP_URL`, secure `SESSION_SECRET`, production database, Resend sender/domain, and Stripe secrets.
4. Add provider monitoring for Yahoo, SEC, FINRA, and Finnhub with alerting and coverage dashboards.
5. Complete iPhone Safari and Android Chrome checks at representative narrow widths, plus tablet checks at approximately 768 px.
6. Run accessibility checks with keyboard-only navigation and a screen reader.
7. Obtain or build the point-in-time dataset before marketing LensValue, LensScore, or Golden Lens as historically predictive.
8. Have financial methodology and consumer-facing language reviewed for regulatory and legal risk.

### Required engineering gates

- `npm run check`
- `npm test`
- Production configuration validation
- Public route smoke test
- Authenticated Pro route smoke test
- Provider-degradation test
- Light/dark screenshots at desktop and mobile widths
- No horizontal page overflow
- No uncaught browser errors
- No synthetic substitution in a market, financial, earnings, or score payload
- Calibration artifact generated with the same model version being deployed

## Recommended next implementation sequence

### Phase 1 — Finish launch hardening

- Complete the release gates above.
- Store LensScore model version and evidence timestamp with saved analyses.
- Add a visible provider-health state for partially unavailable optional data.
- Add analytics for LensScore search, evidence expansion, scenario use, and saved thesis conversion.

### Phase 2 — Validate and tune

- Build a point-in-time fundamentals warehouse.
- Expand to a survivorship-bias-free universe.
- Measure returns, drawdowns, calibration, score monotonicity, turnover, and sector effects.
- Tune weights only on a training set; reserve untouched validation and test periods.
- Publish limitations and validation dates in the product.

### Phase 3 — Make LensScore the product spine

- Add LensValue and LensSetup columns/filters to the screener.
- Add LensScore deltas to watchlists and saved research.
- Add score-history charts with model-version boundaries.
- Add side-by-side LensScore decomposition in Compare.
- Add alerts for Golden Lens activation and meaningful component changes.

## Do not do

- Do not market 10/10 as a guarantee or a literal instruction to buy.
- Do not make price reduction alone override deteriorating company facts.
- Do not use current fundamentals to backfill old dates.
- Do not silently substitute generated or stale values.
- Do not relabel OTC aggregate activity as real-time dark-pool flow.
- Do not combine LensValue and LensSetup so tightly that swing traders or long-term investors cannot use them independently.
- Do not add more indicators unless they improve calibration or explanation.

## Main files for the next engineer or AI agent

- `IMPLIED_LENS_FULL_AUDIT_2026-07-22.md` — original full product/code/competitive audit.
- `IMPLIED_LENS_IMPLEMENTATION_HANDOFF_2026-07-24.md` — current state and remaining launch work.
- `lib/stock-research.js` — canonical live research and provenance.
- `labs/lens-score/lens-score-engine.js` — model and guardrails.
- `labs/lens-score/app.js` — LensScore UI behavior.
- `labs/lens-score/index.html` and `labs/lens-score/styles.css` — LensScore interface.
- `routes/lens-score.js` — production API/page wiring.
- `routes/financials.js` — statements, metrics, earnings, ownership, and FINRA routes.
- `lib/lens-calibration.js` — no-lookahead helpers.
- `scripts/calibrate-lens-score.js` — calibration runner.
- `public/lens-calibration.json` — latest diagnostic artifact.
- `public/data-sources.html` — user-facing methodology.
- `test/lens-score-engine.test.js` — model behavior contract.
- `test/lens-score-lab-route.test.js` — public/dev route contract.

## Final readiness assessment

The core product idea is now clear and technically present. LensScore is understandable, brandable, responsive to valuation, independent across time horizons, and grounded in live reported evidence. The most serious previous trust defects—synthetic-looking fallbacks, missing provenance, stale-period ratio mixing, misleading dark-pool language, and a score that barely reacted to a halved entry price—have been corrected locally.

The remaining gap is not another redesign. It is disciplined post-deployment monitoring and evidence. Production browser and mobile-viewport checks pass; keep the live feature monitored and market the decision framework, but not historical predictive performance until the full point-in-time validation exists.
