# Premium research sweep — September 8, 2026

Implemented on `codex/premium-research-sweep`, starting from `13e928c`. The existing Express application and Render deployment model are retained. These changes are prepared locally; this work did not deploy to production.

## Presentation

- One cream, charcoal, and gold palette across the dashboard, research tools, account pages, and LensScore.
- System typography, quieter surfaces, readable data tables, restrained chart grids, visible keyboard focus, and reduced-motion support.
- A clearer public introduction and company search, four supported feature descriptions, and a member dashboard with a primary market chart and compact supporting panels.
- Mobile layouts have one header, correctly ordered introductory content, chart controls inside the chart card, usable menus, and consistent light/dark navigation.
- Pricing opens the actual plan chooser. Trial links retain plan-selection intent. Watchlists opens the watchlist editor. Research and LensScore have consistent labels.

## Delivery and runtime

The main page's 22 local stylesheet requests are combined into one bundle. Compressed with Node's default gzip for a like-for-like comparison:

| Measure | Before | After |
| --- | ---: | ---: |
| Stylesheet requests | 22 | 1 |
| Total gzip CSS bytes | 236,104 | 149,110 |

This is a 36.8% reduction in compressed CSS, including the new theme. It is a payload measurement, not a claim about measured production load times.

- Seven generated CSS bundles cover the 15 page/template sources. Original ordered stylesheet links remain the source of truth; relative font and image URLs are rebased. CI verifies generated output.
- Named `.html` aliases now receive the same deployment-stamped assets as their clean URLs.
- Removed unused font preloads and duplicate session requests. Hidden landing, legacy market, and member dashboard surfaces defer their requests. Provider polling runs only while the relevant panel and browser tab are visible.
- Research enhancement scripts now execute after the application controller they extend. This fixes silently missing chart/workspace/navigation behavior during startup.
- Removed chart observers and event handlers on disposal. Late technical reads and price zones cannot replace a newer company's data. Missing prices no longer become zero-price candles.
- Monthly index charts request daily closes, legend percentages follow the visible range, and theme changes recolor existing charts.
- Company and range remain in research URLs. Valuation history uses statement reporting years instead of calendar-year guesses.
- Updated vulnerable transitive dependencies; the npm dependency audit reports no known vulnerabilities.

## Validation

- `npm run check:styles`, syntax checks, and all 234 automated tests pass.
- Added regression coverage for initialization order, slow chart installation, missing prices, chart disposal, stale responses, CSS delivery, retained company links, reporting years, and direct watchlist navigation.
- Browser checks covered the public introduction, member dashboard, chart timeframe and theme switching, AAPL research and financials, projection horizon recalculation, valuation, workspace tabs, provider status, LensScore, pricing, login, and mobile menu/keyboard behavior.
- Representative desktop and 390px mobile layouts were inspected for overflow and readability. Clean URLs and representative `.html` aliases were verified with stamped bundles.

The local preview uses a disposable test account/database. Yahoo Finance and SEC financial statements were exercised. Local Finnhub credentials are unavailable, so provider-dependent news and some market features could only be checked for their unavailable states. Billing purchases, email delivery, and production performance still require the deployed environment; no live purchase or production account change was made.

## Maintaining the styles

Edit source CSS, then run `npm run build:styles`. Commit `public/bundles/` and `lib/style-bundles.json` with the source changes. `npm run check:styles` catches stale generated output. The `premium` layer owns shared presentation; the `heritage` layer preserves the existing stylesheet order.
