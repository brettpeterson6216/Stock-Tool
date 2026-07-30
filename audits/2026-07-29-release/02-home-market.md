# 02 — Home and Market

## Scope

Landing hierarchy, introductory product communication, watchlist entry, market overview, index cards, movers, time-range controls, responsive chart surfaces, and live quote provenance.

## Findings

### Passed: landing page hierarchy

The release candidate opens with a beginner-readable explanation of the product before exposing the denser market workflow. The hero visual is a real CSS-built product illustration rather than a false screenshot. No missing image placeholder remained in the hero during the re-audit.

### Fixed: small mobile market controls

Market range controls, mover tabs, and watchlist add/empty-state actions were operational but had undersized mobile hit areas.

Correction:

- Applied the shared 44-pixel interaction floor.
- Preserved the current visual hierarchy and chart space.

### Passed: market data presentation

The Market page loaded eight watch cards plus S&P 500, Nasdaq, and Dow overview values. The 5D range interaction updated without a browser error. Positive and negative values retained vivid green/red semantics in both themes.

## Re-audit

- Desktop/light and mobile/dark passed without overflow, broken images, unnamed buttons, duplicate IDs, or non-finite visible values.
- Quote sample for AAPL, NVDA, MSFT, TSLA, AMZN, META, GOOGL, and SPY returned live Yahoo Finance provenance, `synthetic: false`, and a current market timestamp during the audit.
- Market canvases rendered and remained inside their cards at both sizes.

## Follow-up observation

Public-market availability still depends on upstream provider health. The product exposes provider provenance and health state so a vendor outage is not silently presented as fresh data.

