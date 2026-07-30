# 11 — Integrated validation

## Browser matrices

Two independent route matrices were run:

- desktop/light at 1440 × 900: 28 routes
- mobile/dark at 390 × 844: 28 routes

Regions included Home, Market, Research, chart and company-data tabs, comparison, screener, Projection, EPS/value tools, Planner, Learn, Saved, Workspace, LensScore, public/editorial pages, calculator, policy pages, and a curated ticker landing route.

Across the completed matrices:

- no page-level horizontal overflow;
- no broken images;
- no duplicate element IDs;
- no unnamed buttons;
- no visible `NaN` or `undefined`;
- no theme mismatch;
- no remaining audited control below the mobile interaction threshold.

## Functional browser checks

- Live Research quote and charts: passed.
- Market overview, watch cards, and range control: passed.
- Guest save, Saved listing, and reopen: passed.
- LensScore load and changed-price scenario: passed.
- Wealth Planner finite scenario calculation/chart: passed.
- Compound calculator finite scenario calculation/chart: passed.
- Projection current-move correction: passed and matched Research.
- Shared public navigation: passed.

## Automated release gates

- JavaScript syntax/check suite: passed.
- Complete Node test suite: 174 passed, 0 failed.
- Dependency vulnerability audit: 0 known vulnerabilities.
- Git whitespace validation: passed.

The deployed commit is recorded in the final release handoff after the production build is observed.

## Honest residual risks

- Upstream market-data, filing, transcript, email, and billing providers can fail independently of the application.
- Private Pro data depth depends on production credentials and vendor entitlements.
- LensScore requires continuing historical/out-of-sample monitoring; passing software tests does not validate future investment performance.
- No audit can prove absence of every defect. This release uses repeatable checks and explicit provider states instead of claiming literal perfection.
