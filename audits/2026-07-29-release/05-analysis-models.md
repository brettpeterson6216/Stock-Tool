# 05 — Analysis models

## Scope

Projection, comparison, screener, valuation/EPS workflows, shared ticker context, assumptions, sensitivity controls, explanations, and mobile action layout.

## Findings

### Fixed: Projection mislabeled chart-range performance as the current move

The Projection header displayed `+127 (+60.07%)` for AAPL while Research correctly displayed the current session move of `-1.89 (-0.56%)`. The calculation preferred `chartPreviousClose`, which can represent the beginning of the selected historical range.

Correction:

- Current move now prefers `previousClose`.
- Application state is the secondary fallback.
- The chart-range baseline is used only when no true previous-session value exists.

Browser re-test:

- Projection: `-1.89 (-0.56%)`
- Research: `Today -1.89 (-0.56%)`

### Fixed: mobile model controls

Projection primary actions and templates, comparison input, and the shared research shell now meet the interaction floor and no longer squeeze the search field.

### Passed: projection transparency

The builder exposes inputs, templates, sensitivity, checklist, evidence, and explanation rather than outputting an unexplained target. This is the correct premium-product direction: one decision surface with inspectable assumptions.

## Re-audit

- Comparison and screener loading retain race-safe contracts.
- Screener exposes a live-provider fallback.
- Projection and Research share the same ticker context.
- Both audited themes and viewport sizes passed without non-finite output or layout overflow.

