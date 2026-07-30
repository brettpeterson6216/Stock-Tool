# 03 — Research and charting

## Scope

Ticker search, quote summary, chart loading, period controls, indicators, chart expansion/annotation contracts, research guidance, data dates, and responsive workspace shell.

## Findings

### Passed: live ticker workflow

AAPL loaded at $338.19 during the audit with a displayed daily move of -$1.89 (-0.56%), eight chart canvases, Yahoo Finance provenance, and no visible error.

### Fixed: mobile research shell compression

On narrow screens the shared ticker search and adjacent actions competed for the same row, reducing readability and tap comfort.

Correction:

- Search now owns the full mobile row.
- Workspace actions move to a separate horizontally scrollable row.
- Search, onboarding, comparison, and analysis actions receive the shared mobile interaction floor.

### Passed: chart contracts

Automated checks confirm:

- timestamps and prices remain aligned during chart rebuilding;
- zoom controls and mobile gestures are exposed;
- mobile headers reserve room for controls;
- unavailable indicators explain their state;
- expanded charts support annotation tools;
- invalid ticker errors do not leak provider internals.

## Re-audit

- Desktop/light and mobile/dark showed no horizontal overflow or clipped shell controls.
- The Research “Today” change and Projection current move now agree for the same quote.
- Search, loading, and chart rendering completed without console-visible product errors in the exercised flow.

