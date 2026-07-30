# 06 — LensScore

## Scope

Long-term Value Lens, short-term Setup Lens, combined score, Golden Lens state, price scenarios, ticker coverage, explanation, evidence freshness, technical-only behavior, and responsive controls.

## Findings

### Passed: score composition remains explainable

LensScore keeps the long-term and short-term components independently usable and combines them into the branded 0–10 decision metric. Price scenarios explain why a large price decline can improve valuation while other capped, stale, or unfavorable factors limit the total.

### Passed: live scenario workflow

AAPL loaded successfully. Changing the scenario price to $169.10 produced:

- Combined LensScore: 8.0
- Value Lens: 8.2
- Setup Lens: approximately 7.7

The interface displayed the contributing explanation rather than presenting the number as an unsupported verdict.

### Fixed: mobile action sizing

Quick tickers, company navigation, chart opening, and scenario saving now meet the shared mobile interaction floor.

## Re-audit

- Retrieval time, evidence dates, and technical-only coverage remain distinct.
- Invalid ticker states remain understandable.
- Desktop/light and mobile/dark passed without overflow, broken controls, or visible non-finite values.

## Model limitation

LensScore is a decision-support ranking, not a promise of upside or a substitute for liquidity, portfolio, or risk constraints. Historical calibration and future out-of-sample monitoring remain ongoing model-governance work, not a one-time UI release task.

