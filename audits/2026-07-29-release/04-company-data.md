# 04 — Company data

## Scope

Financials, metrics, earnings, SEC data, institutional ownership, earnings-call research, access gates, ticker validation, evidence dates, and unavailable-data behavior.

## Findings

### Passed: access and input contracts

Financials and SEC routes distinguish guests, free accounts, and Pro accounts. Malformed symbols are rejected before provider contact. Earnings-call research is Pro-gated and degrades to a clear unavailable state when a transcript cannot be sourced.

### Passed: evidence labeling

The product distinguishes retrieval time from underlying evidence dates. This matters for financial statements and filings, where “refreshed now” must not imply that a quarterly fact itself was published today.

### No release change required

No broken public gate, malformed-symbol bypass, or synthetic-data substitution was found in this region during the audit. UI pages remained stable in both themes and sizes.

## Re-audit

Automated integration coverage passed for:

- guest and free-user route denial;
- Pro route behavior;
- malformed ticker rejection;
- earnings-call graceful degradation;
- provider-health state.

## Test boundary

This pass did not purchase a subscription or fabricate provider responses to make private financial data appear live. Authenticated contracts were tested locally; production vendor depth remains dependent on configured credentials and account tier.

