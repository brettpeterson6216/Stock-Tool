# 07 — Saved and Workspace

## Scope

Guest saves, cloud-save contracts, reopening analyses, sorting/filtering, deletion validation, thesis records, review dates, portfolio positions, watchlists, portfolio guide, and review digest.

## Findings

### Passed: guest save and reopen

The complete guest browser flow worked:

1. Load AAPL Research.
2. Save the analysis.
3. Open Saved.
4. Confirm the AAPL snapshot and local-only sync explanation.
5. Load the saved item.
6. Confirm AAPL Research is restored.

This directly addresses the previously reported “saved does not work” failure mode.

### Fixed: mobile workspace controls

Saved sorting, filtering, clear, load, and delete controls plus Workspace tabs/actions now use the shared interaction floor.

### Passed: authenticated persistence contracts

Automated integration tests passed for:

- free cloud saves;
- valuation-type preservation;
- malformed save rejection;
- authenticated thesis create/update/read/delete;
- valid calendar review dates;
- portfolio positions and watchlists;
- CSRF protection;
- portfolio guide totals;
- review-digest concurrency.

## Re-audit

Saved and Workspace passed desktop/light and mobile/dark checks without overflow, duplicate IDs, unnamed buttons, or visible non-finite values.

## Test boundary

The browser walkthrough exercised guest-local persistence. Authenticated cloud persistence was verified through integration tests rather than by creating a permanent production user.

