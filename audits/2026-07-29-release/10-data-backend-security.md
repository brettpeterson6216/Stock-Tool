# 10 — Data, backend, and security

## Scope

Quote freshness and provenance, provider health, range validation, quotas, sessions, passwords, email verification, billing protection, admin operations, analytics validation, HTTP caching/compression, CSRF, and dependency health.

## Findings

### Passed: live quote sample

AAPL, NVDA, MSFT, TSLA, AMZN, META, GOOGL, and SPY returned:

- provider: Yahoo Finance
- `synthetic: false`
- current market timestamp at audit time

This verifies the exercised quote path did not silently substitute fabricated values.

### Passed: provider and quota behavior

- Provider health exposes an observation snapshot and identifies stale observations.
- Malformed symbols are rejected before provider contact.
- Unsupported ranges/intervals are normalized to the allowlist.
- Free quota counts distinct symbols, permits reopening an already-counted symbol, and locks after the configured limit.

### Passed: security and account contracts

Coverage includes correct and incorrect CSRF handling, session rotation after password change, case-insensitive usernames, field limits, verification token validity/expiry/rate limits, admin-secret header policy, protected checkout/portal creation, stable anonymous analytics identity, and event allowlisting.

### Passed: dependency audit

`npm audit --audit-level=low` reports zero known vulnerabilities for the installed dependency tree.

## External-service boundary

Automated tests do not send email when `RESEND_API_KEY` is absent and do not create live Stripe purchases. They verify failure/success contracts around those integrations. Production delivery and billing remain external-service operations that require live credentials and observability.

