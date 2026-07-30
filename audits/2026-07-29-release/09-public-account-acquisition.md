# 09 — Public, account, and acquisition pages

## Scope

About, blog, research process, data sources, privacy, terms, compound calculator, curated ticker landing pages, login, signup, reset password, metadata, social assets, sitemap, and responsive continuity.

## Findings

### Fixed: fragmented public navigation

All public product regions now use the shared nine-destination navigation and keyboard skip link. The prior “Back to platform” bar is hidden.

### Fixed: account canonical metadata

Login, signup, and reset-password pages previously reused incorrect canonical metadata. Each now points to its own route while remaining `noindex, nofollow`.

The reset-password page’s duplicate inline favicon declaration was removed.

### Passed: acquisition surface contracts

- Public brand pages return successfully.
- Curated ticker pages expose research-oriented metadata and free-allowance context.
- Uncurated tickers remain excluded from indexing.
- Malformed ticker routes are rejected rather than generating junk pages.
- Sitemap, favicon, Apple icon, manifest, and social preview are available.

## Re-audit

All audited public pages passed desktop/light and mobile/dark layout checks. The dynamic ticker-page template is also protected by a shared-navigation automated contract.

