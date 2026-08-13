# Implied Lens

Professional stock-analysis platform built with Node.js, Express, Chart.js, and libSQL/Turso.

## Local verification

```bash
npm ci
npm run check
npm test
npm audit --audit-level=moderate
```

## Deployment checks

- `GET /healthz` verifies the running build and database connection.
- `GET /readyz` verifies launch-critical database, market-data, session, billing, email, and public-URL configuration without exposing secrets.
- `GET /api/version` exposes the deployed commit and startup time without caching.
- Every response includes `X-ImpliedLens-Build`.
- GitHub Actions runs syntax checks, smoke tests, and the dependency audit on pushes and pull requests.

Render should use `/healthz` as its health-check path and deploy from `main`.

After a push, verify the exact live commit:

```bash
npm run verify:deploy -- 7b1bd95
```

## Stripe trial and promo-code offers

Checkout starts Pro subscriptions with a 7-day free trial and allows Stripe promotion codes.

To run a `$0.99` paid-month sale, create a Stripe coupon/promotion code that reduces a monthly invoice to `$0.99`, then give the promotion code to the customer. They can enter it directly in Stripe Checkout. For example, if `STRIPE_PRICE_MONTHLY` is `$7.99/month`, create an `amount_off=$7.00` coupon and attach a customer-facing promotion code.

Keep `STRIPE_PRICE_MONTHLY`, `STRIPE_PRICE_ANNUAL`, `STRIPE_SECRET_KEY`, and `STRIPE_WEBHOOK_SECRET` set in Render.

## Frontend structure

`index.html` owns application markup. Executable behavior is external:

- `public/theme-bootstrap.js`: pre-render theme and browser chrome.
- `public/app-navigation.js`: global shell, auth bootstrap, navigation, and account UI.
- `public/app-legacy.js`: extracted legacy application controller and the next incremental migration boundary.
- `public/model-math.js`: pure projection and valuation formulas.
- `public/product-system.js`: chart persistence, data trust, education context, onboarding, and build identity.
- `public/product-system.css`: styles for those product systems.

Do not add executable inline scripts. Put domain behavior in the narrowest owned module, and keep financial math DOM-free and independently tested. See `docs/PRODUCT_ARCHITECTURE.md` and `docs/PRODUCTION_AUDIT_2026-08-12.md`.
