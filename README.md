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
- `GET /api/version` exposes the deployed commit and startup time without caching.
- Every response includes `X-ImpliedLens-Build`.
- GitHub Actions runs syntax checks, smoke tests, and the dependency audit on pushes and pull requests.

Render should use `/healthz` as its health-check path and deploy from `main`.

After a push, verify the exact live commit:

```bash
npm run verify:deploy -- 7b1bd95
```

## Stripe first-month offer

Monthly Checkout is configured to require a one-time Stripe discount before it can launch the advertised `$0.99` first-month offer.

In Stripe, create either:

- A coupon with `duration=once` that reduces the first monthly invoice to `$0.99`.
- A promotion code backed by that same one-time coupon.

For example, if `STRIPE_PRICE_MONTHLY` is `$7.99/month`, create an `amount_off=$7.00` coupon. Then set one of these environment variables in Render:

```bash
STRIPE_FIRST_MONTH_COUPON=coupon_...
# or
STRIPE_FIRST_MONTH_PROMOTION_CODE=promo_...
```

Keep `STRIPE_PRICE_MONTHLY`, `STRIPE_PRICE_ANNUAL`, `STRIPE_SECRET_KEY`, and `STRIPE_WEBHOOK_SECRET` set as before.

## Frontend structure

The legacy application remains in `index.html`. New cross-cutting product behavior lives in:

- `public/product-system.js`: chart persistence, data trust, education context, onboarding, and build identity.
- `public/product-system.css`: styles for those product systems.

Keep new cross-cutting features in external modules instead of adding more inline script or style blocks.
