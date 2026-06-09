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

## Frontend structure

The legacy application remains in `index.html`. New cross-cutting product behavior lives in:

- `public/product-system.js`: chart persistence, data trust, education context, onboarding, and build identity.
- `public/product-system.css`: styles for those product systems.

Keep new cross-cutting features in external modules instead of adding more inline script or style blocks.
