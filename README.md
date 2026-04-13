# Momentor

Your Four Pillars (Saju) birth-chart reading. 518,400 unique combinations
calculated from the exact birth moment. Shipped as a PWA on Vercel.

## Stack

- **Frontend**: single-file `index.html` (vanilla HTML/CSS/JS, Google Fonts)
- **API**: Vercel serverless function — `api/verify-order.js` (LemonSqueezy)
- **PWA**: `manifest.json` + `sw.js` (cache-first service worker)
- **Hosting**: Vercel (static + edge functions)

Nothing compiles. The repo is deliberately build-step-free.

## Quick start

```bash
nvm use                 # Node 20.11+
npm install             # installs dev tooling (lint/format/test)
npm run dev             # zero-dep static server on :3000
npm run dev:vercel      # full serverless parity (needs `vercel` CLI)
```

Copy `.env.example` → `.env.local` and fill in `LS_API_KEY` and
`LS_TOKEN_SECRET` before exercising the order-verification endpoint.

## Daily commands

| Command              | What it does                                     |
| -------------------- | ------------------------------------------------ |
| `npm run dev`        | Local static server on `http://localhost:3000`   |
| `npm run lint`       | ESLint on `api/`, `scripts/`, `tests/`, `sw.js`  |
| `npm run format`     | Prettier write                                   |
| `npm run test`       | Unit + smoke tests (`node --test`, zero deps)    |
| `npm run smoke`      | Pre-deploy static-bundle checks                  |
| `npm run verify`     | Format-check → lint → test → smoke (CI mirror)   |

## Layout

```
.
├── api/                  Vercel serverless (Node 20.x ESM)
├── docs/                 ARCHITECTURE, DEVELOPMENT, DEPLOYMENT, TESTING
├── scripts/              dev server, smoke runner
├── src/                  reserved for future client modules
├── tests/
│   ├── unit/             handler logic, stubbed I/O
│   ├── smoke/            static-bundle invariants
│   └── helpers/          req/res mocks
├── .github/              CI workflow, PR/issue templates, CODEOWNERS
├── index.html            the product (currently monolithic)
├── manifest.json         PWA manifest
├── sw.js                 service worker
└── vercel.json           deploy config (headers, function runtime)
```

See `docs/ARCHITECTURE.md` for the bigger picture and the modularization
roadmap for `index.html`.

## Deployment

Pushes to `main` auto-deploy via Vercel. Environment variables live in the
Vercel dashboard — never commit them. See `docs/DEPLOYMENT.md`.

## Contributing

See `CONTRIBUTING.md`. Short version: branch → change → `npm run verify` →
PR with the template filled in.
