# CLAUDE.md

This file gives any Claude session working in this repo the context and
rules it needs. Read this before making changes.

## What this project is

**Momentor** — a Four Pillars (Saju) birth-chart reading web app. Deployed
as a PWA on Vercel at `momentor.app`. Production traffic exists. Be
careful.

## Stack (and what NOT to change)

- **Frontend**: single-file `index.html` (~5k lines, vanilla HTML/CSS/JS)
- **API**: Vercel serverless function in `api/verify-order.js` (Node 20.x ESM)
- **PWA**: `manifest.json` + `sw.js`
- **Hosting**: Vercel (auto-deploy from `main`)
- **No build step. No bundler. No framework.** This is intentional.

## Hard rules

1. **Never run Prettier/ESLint auto-fix on `index.html`.** It's excluded
   from formatters for a reason (noisy diffs on a live product). Only
   modify it to implement real product changes.
2. **Never commit secrets.** `LS_API_KEY` and `LS_TOKEN_SECRET` live in
   Vercel env only. `.env.local` is gitignored.
3. **Never force-push to `main`.**
4. **Never introduce a bundler** (Webpack/Vite/esbuild) without explicit
   approval. "No build step" is a design property, not a gap.
5. **Never add runtime dependencies** to `package.json` without explicit
   approval. Dev-deps (lint/test tooling) are fine.
6. **Bump the `CACHE` constant in `sw.js`** whenever you change `index.html`
   materially — otherwise users keep seeing the old cached version.

## Before committing

```bash
npm run verify   # format:check → lint → test → smoke
```

All four must pass. CI enforces the same gate.

## Layout

```
api/                  Vercel serverless (Node 20.x ESM)
docs/                 ARCHITECTURE · DEVELOPMENT · DEPLOYMENT · TESTING
scripts/              dev.mjs (static server) · smoke.mjs (pre-deploy)
src/                  reserved for future client modules
tests/
  unit/               handler logic, stubbed I/O (node:test)
  smoke/              static-bundle invariants
  helpers/            req/res mocks
index.html            the product
manifest.json · sw.js · vercel.json
```

## Quick commands

| Command            | What it does                                          |
| ------------------ | ----------------------------------------------------- |
| `npm run dev`      | Zero-dep static server on `:3000`                     |
| `npm run dev:vercel` | Full Vercel parity (needs `vercel` CLI)             |
| `npm test`         | 16 tests (7 unit + 9 smoke), node:test               |
| `npm run smoke`    | Pre-deploy bundle check                               |
| `npm run lint`     | ESLint on `api/`, `scripts/`, `tests/`, `sw.js`       |
| `npm run format`   | Prettier write (skips `index.html`)                   |
| `npm run verify`   | All of the above, in CI order                         |

## Deployment

- Push to `main` → Vercel auto-deploys to production.
- Any other branch → Vercel auto-deploys a preview URL.
- Rollback via Vercel dashboard (promote previous deployment).
- Full deploy playbook: `docs/DEPLOYMENT.md`.

## When you're unsure

- Architecture questions → `docs/ARCHITECTURE.md`
- Local setup questions → `docs/DEVELOPMENT.md`
- Testing questions → `docs/TESTING.md`
- Everything else → ask the user before making assumptions.
