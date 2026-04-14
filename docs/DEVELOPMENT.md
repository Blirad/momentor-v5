# Development

## Prerequisites

- Node 20.11+ (`nvm use` picks it up from `.nvmrc`)
- npm 10+

## First-time setup

```bash
nvm use
npm install
cp .env.example .env.local
# edit .env.local with real LS_API_KEY + LS_TOKEN_SECRET
```

## Run locally

### Option A — static only (fast, zero deps)

```bash
npm run dev             # http://localhost:3000
```

Hits to `/api/*` return a 501 stub. Good enough for UI iteration.

### Option B — full parity with Vercel serverless

```bash
npm i -g vercel
npm run dev:vercel
```

Runs the real `api/verify-order.js` with env vars from `.env.local`.

## Editing `index.html`

- The file is excluded from Prettier (see `.prettierignore`). Match the
  surrounding style by eye.
- Bump the `CACHE` constant in `sw.js` when you ship changes users need to
  see immediately — otherwise service-worker caching will delay them.
- Test on a real phone viewport. The product is mobile-first and the
  desktop view is an afterthought.

## Editing `api/verify-order.js`

- Write a unit test for any branch you add. See
  `tests/unit/verify-order.test.mjs` for the pattern.
- `process.env` reads should short-circuit with a 500 if the key is
  missing — never fall back to a hardcoded default in production paths.

## Running the gate

Before every PR:

```bash
npm run verify
```

This is exactly what CI runs. No surprises.

## Debugging tips

- **Service worker stuck on old content**: DevTools → Application → Service
  Workers → "Update on reload" + "Unregister". Or bump the `CACHE` name.
- **Order verification failing locally**: check `.env.local` — the most
  common cause is a missing `LS_API_KEY`.
- **CI fails on format-check but local looks fine**: run
  `npm run format` and commit the result. Line endings on Windows can
  trip this; `.editorconfig` pins `lf`.
