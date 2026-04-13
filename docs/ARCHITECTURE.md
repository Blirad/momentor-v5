# Architecture

## Shape today

```
┌─────────────────────────────────────────────────────────────┐
│ Browser                                                     │
│                                                             │
│   index.html  ── inline CSS/JS, Google Fonts, PWA shell     │
│       │                                                     │
│       ├── sw.js          (cache-first service worker)       │
│       └── fetch()        ──────────────┐                    │
└────────────────────────────────────────┼────────────────────┘
                                         ▼
                              ┌──────────────────────┐
                              │ Vercel Edge          │
                              │   api/verify-order.js│
                              └──────────┬───────────┘
                                         │
                                         ▼
                              ┌──────────────────────┐
                              │ LemonSqueezy API     │
                              │   (order status)     │
                              └──────────────────────┘
```

- The **product surface** is one 5k-line `index.html`. All UI, all state,
  all Saju calculation logic lives there today.
- **PWA**: `manifest.json` declares the install shell; `sw.js` implements
  cache-first static caching (so the app is available offline after first
  load).
- **Single API route**: `POST /api/verify-order`. Takes a LemonSqueezy
  `orderId`, checks paid status, returns an HMAC-signed token the client
  uses to unlock paid surfaces.

## Why a single HTML file

Historical: fast iteration during product-market-fit search, zero build
cost, trivial Vercel deploy, no bundler skew. The tradeoff is diff noise
and the inability to unit-test client logic.

## Modularization roadmap

When the pain from the monolith exceeds the pain of refactoring, split in
this order:

1. **Extract Saju engine** → `src/saju/` (pure functions: calendar
   conversions, pillar derivation, element mapping). These are the most
   valuable to unit-test.
2. **Extract i18n copy** → `src/i18n/` (currently inline strings).
3. **Extract components** → `src/components/` (form sections, accordions,
   modals). Start with the ones that change most often.
4. **Introduce a minimal bundler** (esbuild) only once there are enough
   modules to justify it. Keep `index.html` as the entrypoint.

Do not rewrite in a framework as the first step. Split first, evaluate
after.

## Boundaries we care about

- **Paid vs. free**: `api/verify-order.js` is the only trusted boundary.
  Client-side paywall gating is UX, not security.
- **Secrets**: `LS_API_KEY` and `LS_TOKEN_SECRET` never leave the server.
  The client only ever sees the signed token.
- **PWA cache**: `sw.js` caches `/` and `/index.html`. API responses are
  always served `no-store`. Bump `CACHE` constant in `sw.js` when shipping
  a breaking change to the shell.

## Non-goals

- SSR.
- A JS framework.
- A database — order state is owned by LemonSqueezy.
