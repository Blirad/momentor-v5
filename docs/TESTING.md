# Testing

## Philosophy

- Tests exist to catch regressions that would otherwise ship to users.
- Prefer tests that are **fast, deterministic, and close to real usage**.
- Don't test the framework — test our logic.

## Tiers

### Unit (`tests/unit/`)

Pure logic and serverless handlers. Stub `global.fetch` and `process.env`.
No network, no filesystem (beyond fixture reads).

Run: `npm run test:unit`

### Smoke (`tests/smoke/`)

Invariants on the static bundle that, if violated, indicate a broken
deploy. Fast (reads files, asserts on strings). Runs on every PR.

Run: `npm run test:smoke`

### Pre-deploy (`scripts/smoke.mjs`)

Last-mile sanity check before a deploy: required files exist, sizes are
plausible, manifest parses. Not a replacement for smoke tests — it
catches different classes of breakage (missing files, oversized bundles).

Run: `npm run smoke`

## Runner

Node's built-in test runner (`node --test`). No `jest`, no `vitest`, no
deps. Keeps install footprint near zero.

## Patterns

### Stubbing fetch in a handler

```js
const ORIGINAL_FETCH = global.fetch;
beforeEach(() => { global.fetch = async () => ({ ok: true, json: async () => ({}) }); });
afterEach(() => { global.fetch = ORIGINAL_FETCH; });
```

### Mocking the Vercel req/res pair

Use `tests/helpers/mock-res.mjs` — it implements the narrow slice of the
response API that serverless handlers actually call (`status`, `json`,
`setHeader`, `end`).

## When to add what

| You changed…                      | Add this                                    |
| --------------------------------- | ------------------------------------------- |
| `api/verify-order.js`             | Unit test covering the new branch           |
| Anything in `index.html` head/PWA | Smoke test asserting the new contract       |
| A new API route                   | Unit tests + extend `REQUIRED_FILES` list   |
| Extracted a module into `src/`    | Unit tests mirroring the module             |

## E2E

Not set up. When the product stops fitting in a single HTML file, add
Playwright in a separate PR. Until then, E2E is "browse the preview URL
on a phone".
