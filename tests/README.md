# Tests

Two tiers, both built on Node's built-in test runner (`node --test`) — zero
runtime dependencies.

## Layout

```
tests/
├── unit/      Serverless handlers and pure logic, stubbed I/O
├── smoke/    Static-file invariants (HTML/manifest/sw) that must hold on every deploy
├── helpers/  Shared mocks (Vercel req/res shim, etc.)
└── fixtures/ Frozen sample data
```

## Running

```bash
npm run test         # everything
npm run test:unit    # just unit
npm run test:smoke   # just smoke
```

## Adding a unit test

Import the handler as an ES module, stub `global.fetch` / env vars, assert on
the mock `res`. See `tests/unit/verify-order.test.mjs` for the pattern.

## Adding a smoke test

Read the static file from disk, assert on invariants that would break the
product if violated. Keep these fast — they run on every PR.

## When to add an E2E test

When the cost of a regression silently shipping outweighs the cost of running
Playwright in CI. Not set up by default — open an issue first.
