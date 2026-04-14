# Contributing

## Branching

- `main` — always deployable. Vercel auto-deploys from here.
- `feat/*`, `fix/*`, `chore/*`, `docs/*` — short-lived feature branches.
- Claude-opened branches use the `claude/<slug>-<suffix>` convention.

Do not push to `main` directly; open a PR.

## Local setup

```bash
nvm use
npm install
cp .env.example .env.local   # fill in the blanks
npm run dev
```

## Before opening a PR

```bash
npm run verify
```

This runs `format:check → lint → test → smoke` — the same gate CI enforces.

## Commit messages

Follow the existing log style:

```
<type>: <short imperative summary>

<body — the why, not the what. Optional.>
```

Types in use: `feat`, `fix`, `hotfix`, `chore`, `docs`, `refactor`, `test`.

Examples from history:

- `feat: accordion copy applied — 10 categories × 10 stems`
- `fix: saju calc bugs (3 P0) + true solar time correction`
- `hotfix: KR copy, accordion visibility, paywall blur`

## Code style

Enforced by Prettier + ESLint. Don't fight the formatter — run `npm run
format`.

`index.html` is currently excluded from Prettier because it's the live
product and reflowing it creates noisy diffs. When we split it into
modules under `src/`, remove the exclusion.

## Reviews

- At least one codeowner approval before merge.
- Keep PRs focused. Unrelated cleanups go in a separate PR.
- Screenshots for any UI change.

## Security

- Never commit secrets. Use `.env.local` and Vercel env vars.
- If you accidentally commit a secret, rotate it immediately and notify the
  team — `git history` is public once pushed.
- The order-verification endpoint is the boundary between paid and unpaid
  surfaces. Changes to `api/verify-order.js` require extra scrutiny.
