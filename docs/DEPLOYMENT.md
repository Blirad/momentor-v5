# Deployment

## Hosting

Vercel. The repo is a Vercel project — pushes to `main` auto-deploy to
production. Pushes to any other branch get a preview deploy.

## Configuration

`vercel.json` pins:

- Node 20.x runtime for `api/*.js`
- 256 MB memory, 10s max duration
- Security headers (`X-Content-Type-Options`, `X-Frame-Options`,
  `Referrer-Policy`, `Permissions-Policy`)
- `no-store` on `/api/*` and `sw.js` (service worker must always be fresh)
- Clean URLs, no trailing slash

Changes to `vercel.json` take effect on the next deploy.

## Environment variables

Set in the Vercel dashboard → Project → Settings → Environment Variables.
Mirror them in `.env.local` for local dev (copy from `.env.example`).

| Name              | Where          | Purpose                                          |
| ----------------- | -------------- | ------------------------------------------------ |
| `LS_API_KEY`      | Production     | LemonSqueezy API key — reads order status        |
| `LS_TOKEN_SECRET` | Prod + Preview | HMAC secret for the client access token          |

**Rotate `LS_TOKEN_SECRET` if leaked** — all outstanding tokens invalidate
on the next hourly rotation window (see `signToken` in `verify-order.js`).

## Promotion flow

1. Open PR → Vercel deploys a preview.
2. Smoke-test the preview URL (mobile viewport + desktop).
3. Merge to `main` → production deploys.
4. Hard-refresh or bump `CACHE` in `sw.js` if you need users to see
   changes instantly.

## Rollback

Vercel dashboard → Deployments → promote a previous successful deployment.
No git operation required. Afterwards, open a PR that reverts the bad
commit so `main` reflects what's live.

## Custom domain

`momentor.app` is the production origin (see meta OG tags in
`index.html`). DNS lives outside this repo — ask an admin if it needs to
change.
