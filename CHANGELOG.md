# Changelog

All notable changes to this project are documented here. Format based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project itself
does not follow strict semver (product release cycle drives the version).

## [Unreleased]

### Added

- Engineering harness: `package.json`, ESLint flat config, Prettier,
  EditorConfig, `.nvmrc`, `.env.example`.
- `vercel.json` with security headers and function runtime pin.
- Node-native test harness (`node --test`) with unit tests for
  `api/verify-order.js` and smoke tests for the static bundle.
- Zero-dependency `scripts/dev.mjs` local static server and
  `scripts/smoke.mjs` pre-deploy checks.
- GitHub Actions CI (lint · format · test · smoke).
- PR template, bug/feature issue templates, `CODEOWNERS`.
- `docs/` scaffold: ARCHITECTURE, DEVELOPMENT, DEPLOYMENT, TESTING.

### Changed

- Expanded `.gitignore` (node_modules, envs, logs, editor junk, coverage).

## [5.0.0] — 2025

See git history for the v5 product overhaul (flow redesign, copy overhaul,
paywall fix). Tag retrospectively on first tagged release going forward.
