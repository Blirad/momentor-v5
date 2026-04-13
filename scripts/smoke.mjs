#!/usr/bin/env node
// Pre-deploy smoke runner. Fails fast if the static bundle is obviously broken
// (missing files, broken manifest, oversized HTML). Runs in CI after tests.

import { readFile, stat } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { resolve, dirname } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, '..');

const REQUIRED_FILES = ['index.html', 'manifest.json', 'sw.js', 'api/verify-order.js'];

// Rough size guardrail — if index.html balloons past this, it's probably wrong.
const MAX_HTML_BYTES = 2_000_000;

let failed = 0;
const log = {
  ok: (msg) => console.log(`  \u2713 ${msg}`),
  fail: (msg) => {
    console.error(`  \u2717 ${msg}`);
    failed++;
  },
};

for (const rel of REQUIRED_FILES) {
  try {
    await stat(resolve(ROOT, rel));
    log.ok(`${rel} exists`);
  } catch {
    log.fail(`${rel} is missing`);
  }
}

try {
  const s = await stat(resolve(ROOT, 'index.html'));
  if (s.size > MAX_HTML_BYTES) {
    log.fail(`index.html is ${s.size} bytes (> ${MAX_HTML_BYTES})`);
  } else {
    log.ok(`index.html size OK (${(s.size / 1024).toFixed(1)} KB)`);
  }
} catch {
  /* handled above */
}

try {
  const manifest = JSON.parse(await readFile(resolve(ROOT, 'manifest.json'), 'utf8'));
  if (!manifest.name || !manifest.start_url) {
    log.fail('manifest.json missing required fields');
  } else {
    log.ok('manifest.json parses with required fields');
  }
} catch (err) {
  log.fail(`manifest.json parse error: ${err.message}`);
}

if (failed > 0) {
  console.error(`\n  Smoke check failed (${failed} issue${failed === 1 ? '' : 's'}).`);
  process.exit(1);
}
console.log('\n  All smoke checks passed.');
