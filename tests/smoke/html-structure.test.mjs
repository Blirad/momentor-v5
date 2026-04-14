// Smoke tests: basic invariants on index.html that, if violated,
// almost certainly indicate a broken deploy. Fast and dependency-free.

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, '../..');

const html = await readFile(resolve(ROOT, 'index.html'), 'utf8');

describe('index.html smoke', () => {
  test('has a valid doctype', () => {
    assert.match(html.slice(0, 200), /<!DOCTYPE html>/i);
  });

  test('declares viewport meta (mobile-first contract)', () => {
    assert.match(html, /<meta\s+name="viewport"[^>]*width=device-width/i);
  });

  test('references the manifest', () => {
    assert.match(html, /<link[^>]*rel="manifest"[^>]*href="\/manifest\.json"/i);
  });

  test('sets theme-color for PWA shell', () => {
    assert.match(html, /<meta[^>]*name="theme-color"/i);
  });

  test('includes OpenGraph title/description', () => {
    assert.match(html, /property="og:title"/);
    assert.match(html, /property="og:description"/);
  });

  test('has balanced <html> and <body> tags', () => {
    const htmlOpen = (html.match(/<html\b/gi) || []).length;
    const htmlClose = (html.match(/<\/html>/gi) || []).length;
    const bodyOpen = (html.match(/<body\b/gi) || []).length;
    const bodyClose = (html.match(/<\/body>/gi) || []).length;
    assert.equal(htmlOpen, 1);
    assert.equal(htmlClose, 1);
    assert.equal(bodyOpen, 1);
    assert.equal(bodyClose, 1);
  });

  test('does not leak obvious secrets', () => {
    // Crude but effective — catches accidental API keys / bearer tokens.
    assert.doesNotMatch(html, /sk_live_[A-Za-z0-9]{16,}/);
    assert.doesNotMatch(html, /LS_API_KEY\s*=\s*["'][^"']+["']/);
    assert.doesNotMatch(html, /Bearer\s+[A-Za-z0-9]{32,}/);
  });
});

describe('manifest.json smoke', () => {
  test('is valid JSON with required PWA fields', async () => {
    const raw = await readFile(resolve(ROOT, 'manifest.json'), 'utf8');
    const manifest = JSON.parse(raw);
    assert.ok(manifest.name, 'name is required');
    assert.ok(manifest.start_url, 'start_url is required');
    assert.ok(manifest.display, 'display is required');
    assert.ok(Array.isArray(manifest.icons) && manifest.icons.length > 0, 'icons required');
  });
});

describe('sw.js smoke', () => {
  test('registers install/activate/fetch handlers', async () => {
    const sw = await readFile(resolve(ROOT, 'sw.js'), 'utf8');
    assert.match(sw, /addEventListener\(\s*['"]install['"]/);
    assert.match(sw, /addEventListener\(\s*['"]activate['"]/);
    assert.match(sw, /addEventListener\(\s*['"]fetch['"]/);
  });
});
