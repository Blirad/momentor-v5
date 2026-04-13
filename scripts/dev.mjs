#!/usr/bin/env node
// Zero-dependency static dev server for local iteration on index.html.
// For full serverless-function parity, use `npm run dev:vercel` (requires
// the Vercel CLI).
//
// Usage: npm run dev        # default port 3000
//        PORT=4000 npm run dev

import http from 'node:http';
import { readFile, stat } from 'node:fs/promises';
import { extname, join, normalize, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = fileURLToPath(new URL('.', import.meta.url));
const ROOT = resolve(__dirname, '..');
const PORT = Number(process.env.PORT) || 3000;

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.mjs': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif': 'image/gif',
  '.webp': 'image/webp',
  '.ico': 'image/x-icon',
  '.webmanifest': 'application/manifest+json',
};

function safeJoin(root, url) {
  // Strip query string, decode, and prevent path traversal.
  const clean = decodeURIComponent(url.split('?')[0]);
  const joined = normalize(join(root, clean));
  if (!joined.startsWith(root)) return null;
  return joined;
}

async function resolveFile(path) {
  try {
    const s = await stat(path);
    if (s.isDirectory()) return resolveFile(join(path, 'index.html'));
    return path;
  } catch {
    return null;
  }
}

const server = http.createServer(async (req, res) => {
  const reqPath = req.url === '/' ? '/index.html' : req.url;

  // API stub — real deploy uses Vercel serverless.
  if (reqPath.startsWith('/api/')) {
    res.writeHead(501, { 'content-type': 'application/json' });
    res.end(
      JSON.stringify({
        ok: false,
        error: 'API routes are served by Vercel. Run `npm run dev:vercel` instead.',
      }),
    );
    return;
  }

  const path = safeJoin(ROOT, reqPath);
  if (!path) {
    res.writeHead(400).end('Bad request');
    return;
  }

  const file = await resolveFile(path);
  if (!file) {
    res.writeHead(404, { 'content-type': 'text/plain' }).end('Not found');
    return;
  }

  try {
    const body = await readFile(file);
    const type = MIME[extname(file).toLowerCase()] || 'application/octet-stream';
    res.writeHead(200, {
      'content-type': type,
      'cache-control': 'no-cache',
    });
    res.end(body);
  } catch (err) {
    console.error('dev-server error:', err);
    res.writeHead(500).end('Internal error');
  }
});

server.listen(PORT, () => {
  console.log(`\n  Momentor dev server → http://localhost:${PORT}\n`);
});
