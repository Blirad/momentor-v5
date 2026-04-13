import { test, describe, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { createMockReq, createMockRes } from '../helpers/mock-res.mjs';

// NOTE: This imports the Vercel serverless handler as a plain ESM module.
// We stub global.fetch and env vars per-test to exercise each code path.
const { default: handler } = await import('../../api/verify-order.js');

const ORIGINAL_FETCH = global.fetch;
const ORIGINAL_ENV = { ...process.env };

function stubFetch(impl) {
  global.fetch = impl;
}

describe('POST /api/verify-order', () => {
  beforeEach(() => {
    process.env.LS_API_KEY = 'test-key';
    process.env.LS_TOKEN_SECRET = 'test-secret';
  });

  afterEach(() => {
    global.fetch = ORIGINAL_FETCH;
    process.env = { ...ORIGINAL_ENV };
  });

  test('rejects non-POST methods with 405', async () => {
    const req = createMockReq({ method: 'GET' });
    const res = createMockRes();
    await handler(req, res);
    assert.equal(res.statusCode, 405);
    assert.equal(res.body.ok, false);
  });

  test('returns 400 when orderId is missing', async () => {
    const req = createMockReq({ method: 'POST', body: {} });
    const res = createMockRes();
    await handler(req, res);
    assert.equal(res.statusCode, 400);
    assert.match(res.body.error, /orderId/i);
  });

  test('returns 500 when LS_API_KEY is not configured', async () => {
    delete process.env.LS_API_KEY;
    const req = createMockReq({ method: 'POST', body: { orderId: 'abc' } });
    const res = createMockRes();
    await handler(req, res);
    assert.equal(res.statusCode, 500);
  });

  test('returns signed token for paid orders', async () => {
    stubFetch(async () => ({
      ok: true,
      json: async () => ({ data: { attributes: { status: 'paid' } } }),
    }));
    const req = createMockReq({ method: 'POST', body: { orderId: 'order-123' } });
    const res = createMockRes();
    await handler(req, res);
    assert.equal(res.statusCode, 200);
    assert.equal(res.body.ok, true);
    assert.match(res.body.token, /^[a-f0-9]{64}$/);
  });

  test('rejects non-paid orders with 403', async () => {
    stubFetch(async () => ({
      ok: true,
      json: async () => ({ data: { attributes: { status: 'pending' } } }),
    }));
    const req = createMockReq({ method: 'POST', body: { orderId: 'order-xyz' } });
    const res = createMockRes();
    await handler(req, res);
    assert.equal(res.statusCode, 403);
    assert.match(res.body.error, /pending/);
  });

  test('rejects unknown orders with 403', async () => {
    stubFetch(async () => ({ ok: false, status: 404 }));
    const req = createMockReq({ method: 'POST', body: { orderId: 'nope' } });
    const res = createMockRes();
    await handler(req, res);
    assert.equal(res.statusCode, 403);
  });

  test('returns 500 on upstream network failure', async () => {
    stubFetch(async () => {
      throw new Error('ECONNRESET');
    });
    const req = createMockReq({ method: 'POST', body: { orderId: 'boom' } });
    const res = createMockRes();
    await handler(req, res);
    assert.equal(res.statusCode, 500);
  });
});
