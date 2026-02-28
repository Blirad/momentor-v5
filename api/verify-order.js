import crypto from 'crypto';

/**
 * Vercel Serverless Function: POST /api/verify-order
 * Verifies a LemonSqueezy order via the LS API and returns a signed token.
 * 
 * Env vars required:
 *   LS_API_KEY   — LemonSqueezy API key
 *   LS_TOKEN_SECRET — HMAC signing secret (set any random string)
 */

function signToken(orderId) {
  const secret = process.env.LS_TOKEN_SECRET || 'momentor-default-secret';
  const payload = `${orderId}:${Math.floor(Date.now() / 1000 / 3600)}`; // hourly rotation
  return crypto.createHmac('sha256', secret).update(payload).digest('hex');
}

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ ok: false, error: 'Method not allowed' });
  }

  const { orderId } = req.body || {};
  if (!orderId) {
    return res.status(400).json({ ok: false, error: 'Missing orderId' });
  }

  const apiKey = process.env.LS_API_KEY;
  if (!apiKey) {
    console.error('LS_API_KEY not set');
    return res.status(500).json({ ok: false, error: 'Server configuration error' });
  }

  try {
    const resp = await fetch(`https://api.lemonsqueezy.com/v1/orders/${orderId}`, {
      headers: {
        Authorization: `Bearer ${apiKey}`,
        Accept: 'application/vnd.api+json',
      },
    });

    if (!resp.ok) {
      return res.status(403).json({ ok: false, error: 'Order not found' });
    }

    const data = await resp.json();
    const status = data?.data?.attributes?.status;

    if (status === 'paid') {
      const token = signToken(String(orderId));
      return res.json({ ok: true, token });
    } else {
      return res.status(403).json({ ok: false, error: `Order status: ${status}` });
    }
  } catch (err) {
    console.error('verify-order error:', err);
    return res.status(500).json({ ok: false, error: 'Verification failed' });
  }
}
