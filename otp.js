import express from 'express';
import crypto from 'node:crypto';

const router = express.Router();
const store = new Map();
const hash = (c) => crypto.createHash('sha256').update(c + (process.env.JWT_SECRET || '')).digest('hex');
const okEmail = (e) => /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(e);

router.post('/send-otp', async (req, res) => {
  const email = String(req.body?.email || '').trim().toLowerCase();
  if (!okEmail(email)) return res.status(400).json({ error: 'Invalid email' });
  const now = Date.now();
  const rec = store.get(email) || { sent: [], tries: 0 };
  rec.sent = rec.sent.filter((t) => now - t < 3600000);
  if (rec.sent.length >= 5) return res.status(429).json({ error: 'Too many requests' });
  const code = String(crypto.randomInt(100000, 1000000));
  try {
    const r = await fetch('https://api.brevo.com/v3/smtp/email', {
      method: 'POST',
      headers: { 'api-key': process.env.BREVO_API_KEY, 'content-type': 'application/json' },
      body: JSON.stringify({
        sender: { name: 'Gaming White Chat', email: process.env.SENDER_EMAIL },
        to: [{ email }],
        subject: 'Your verification code',
        textContent: `Your code is ${code}. It expires in 1 minute.`,
      }),
    });
    if (!r.ok) {
      console.error('[OTP] Brevo', r.status, await r.text());
      return res.status(503).json({ error: 'Email service unavailable' });
    }
  } catch (e) {
    console.error('[OTP] failed', e.message);
    return res.status(503).json({ error: 'Email service unavailable' });
  }
  rec.sent.push(now);
  rec.hash = hash(code);
  rec.exp = now + 60000;
  rec.tries = 0;
  store.set(email, rec);
  console.log('[OTP] sent to', email);
  res.json({ ok: true });
});

router.post('/verify-otp', (req, res) => {
  const email = String(req.body?.email || '').trim().toLowerCase();
  const code = String(req.body?.code || '');
  const rec = store.get(email);
  if (!rec || !rec.hash || Date.now() > rec.exp) return res.status(400).json({ error: 'Code expired' });
  if (rec.tries >= 5) return res.status(429).json({ error: 'Too many tries' });
  rec.tries++;
  const a = Buffer.from(hash(code));
  const b = Buffer.from(rec.hash);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return res.status(400).json({ error: 'Wrong code' });
  rec.hash = null;
  res.json({ verified: true });
});

export default router;
