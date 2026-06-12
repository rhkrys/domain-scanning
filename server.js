// Web entry point. Serves the single-page form and exposes POST /api/scan,
// which runs the audit, emails the user their next steps, and returns the
// report so the page can render an instant summary.

import express from 'express';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runAudit, normaliseDomain } from './src/audit.js';
import { sendReport } from './src/email/mailer.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = process.env.PORT ?? 3000;

app.use(express.json({ limit: '8kb' }));
app.use(express.static(path.join(__dirname, 'public')));

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// Light in-memory rate limiting so the scanner cannot be used to hammer
// third-party infrastructure from one client.
const hits = new Map();
function rateLimited(ip) {
  const now = Date.now();
  const windowMs = 60_000;
  const max = 10;
  const list = (hits.get(ip) ?? []).filter((t) => now - t < windowMs);
  list.push(now);
  hits.set(ip, list);
  return list.length > max;
}

app.post('/api/scan', async (req, res) => {
  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip;
  if (rateLimited(ip)) {
    return res.status(429).json({ error: 'Too many scans. Please wait a minute and try again.' });
  }

  const { domain, email } = req.body ?? {};
  const cleanDomain = normaliseDomain(domain);
  if (!cleanDomain) {
    return res.status(400).json({ error: 'Please enter a valid domain, e.g. example.com.' });
  }
  if (email != null && email !== '' && !EMAIL_RE.test(email)) {
    return res.status(400).json({ error: 'Please enter a valid email address.' });
  }

  try {
    const report = await runAudit(cleanDomain);

    let mail = null;
    if (email) {
      try {
        mail = await sendReport(email, report);
      } catch (err) {
        mail = { delivered: false, mode: 'error', error: err.message };
      }
    }

    res.json({ report, mail });
  } catch (err) {
    if (err.code === 'INVALID_DOMAIN') {
      return res.status(400).json({ error: 'Please enter a valid domain, e.g. example.com.' });
    }
    console.error('Scan failed:', err);
    res.status(500).json({ error: 'The scan could not be completed. Please try again.' });
  }
});

app.get('/healthz', (_req, res) => res.json({ ok: true }));

// Only listen when run directly, so tests can import the app.
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  app.listen(PORT, () => {
    console.log(`Domain scanner listening on http://localhost:${PORT}`);
  });
}

export default app;
