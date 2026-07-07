// Web entry point. Serves the single-page form and exposes POST /api/scan,
// which runs the audit, emails the user their next steps, and returns the
// report so the page can render an instant summary.
//
// createApp() takes injectable audit/send functions so the full HTTP flow can
// be tested without touching the network.

import express from 'express';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runAudit, normaliseDomain, domainInputProblem } from './src/audit.js';
import { sendReport } from './src/email/mailer.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = process.env.PORT ?? 3000;

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// Catch the most common mail-provider typos so a mistyped address doesn't
// silently swallow the report.
const EMAIL_DOMAIN_TYPOS = {
  'gmial.com': 'gmail.com',
  'gamil.com': 'gmail.com',
  'gmal.com': 'gmail.com',
  'gmai.com': 'gmail.com',
  'gmail.co': 'gmail.com',
  'gmail.con': 'gmail.com',
  'hotmial.com': 'hotmail.com',
  'hotmal.com': 'hotmail.com',
  'hotmail.co': 'hotmail.com',
  'outlok.com': 'outlook.com',
  'outloook.com': 'outlook.com',
  'yaho.com': 'yahoo.com',
  'yahooo.com': 'yahoo.com',
  'iclould.com': 'icloud.com',
  'icoud.com': 'icloud.com',
};

export function emailInputProblem(email) {
  const e = String(email).trim();
  if (!EMAIL_RE.test(e)) {
    return 'That email address doesn’t look right. Check it follows the format you@example.com.';
  }
  const domain = e.split('@')[1].toLowerCase();
  const suggestion = EMAIL_DOMAIN_TYPOS[domain];
  if (suggestion) {
    return `Did you mean @${suggestion}? "${domain}" looks like a typo — please double-check so your report reaches you.`;
  }
  return null;
}

export function createApp({ audit = runAudit, send = sendReport, rateLimit = {} } = {}) {
  const { windowMs = 60_000, max = 10 } = rateLimit;
  const app = express();
  app.use(express.json({ limit: '8kb' }));
  app.use(express.static(path.join(__dirname, 'public')));

  // Light in-memory rate limiting so the scanner cannot be used to hammer
  // third-party infrastructure from one client.
  const hits = new Map();
  function rateLimited(ip) {
    const now = Date.now();
    const list = (hits.get(ip) ?? []).filter((t) => now - t < windowMs);
    list.push(now);
    hits.set(ip, list);
    return list.length > max;
  }

  app.post('/api/scan', async (req, res) => {
    const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip;
    if (rateLimited(ip)) {
      return res.status(429).json({ error: 'You’ve run a few scans in a row — please wait a minute and try again.' });
    }

    const { domain, email } = req.body ?? {};
    const domainProblem = domainInputProblem(domain);
    if (domainProblem) {
      return res.status(400).json({ error: domainProblem, field: 'domain' });
    }
    const cleanDomain = normaliseDomain(domain);

    const cleanEmail = typeof email === 'string' ? email.trim() : '';
    if (cleanEmail !== '') {
      const emailProblem = emailInputProblem(cleanEmail);
      if (emailProblem) {
        return res.status(400).json({ error: emailProblem, field: 'email' });
      }
    }

    // Privacy-safe request log: domain + whether an email was supplied (not the
    // address). Helps diagnose "email didn't arrive" reports.
    console.log(JSON.stringify({ evt: 'scan', domain: cleanDomain, hasEmail: Boolean(cleanEmail) }));

    try {
      const report = await audit(cleanDomain);

      let mail = null;
      if (cleanEmail) {
        try {
          mail = await send(cleanEmail, report);
        } catch (err) {
          mail = { delivered: false, mode: 'error', error: err.message };
        }
        console.log(JSON.stringify({ evt: 'mail', domain: cleanDomain, mode: mail?.mode, delivered: mail?.delivered }));
      }

      res.json({ report, mail });
    } catch (err) {
      if (err.code === 'INVALID_DOMAIN') {
        return res.status(400).json({ error: 'We couldn’t recognise that as a website address. Try the format example.com.', field: 'domain' });
      }
      console.error('Scan failed:', err);
      res.status(500).json({ error: 'Something went wrong running the scan. Please try again in a moment.' });
    }
  });

  app.get('/healthz', (_req, res) => res.json({ ok: true }));

  return app;
}

const app = createApp();

// Only listen when run directly, so tests can import the app.
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  app.listen(PORT, () => {
    console.log(`Domain scanner listening on http://localhost:${PORT}`);
  });
}

export default app;
