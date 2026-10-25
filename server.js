// Web entry point. Serves the single-page form and exposes:
//   POST /api/scan       the scan page: runs the audit, emails the report if
//                        asked, and returns the full report to render.
//   POST /api/v1/scan    the JSON API (for the ChatGPT app): the scan result
//                        object plus a report link. CORS from config, rate
//                        limited per IP per hour.
//   GET  /api/report/:id a saved scan, for report links.
//
// createApp() takes injectable audit/send functions so the full HTTP flow can
// be tested without touching the network.

import express from 'express';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runAudit, normaliseDomain, domainInputProblem } from './src/audit.js';
import { sendReport } from './src/email/mailer.js';
import { loadConfig } from './src/config.js';
import { createApiLimiter } from './src/ratelimit.js';
import { createMemoryStore, newScanId, SCAN_ID_RE } from './src/store.js';

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

function clientIp(req) {
  return req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip;
}

export function createApp({
  audit = runAudit,
  send = sendReport,
  rateLimit = {},
  config = loadConfig(),
  apiLimiter,
  store = createMemoryStore(),
} = {}) {
  const { windowMs = 60_000, max = 10 } = rateLimit;
  const limiterReady = apiLimiter ? Promise.resolve(apiLimiter) : createApiLimiter(config);
  const app = express();

  // CORS for the JSON API only. Allowed browser origins come from config;
  // calls with no Origin (server to server) are not affected.
  app.use('/api/v1', (req, res, next) => {
    const origin = req.headers.origin;
    if (origin && config.allowedOrigins.includes(origin)) {
      res.set('Access-Control-Allow-Origin', origin);
      res.set('Vary', 'Origin');
      res.set('Access-Control-Allow-Methods', 'POST, OPTIONS');
      res.set('Access-Control-Allow-Headers', 'Content-Type');
      res.set('Access-Control-Max-Age', '600');
    }
    if (req.method === 'OPTIONS') return res.sendStatus(204);
    next();
  });

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
    const ip = clientIp(req);
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

    try {
      const report = await audit(cleanDomain);

      let mail = null;
      if (cleanEmail) {
        try {
          mail = await send(cleanEmail, report);
        } catch (err) {
          mail = { delivered: false, mode: 'error', error: err.message };
        }
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

  app.post('/api/v1/scan', async (req, res) => {
    const ip = clientIp(req);
    try {
      const limiter = await limiterReady;
      if ((await limiter.hit(ip)).limited) {
        return res.status(429).json({ error: 'Too many scans from this address. Please try again in an hour.' });
      }
    } catch (err) {
      // Never block a scan because the counter is unavailable.
      console.error('Rate limiter failed:', err.message);
    }

    const { domain } = req.body ?? {};
    const domainProblem = domainInputProblem(domain);
    if (domainProblem) return res.status(400).json({ error: domainProblem, field: 'domain' });

    try {
      const report = await audit(normaliseDomain(domain));
      const scanId = newScanId();
      await saveScan({ scanId, report, source: 'api' });
      res.json({ ...report.result, report_url: reportUrl(scanId) });
    } catch (err) {
      if (err.code === 'INVALID_DOMAIN') {
        return res.status(400).json({ error: 'That is not a valid domain. Try the format example.com.', field: 'domain' });
      }
      console.error('API scan failed:', err);
      res.status(500).json({ error: 'Something went wrong running the scan. Please try again in a moment.' });
    }
  });

  // A saved scan for a report link. Returns the report only, never the email.
  app.get('/api/report/:id', async (req, res) => {
    if (!SCAN_ID_RE.test(req.params.id)) return res.status(404).json({ error: 'Report not found.' });
    try {
      const record = await store.get(req.params.id);
      if (!record) return res.status(404).json({ error: 'Report not found. Links expire after a while; run a new scan.' });
      res.json({ report: JSON.parse(record.result_json) });
    } catch (err) {
      console.error('Report lookup failed:', err);
      res.status(500).json({ error: 'Something went wrong loading this report.' });
    }
  });

  function reportUrl(scanId) {
    return `${config.publicBaseUrl}/scan?report=${scanId}`;
  }

  async function saveScan({ scanId, report, source }) {
    try {
      await store.save({
        scan_id: scanId,
        domain: report.domain,
        checked_at: report.scannedAt,
        result_json: JSON.stringify(report),
        source,
      });
    } catch (err) {
      // A storage problem must not cost the visitor their result.
      console.error('Saving scan failed:', err.message);
    }
  }

  app.get('/healthz', (_req, res) => res.json({ ok: true }));

  return app;
}

const app = createApp();

// Only listen when run directly, so tests can import the app.
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  app.listen(PORT, () => {
    console.log(`Domain and website security scanner listening on http://localhost:${PORT}`);
  });
}

export default app;
