// HTTP security headers. We make a single HTTPS request to the site root and
// grade the response headers that protect visitors (HSTS, CSP, etc).
//
// Not every missing header deserves the same urgency, so each one carries an
// "effort" label (quick win, depends on the site, planned project) and some
// ratings depend on the kind of site:
//   - HSTS is Medium for a basic site and High for a site with logins,
//     payments, or patient or donor data.
//   - X-Frame-Options is Low for a basic site and Medium when there is a login
//     or payment area to protect from clickjacking.
// We read the home page (never more than MAX_BODY_BYTES) to look for signs of
// that kind of site, and we say exactly what we saw so the owner can correct us.

import https from 'node:https';

const MAX_BODY_BYTES = 200 * 1024;

// effort: how the finding is framed in the report.
//   'quick win'    a one-line setting, usually minutes
//   'site type'    how much it matters depends on what the site does
//   'project'      worth doing, but plan and test it first
//   'also'         minor extra
const EXPECTED = [
  {
    key: 'strict-transport-security',
    name: 'HSTS',
    effort: 'quick win',
    severity: (sensitive) => (sensitive ? 'high' : 'medium'),
    advice: 'Add "Strict-Transport-Security: max-age=31536000; includeSubDomains" to force HTTPS.',
  },
  {
    key: 'x-content-type-options',
    name: 'X-Content-Type-Options',
    effort: 'quick win',
    severity: () => 'low',
    advice: 'Add "X-Content-Type-Options: nosniff" to stop MIME-type sniffing.',
  },
  {
    key: 'x-frame-options',
    name: 'X-Frame-Options',
    effort: 'site type',
    severity: (sensitive) => (sensitive ? 'medium' : 'low'),
    advice:
      'Add "X-Frame-Options: DENY" (or a frame-ancestors CSP) to prevent clickjacking. ' +
      'It matters most on pages with logins or payments, and is a low priority on a basic brochure site.',
  },
  {
    key: 'content-security-policy',
    name: 'Content-Security-Policy',
    effort: 'project',
    severity: () => 'medium',
    advice:
      'Add a Content-Security-Policy to limit which scripts and resources can load (mitigates XSS). ' +
      'Plan it as a small project: start in report-only mode, test your pages, then enforce it.',
  },
  {
    key: 'referrer-policy',
    name: 'Referrer-Policy',
    effort: 'also',
    severity: () => 'low',
    advice: 'Add a Referrer-Policy such as "strict-origin-when-cross-origin".',
  },
];

const GROUPS = [
  { effort: 'quick win', label: 'Quick wins' },
  { effort: 'site type', label: 'Depends on your site' },
  { effort: 'project', label: 'Planned project' },
  { effort: 'also', label: 'Also worth adding' },
];

const SEVERITY_ORDER = { high: 3, medium: 2, low: 1 };

const SIGNAL_PHRASE = {
  login: 'a login area',
  payments: 'payments',
  donations: 'donations',
  patient: 'patient information',
};

// Looks at the home page HTML for signs the site handles logins, payments, or
// patient or donor data. This is a best-effort guess from one page: it can miss
// things that live deeper in the site, and the report says so.
export function detectSensitiveSite(html) {
  if (typeof html !== 'string' || html === '') return [];
  const h = html.toLowerCase();
  const signals = new Set();

  if (
    /<input[^>]+type\s*=\s*["']?password/.test(h) ||
    /\b(log[ -]?in|sign[ -]?in|my account|member portal|client portal|customer portal|student portal)\b/.test(h)
  ) {
    signals.add('login');
  }
  if (
    /\b(add to cart|shopping cart|checkout|pay now|pay online|pay your bill|pay an invoice)\b/.test(h) ||
    /(js\.stripe\.com|checkout\.stripe\.com|buy\.stripe\.com|paypal\.com|squareup\.com|square\.site|braintreegateway\.com|authorize\.net)/.test(h)
  ) {
    signals.add('payments');
  }
  if (
    /\b(donate|donation|give now|make a gift)\b/.test(h) ||
    /(donorbox\.org|givebutter\.com|classy\.org|zeffy\.com|bloomerang\.co|networkforgood\.org)/.test(h)
  ) {
    signals.add('donations');
  }
  if (/\b(patient portal|new patients?|patient forms?|request an appointment|telehealth|hipaa)\b/.test(h)) {
    signals.add('patient');
  }
  return [...signals];
}

function joinList(items) {
  if (items.length <= 1) return items.join('');
  if (items.length === 2) return `${items[0]} and ${items[1]}`;
  return `${items.slice(0, -1).join(', ')}, and ${items[items.length - 1]}`;
}

function siteTypeNote(signals) {
  if (signals.length > 0) {
    const seen = joinList(signals.map((s) => SIGNAL_PHRASE[s]));
    return `We saw signs of ${seen} on your home page, so HSTS is rated High for your site.`;
  }
  return (
    'We did not see logins, payments, or patient or donor data on your home page, so HSTS is rated Medium for your site. ' +
    'If your site has any of those, treat it as High.'
  );
}

export function evaluateHeaders(headers, { signals = [] } = {}) {
  const sensitive = signals.length > 0;
  const present = [];
  const missing = [];
  for (const item of EXPECTED) {
    if (headers[item.key]) present.push(item.name);
    else missing.push({ ...item, rated: item.severity(sensitive) });
  }

  if (missing.length === 0) {
    return {
      id: 'headers',
      category: 'Transport Security',
      title: 'HTTP security headers',
      status: 'pass',
      severity: 'info',
      summary: 'All key security headers present',
      detail: `Present: ${present.join(', ')}.`,
    };
  }

  const worst = missing.reduce(
    (w, m) => ((SEVERITY_ORDER[m.rated] ?? 0) > (SEVERITY_ORDER[w] ?? 0) ? m.rated : w),
    'low',
  );

  // One recommendation, grouped by how much work each fix is, so a site that is
  // missing everything reads as a short to-do list and not one alarming wall.
  const parts = [];
  for (const group of GROUPS) {
    const items = missing.filter((m) => m.effort === group.effort);
    if (items.length === 0) continue;
    parts.push(`${group.label}: ${items.map((m) => m.advice).join(' ')}`);
  }
  if (missing.some((m) => m.key === 'strict-transport-security')) {
    parts.push(
      'HSTS is rated Medium for a basic site and High for a site with logins, payments, or patient or donor data. ' +
        siteTypeNote(signals),
    );
  }

  const quickWins = missing.filter((m) => m.effort === 'quick win').length;
  const summary =
    `${missing.length} security header${missing.length > 1 ? 's' : ''} missing` +
    (quickWins > 0 ? `, ${quickWins} ${quickWins > 1 ? 'are quick wins' : 'is a quick win'}` : '');

  return {
    id: 'headers',
    category: 'Transport Security',
    title: 'HTTP security headers',
    status: worst === 'low' ? 'warn' : 'fail',
    severity: worst,
    summary,
    detail: `Present: ${present.join(', ') || 'none'}. Missing: ${missing.map((m) => m.name).join(', ')}.`,
    recommendation: parts.join(' '),
    evidence: {
      present,
      missing: missing.map((m) => m.name),
      siteType: sensitive ? 'sensitive' : 'basic',
      signals,
      items: missing.map((m) => ({ name: m.name, severity: m.rated, effort: m.effort })),
    },
  };
}

export async function checkHeaders(domain, { timeoutMs = 6000, requestImpl } = {}) {
  const page = await fetchPage(domain, timeoutMs, requestImpl);
  if (!page) {
    return {
      id: 'headers',
      category: 'Transport Security',
      title: 'HTTP security headers',
      status: 'warn',
      severity: 'low',
      summary: 'Could not retrieve HTTP headers',
      detail: 'No HTTPS response was received from the site root.',
      recommendation: 'Confirm the site is reachable over HTTPS so security headers can be evaluated.',
    };
  }
  return evaluateHeaders(page.headers, { signals: detectSensitiveSite(page.html) });
}

// Resolves { headers, html } (html is '' unless the home page answered 200 with
// HTML) or null when no response arrived. The body is capped, and a slow body
// never costs us the headers we already have.
function fetchPage(domain, timeoutMs, requestImpl = https.request) {
  return new Promise((resolve) => {
    let headers = null;
    let html = '';
    let settled = false;
    let timer;
    let req;

    const finish = () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(headers ? { headers, html } : null);
    };

    req = requestImpl(
      { host: domain, port: 443, path: '/', method: 'GET', timeout: timeoutMs, rejectUnauthorized: false },
      (res) => {
        headers = res.headers;
        const isHtml = res.statusCode === 200 && /text\/html/i.test(String(res.headers?.['content-type'] ?? ''));
        if (!isHtml || typeof res.on !== 'function') {
          res.resume?.();
          finish();
          return;
        }
        res.setEncoding?.('utf8');
        res.on('data', (chunk) => {
          html += chunk;
          if (html.length > MAX_BODY_BYTES) {
            html = html.slice(0, MAX_BODY_BYTES);
            res.destroy?.();
            finish();
          }
        });
        res.on('end', finish);
        res.on('close', finish);
        res.on('error', finish);
      },
    );
    timer = setTimeout(() => {
      req?.destroy?.();
      finish();
    }, timeoutMs + 2000);
    req.on('timeout', () => {
      req.destroy();
      finish();
    });
    req.on('error', () => finish());
    req.end();
  });
}
