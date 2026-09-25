// HTTP security headers. We make a single HTTPS request to the site root and
// grade the response headers that protect visitors (HSTS, CSP, etc).

import https from 'node:https';

const EXPECTED = [
  {
    key: 'strict-transport-security',
    name: 'HSTS',
    severity: 'high',
    advice: 'Add "Strict-Transport-Security: max-age=31536000; includeSubDomains" to force HTTPS.',
  },
  {
    key: 'content-security-policy',
    name: 'Content-Security-Policy',
    severity: 'medium',
    advice: 'Add a Content-Security-Policy to limit which scripts and resources can load (mitigates XSS).',
  },
  {
    key: 'x-content-type-options',
    name: 'X-Content-Type-Options',
    severity: 'low',
    advice: 'Add "X-Content-Type-Options: nosniff" to stop MIME-type sniffing.',
  },
  {
    key: 'x-frame-options',
    name: 'X-Frame-Options',
    severity: 'low',
    advice: 'Add "X-Frame-Options: DENY" (or a frame-ancestors CSP) to prevent clickjacking.',
  },
  {
    key: 'referrer-policy',
    name: 'Referrer-Policy',
    severity: 'low',
    advice: 'Add a Referrer-Policy such as "strict-origin-when-cross-origin".',
  },
];

export function evaluateHeaders(headers) {
  const present = [];
  const missing = [];
  for (const item of EXPECTED) {
    if (headers[item.key]) present.push(item.name);
    else missing.push(item);
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

  const worst = missing.some((m) => m.severity === 'high')
    ? 'high'
    : missing.some((m) => m.severity === 'medium')
      ? 'medium'
      : 'low';

  return {
    id: 'headers',
    category: 'Transport Security',
    title: 'HTTP security headers',
    status: worst === 'low' ? 'warn' : 'fail',
    severity: worst,
    summary: `${missing.length} security header${missing.length > 1 ? 's' : ''} missing`,
    detail: `Present: ${present.join(', ') || 'none'}. Missing: ${missing.map((m) => m.name).join(', ')}.`,
    recommendation: missing.map((m) => m.advice).join(' '),
    evidence: { present, missing: missing.map((m) => m.name) },
  };
}

export async function checkHeaders(domain, { timeoutMs = 6000, requestImpl } = {}) {
  const headers = await fetchHeaders(domain, timeoutMs, requestImpl);
  if (!headers) {
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
  return evaluateHeaders(headers);
}

function fetchHeaders(domain, timeoutMs, requestImpl = https.request) {
  return new Promise((resolve) => {
    const req = requestImpl(
      { host: domain, port: 443, path: '/', method: 'GET', timeout: timeoutMs, rejectUnauthorized: false },
      (res) => {
        res.resume();
        resolve(res.headers);
      },
    );
    req.on('timeout', () => {
      req.destroy();
      resolve(null);
    });
    req.on('error', () => resolve(null));
    req.end();
  });
}
