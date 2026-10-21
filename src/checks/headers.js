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

// Says which page we actually graded, so the owner is never left guessing.
function describeContext(context) {
  if (!context?.checkedUrl) return '';
  const { checkedUrl, redirects = [], stopped, stoppedAt } = context;
  if (stopped) {
    const where = stoppedAt ? ` to ${stoppedAt}` : '';
    const why = {
      'other-site': 'a different site, which we do not follow',
      http: 'an unencrypted address, which we do not follow',
      unreachable: 'an address we could not reach',
      'too-many': 'too many times in a row',
      loop: 'itself in a circle',
    }[stopped] ?? 'an address we do not follow';
    return ` Your home page (${checkedUrl}) redirects${where} (${why}), so we graded the redirect response itself.`;
  }
  if (redirects.length > 0) {
    return ` We checked ${checkedUrl} because ${redirects[0]} redirects there.`;
  }
  return '';
}

export function evaluateHeaders(headers, { signals = [], context = null } = {}) {
  const sensitive = signals.length > 0;
  const contextNote = describeContext(context);
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
      detail: `Present: ${present.join(', ')}.${contextNote}`,
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
    detail: `Present: ${present.join(', ') || 'none'}. Missing: ${missing.map((m) => m.name).join(', ')}.${contextNote}`,
    recommendation: parts.join(' '),
    evidence: {
      present,
      missing: missing.map((m) => m.name),
      siteType: sensitive ? 'sensitive' : 'basic',
      signals,
      items: missing.map((m) => ({ name: m.name, severity: m.rated, effort: m.effort })),
      checkedUrl: context?.checkedUrl ?? null,
      redirects: context?.redirects ?? [],
    },
  };
}

// loadPage lets the audit fetch the home page once and share it with the
// website software check. Without it we fetch the page ourselves.
export async function checkHeaders(domain, { timeoutMs = 6000, requestImpl, loadPage } = {}) {
  const page = loadPage ? await loadPage() : await fetchPage(domain, timeoutMs, requestImpl);
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
  return evaluateHeaders(page.headers, {
    signals: detectSensitiveSite(page.html),
    context: { checkedUrl: page.url, redirects: page.redirects, stopped: page.stopped, stoppedAt: page.stoppedAt },
  });
}

const MAX_REDIRECTS = 3;
const REDIRECT_CODES = new Set([301, 302, 303, 307, 308]);

// A redirect is only followed when it stays on the scanned domain (or one of
// its subdomains, which includes www), uses HTTPS on the normal port, and
// carries no credentials. Anything else could point the scanner somewhere the
// owner did not ask us to look.
function isSameSite(hostname, domain) {
  const h = hostname.toLowerCase();
  const d = domain.toLowerCase();
  return h === d || h.endsWith(`.${d}`);
}

function nextHop(current, location, domain) {
  let url;
  try {
    url = new URL(location, `https://${current.host}${current.path}`);
  } catch {
    return { stop: 'unreadable' };
  }
  if (url.protocol !== 'https:') return { stop: 'http', at: url.href };
  if (url.port && url.port !== '443') return { stop: 'port', at: url.href };
  if (url.username || url.password) return { stop: 'credentials' };
  if (!isSameSite(url.hostname, domain)) return { stop: 'other-site', at: url.origin + '/' };
  return { host: url.hostname, path: `${url.pathname}${url.search}` };
}

// Starts at https://domain/ and follows same-site redirects. Resolves the page
// we ended on (headers, html, url) plus the redirects followed, or null when
// nothing answered. If a later step fails we keep the last response we had.
export async function fetchPage(domain, timeoutMs, requestImpl = https.request) {
  const deadline = Date.now() + timeoutMs * 2;
  let host = domain;
  let path = '/';
  let from = null;
  let last = null;
  const redirects = [];
  let stopped = null;
  let stoppedAt = null;

  for (let hop = 0; hop <= MAX_REDIRECTS; hop += 1) {
    const budget = Math.min(timeoutMs, deadline - Date.now());
    if (budget <= 0) break;
    const res = await fetchOnce(host, path, budget, requestImpl);
    if (!res) {
      if (last) {
        stopped = 'unreachable';
        stoppedAt = `https://${host}${path}`;
      }
      break;
    }
    if (from) redirects.push(from);
    last = { ...res, url: `https://${host}${path}` };

    const location = res.headers?.location;
    if (!REDIRECT_CODES.has(res.statusCode) || !location) break;
    if (hop === MAX_REDIRECTS) {
      stopped = 'too-many';
      break;
    }
    const next = nextHop({ host, path }, String(location), domain);
    if (next.stop) {
      stopped = next.stop;
      stoppedAt = next.at ?? null;
      break;
    }
    if (next.host === host && next.path === path) {
      stopped = 'loop';
      break;
    }
    from = last.url;
    host = next.host;
    path = next.path;
  }
  return last ? { ...last, redirects, stopped, stoppedAt } : null;
}

// One request. Resolves { headers, statusCode, html } (html is '' unless the
// page answered 200 with HTML, and is capped) or null when no response arrived.
// A slow body never costs us the headers we already have.
function fetchOnce(host, path, timeoutMs, requestImpl) {
  return new Promise((resolve) => {
    let headers = null;
    let statusCode = 0;
    let html = '';
    let settled = false;
    let timer;
    let req;

    const finish = () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(headers ? { headers, statusCode, html } : null);
    };

    req = requestImpl(
      { host, port: 443, path, method: 'GET', timeout: timeoutMs, rejectUnauthorized: false },
      (res) => {
        headers = res.headers;
        statusCode = res.statusCode;
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
