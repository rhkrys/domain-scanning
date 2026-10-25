// Orchestrates every check against a domain and assembles the scored report.

import { Resolver } from './resolver.js';
import {
  checkAddressing,
  checkMx,
  checkNameservers,
  checkCaa,
} from './checks/records.js';
import {
  checkSpf,
  checkDmarc,
  checkDkim,
  checkMtaSts,
  checkBimi,
} from './checks/email.js';
import { checkDnssec } from './checks/dnssec.js';
import { checkTls } from './checks/tls.js';
import { checkHeaders, fetchPage } from './checks/headers.js';
import { checkSoftware } from './checks/software.js';
import { scoreFindings } from './scoring.js';
import { detectEmailProviders } from './providers.js';
import { sendersFromSpf, selectorsForSenders } from './senders.js';

const DOMAIN_RE = /^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.[a-z0-9-]{1,63})+$/i;

// Accepts the messy ways people actually type a domain: a pasted URL, a
// "www." prefix, stray spaces, uppercase, a trailing dot or slash. Returns
// the clean registrable-looking domain, or null if we can't make sense of it.
export function normaliseDomain(input) {
  if (typeof input !== 'string') return null;
  let d = input.trim().toLowerCase().replace(/\s+/g, '');
  d = d.replace(/^[a-z][a-z0-9+.-]*:\/\//, '').replace(/\/.*$/, '').replace(/:\d+$/, '');
  d = d.replace(/\.$/, '');
  // People type their website as "www.example.com"; the security records we
  // audit (SPF, DMARC, MX, DNSSEC) live on the apex domain.
  d = d.replace(/^www\./, '');
  if (!DOMAIN_RE.test(d)) return null;
  return d;
}

// Explains *why* an input was rejected, in words a non-technical user can act
// on. Returns null when the input is acceptable.
export function domainInputProblem(input) {
  if (typeof input !== 'string' || input.trim() === '') {
    return 'Please enter your website address, e.g. example.com.';
  }
  if (input.includes('@')) {
    return 'That looks like an email address. In this box, enter your website address instead, e.g. example.com.';
  }
  const cleaned = normaliseDomain(input);
  if (cleaned) return null;
  if (!input.includes('.')) {
    return `"${input.trim()}" is missing its ending. Try something like ${input.trim().toLowerCase().replace(/[^a-z0-9-]/g, '') || 'example'}.com.`;
  }
  return 'We couldn’t recognise that as a website address. Try the format example.com — you can also paste your full website link.';
}

// Wrap a check so one failing lookup cannot abort the whole scan.
async function safe(id, title, category, fn) {
  try {
    return await fn();
  } catch (err) {
    return {
      id,
      title,
      category,
      status: 'warn',
      severity: 'low',
      summary: 'Check could not be completed',
      detail: `An error occurred while running this check: ${err.message}`,
    };
  }
}

// The SPF text to read senders from. A broken record still says who the owner
// meant to list, so use the repaired one; several records are read together.
export function spfRecordOf(spf) {
  const ev = spf?.evidence ?? {};
  return ev.fixed ?? ev.record ?? (ev.records ? ev.records.join(' ') : null);
}

export const DELIVERABILITY_IDS = new Set(['spf', 'dkim', 'dmarc']);

export async function runAudit(rawDomain, { resolver = new Resolver(), loadPage } = {}) {
  const domain = normaliseDomain(rawDomain);
  if (!domain) {
    const error = new Error('Invalid domain');
    error.code = 'INVALID_DOMAIN';
    throw error;
  }

  // MX first: whether the domain sends mail tunes the severity of the
  // email-authentication findings.
  const mx = await safe('mx', 'MX records', 'DNS Foundation', () => checkMx(resolver, domain));
  const sendsMail = mx.evidence?.sendsMail !== false;
  const opts = { sendsMail };

  // Fetch the home page once; the headers and website software checks share it.
  let homePage;
  const sharedPage = () => (homePage ??= (loadPage ?? (() => fetchPage(domain, 6000)))().catch(() => null));

  // SPF names the systems that send as the domain; DKIM then also tests the
  // selectors those systems use (k1-k3 for Mailchimp, and so on).
  const spfCheck = safe('spf', 'SPF', 'Email Deliverability', () => checkSpf(resolver, domain, opts));
  const dkimCheck = spfCheck.then((spf) => {
    const extraSelectors = selectorsForSenders(sendersFromSpf(spfRecordOf(spf)));
    return safe('dkim', 'DKIM', 'Email Deliverability', () => checkDkim(resolver, domain, { ...opts, extraSelectors }));
  });

  // Email deliverability checks come first so they lead the report.
  const findings = await Promise.all([
    spfCheck,
    safe('dmarc', 'DMARC', 'Email Deliverability', () => checkDmarc(resolver, domain, opts)),
    dkimCheck,
    safe('mta-sts', 'MTA-STS', 'Email Deliverability', () => checkMtaSts(resolver, domain, opts)),
    safe('bimi', 'BIMI', 'Email Deliverability', () => checkBimi(resolver, domain)),
    Promise.resolve(mx),
    safe('addressing', 'A / AAAA records', 'DNS Foundation', () => checkAddressing(resolver, domain)),
    safe('nameservers', 'Nameservers', 'DNS Foundation', () => checkNameservers(resolver, domain)),
    safe('dnssec', 'DNSSEC', 'DNS Foundation', () => checkDnssec(resolver, domain)),
    safe('caa', 'CAA record', 'DNS Foundation', () => checkCaa(resolver, domain)),
    safe('tls', 'TLS certificate', 'Transport Security', () => checkTls(domain)),
    safe('headers', 'HTTP security headers', 'Transport Security', () => checkHeaders(domain, { loadPage: sharedPage })),
    safe('php', 'PHP (website software)', 'Website Software', () => checkSoftware(domain, { loadPage: sharedPage })),
  ]);

  // SPF, DKIM and DMARC decide whether mail reaches the inbox; flag them.
  for (const f of findings) {
    if (DELIVERABILITY_IDS.has(f.id)) f.deliverability = true;
  }

  const scored = scoreFindings(findings);

  // Who to ask for SPF, DKIM and DMARC setup, from the MX and SPF we already have.
  const spf = findings.find((f) => f.id === 'spf');
  const emailSetup = detectEmailProviders({
    mxHosts: mx.evidence?.hosts ?? [],
    spfRecord: spfRecordOf(spf),
  });

  return {
    domain,
    scannedAt: new Date().toISOString(),
    sendsMail,
    ...scored,
    findings,
    emailSetup,
  };
}
