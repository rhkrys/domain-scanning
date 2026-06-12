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
import { checkHeaders } from './checks/headers.js';
import { scoreFindings } from './scoring.js';

const DOMAIN_RE = /^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.[a-z0-9-]{1,63})+$/i;

export function normaliseDomain(input) {
  if (typeof input !== 'string') return null;
  let d = input.trim().toLowerCase();
  d = d.replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/:\d+$/, '');
  d = d.replace(/\.$/, '');
  if (!DOMAIN_RE.test(d)) return null;
  return d;
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

export async function runAudit(rawDomain, { resolver = new Resolver() } = {}) {
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

  const findings = await Promise.all([
    Promise.resolve(mx),
    safe('addressing', 'A / AAAA records', 'DNS Foundation', () => checkAddressing(resolver, domain)),
    safe('nameservers', 'Nameservers', 'DNS Foundation', () => checkNameservers(resolver, domain)),
    safe('dnssec', 'DNSSEC', 'DNS Foundation', () => checkDnssec(resolver, domain)),
    safe('caa', 'CAA record', 'DNS Foundation', () => checkCaa(resolver, domain)),
    safe('spf', 'SPF', 'Email Authentication', () => checkSpf(resolver, domain, opts)),
    safe('dmarc', 'DMARC', 'Email Authentication', () => checkDmarc(resolver, domain, opts)),
    safe('dkim', 'DKIM', 'Email Authentication', () => checkDkim(resolver, domain, opts)),
    safe('mta-sts', 'MTA-STS', 'Email Authentication', () => checkMtaSts(resolver, domain, opts)),
    safe('bimi', 'BIMI', 'Email Authentication', () => checkBimi(resolver, domain)),
    safe('tls', 'TLS certificate', 'Transport Security', () => checkTls(domain)),
    safe('headers', 'HTTP security headers', 'Transport Security', () => checkHeaders(domain)),
  ]);

  const scored = scoreFindings(findings);

  return {
    domain,
    scannedAt: new Date().toISOString(),
    sendsMail,
    ...scored,
    findings,
  };
}
