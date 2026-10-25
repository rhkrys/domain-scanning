// Email authentication checks. These are the highest-impact findings for most
// domains: weak SPF/DMARC is what lets attackers spoof a business's address.

import https from 'node:https';

export function parseSpf(txtRecords) {
  return txtRecords.find((r) => /^v=spf1\b/i.test(r.trim())) ?? null;
}

// SPF syntax per RFC 7208. A record with an unknown term or a malformed
// mechanism is a "permerror": strict receivers ignore the whole record.
const SPF_DOMAIN = /^(?:%\{[^}]+\}|[a-z0-9_-])(?:%\{[^}]+\}|[a-z0-9_.-])*\.[a-z0-9-]+\.?$/i;
const SPF_IP4 = /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\/(?:3[0-2]|[12]?\d))?$/;
const SPF_IP6 = /^[0-9a-f:.]*:[0-9a-f:.]*(?:\/(?:12[0-8]|1[01]\d|[1-9]?\d))?$/i;
const SPF_CIDR = /^(?:\/(?:3[0-2]|[12]?\d))?(?:\/\/(?:12[0-8]|1[01]\d|[1-9]?\d))?$/;
const BARE_DOMAIN = /^[a-z0-9_-]+(?:\.[a-z0-9_-]+)+\.?$/i;

function spfTermOk(term) {
  const t = term.replace(/^[+\-~?]/, '');
  let m;
  if (/^all$/i.test(t)) return true;
  if ((m = t.match(/^(include|exists):(.+)$/i))) return SPF_DOMAIN.test(m[2]);
  if ((m = t.match(/^(a|mx)(?::([^/]+))?(\/.*)?$/i))) return (!m[2] || SPF_DOMAIN.test(m[2])) && SPF_CIDR.test(m[3] ?? '');
  if ((m = t.match(/^ptr(?::(.+))?$/i))) return !m[1] || SPF_DOMAIN.test(m[1]);
  if ((m = t.match(/^ip4:(.+)$/i))) return SPF_IP4.test(m[1]);
  if ((m = t.match(/^ip6:(.+)$/i))) return SPF_IP6.test(m[1]);
  if ((m = term.match(/^(redirect|exp)=(.+)$/i))) return SPF_DOMAIN.test(m[2]);
  // Other name=value modifiers are allowed and ignored by receivers.
  return /^[a-z][a-z0-9_.-]*=\S*$/i.test(term);
}

// Returns { problems: [plain-language strings], fixed: corrected record or null }.
// "fixed" is only offered when every problem is one we can repair safely
// (stray commas, a domain missing "include:").
export function validateSpfSyntax(record) {
  const problems = [];
  let fixable = true;
  const terms = record.trim().split(/\s+/).slice(1);
  const fixedTerms = [];

  if (!/^v=spf1$/i.test(record.trim().split(/\s+/)[0])) {
    problems.push('The record must start with exactly "v=spf1" followed by a space.');
    fixable = false;
  }

  for (const raw of terms) {
    let term = raw;
    if (term.includes(',') && !term.includes('%{')) {
      problems.push(`"${raw}" has a comma. SPF parts are separated by spaces only.`);
      term = term.replace(/,/g, '');
      if (!term) continue;
    }
    if (spfTermOk(term)) {
      fixedTerms.push(term);
    } else if (BARE_DOMAIN.test(term)) {
      problems.push(`"${term}" is missing "include:" in front. It should read "include:${term}".`);
      fixedTerms.push(`include:${term}`);
    } else {
      problems.push(`"${term}" is not a valid SPF part.`);
      fixable = false;
    }
  }

  const redirects = terms.filter((t) => /^redirect=/i.test(t)).length;
  if (redirects > 1) {
    problems.push('The record has more than one "redirect=". Only one is allowed.');
    fixable = false;
  }

  return {
    problems,
    fixed: problems.length && fixable ? ['v=spf1', ...fixedTerms].join(' ') : null,
  };
}

export async function checkSpf(resolver, domain, { sendsMail = true } = {}) {
  const txt = await resolver.txt(domain);
  const spf = parseSpf(txt);
  const spfCount = txt.filter((r) => /^v=spf1\b/i.test(r.trim())).length;

  if (spfCount > 1) {
    return {
      id: 'spf',
      category: 'Email Deliverability',
      title: 'SPF',
      status: 'fail',
      severity: sendsMail ? 'high' : 'medium',
      summary: `${spfCount} SPF records found. Only one is allowed`,
      detail: `${domain} publishes ${spfCount} TXT records starting with "v=spf1". Receivers treat that as an error and SPF stops working.`,
      recommendation:
        'Merge them into a single SPF record that lists every service that sends as you, then delete the extra records.',
      evidence: { records: txt.filter((r) => /^v=spf1\b/i.test(r.trim())) },
    };
  }

  if (!spf) {
    return {
      id: 'spf',
      category: 'Email Deliverability',
      title: 'SPF',
      status: 'fail',
      severity: sendsMail ? 'high' : 'medium',
      summary: 'No SPF record',
      detail: `${domain} publishes no SPF record, so receivers cannot tell which servers are allowed to send as this domain.`,
      recommendation:
        'Publish an SPF TXT record listing your legitimate senders and ending in "-all" (hard fail), e.g. "v=spf1 include:_spf.google.com -all".',
    };
  }

  // A broken record outranks every other SPF finding: receivers ignore it.
  const syntax = validateSpfSyntax(spf);
  if (syntax.problems.length) {
    return {
      id: 'spf',
      category: 'Email Deliverability',
      title: 'SPF',
      status: 'fail',
      severity: sendsMail ? 'high' : 'medium',
      summary: 'SPF record has a typo, so it does not work',
      detail:
        `Record: ${spf}. ${syntax.problems.join(' ')} ` +
        'Mail servers that check SPF strictly treat the whole record as broken.',
      recommendation: syntax.fixed
        ? `Edit your SPF record (do not add a second one) so it reads exactly: ${syntax.fixed}`
        : 'Fix the parts listed above in your SPF record. Your email provider’s setup guide shows the correct format.',
      evidence: { record: spf, problems: syntax.problems, fixed: syntax.fixed },
    };
  }

  const all = spf.match(/[~\-?+]all\b/i)?.[0]?.toLowerCase();
  let status = 'pass';
  let severity = 'info';
  let recommendation;
  let summary = 'SPF published with hard fail';

  if (!all) {
    status = 'warn';
    severity = 'medium';
    summary = 'SPF record has no "all" mechanism';
    recommendation = 'End your SPF record with "-all" so unauthorised senders are rejected.';
  } else if (all === '+all') {
    status = 'fail';
    severity = 'high';
    summary = 'SPF allows any sender ("+all")';
    recommendation = 'Replace "+all" with "-all"; "+all" authorises the entire internet to send as you.';
  } else if (all === '~all' || all === '?all') {
    status = 'warn';
    severity = 'low';
    summary = `SPF uses soft policy ("${all}")`;
    recommendation = 'Tighten the SPF record to "-all" once you are confident all legitimate senders are listed.';
  }

  // RFC 7208 caps SPF at 10 DNS-querying mechanisms; exceeding it makes SPF
  // fail "permerror" and silently stop protecting the domain.
  const lookups = await countSpfLookups(resolver, spf);
  if (lookups > 10 && status === 'pass') {
    status = 'warn';
    severity = 'medium';
    summary = 'SPF exceeds the 10 DNS-lookup limit';
    recommendation = 'Flatten or consolidate includes so SPF stays within 10 DNS lookups, otherwise it returns permerror.';
  }

  return {
    id: 'spf',
    category: 'Email Deliverability',
    title: 'SPF',
    status,
    severity,
    summary,
    detail: `Record: ${spf}`,
    recommendation,
    evidence: { record: spf, lookups, all: all ?? null },
  };
}

// Counts DNS lookups the way receivers do: every include, a, mx, ptr, exists
// and redirect costs one, and includes are followed into their own records.
export async function countSpfLookups(resolver, record, depth = 0, seen = new Set()) {
  if (typeof record !== 'string' || depth > 10) return 0;
  const terms = record.trim().split(/\s+/).slice(1).map((t) => t.replace(/,+$/, '').replace(/^[+\-~?]/, ''));
  let count = 0;
  const follow = [];
  for (const term of terms) {
    const m = term.match(/^(?:include:|redirect=)(.+)$/i);
    if (m) {
      count += 1;
      const target = m[1].toLowerCase().replace(/\.$/, '');
      if (!seen.has(target)) {
        seen.add(target);
        follow.push(target);
      }
    } else if (/^(a|mx|ptr)(?:[:/]|$)/i.test(term) || /^exists:/i.test(term)) {
      count += 1;
    }
  }
  const nested = await Promise.all(
    follow.map(async (target) => {
      const txt = await resolver.txt(target).catch(() => []);
      return countSpfLookups(resolver, parseSpf(txt), depth + 1, seen);
    }),
  );
  return count + nested.reduce((a, b) => a + b, 0);
}

export function parseDmarc(txtRecords) {
  const recs = txtRecords.filter((r) => /^v=dmarc1\b/i.test(r.trim()));
  const rec = recs[0] ?? null;
  if (!rec) return null;
  const tags = {};
  for (const part of rec.split(';')) {
    const [k, v] = part.split('=').map((s) => s && s.trim());
    if (k && v) tags[k.toLowerCase()] = v;
  }
  // "mailto:a@x.com!10m,mailto:b@y.com" -> ["a@x.com", "b@y.com"]
  const rua = (tags.rua ?? '')
    .split(',')
    .map((u) => u.trim().replace(/^mailto:/i, '').replace(/!.*$/, ''))
    .filter(Boolean);
  return { record: rec, tags, rua, count: recs.length };
}

export async function checkDmarc(resolver, domain, { sendsMail = true } = {}) {
  const txt = await resolver.txt(`_dmarc.${domain}`);
  const parsed = parseDmarc(txt);

  if (!parsed) {
    return {
      id: 'dmarc',
      category: 'Email Deliverability',
      title: 'DMARC',
      status: 'fail',
      severity: sendsMail ? 'critical' : 'high',
      summary: 'No DMARC record',
      detail: `${domain} has no DMARC policy, so spoofed mail is not detected or reported.`,
      recommendation:
        'Start with "v=DMARC1; p=none; rua=mailto:dmarc@yourdomain" to collect reports, then move to "p=quarantine" and finally "p=reject".',
    };
  }

  const policy = (parsed.tags.p ?? 'none').toLowerCase();
  const hasReporting = Boolean(parsed.tags.rua);
  let status;
  let severity;
  let summary;
  let recommendation;

  if (policy === 'reject') {
    status = 'pass';
    severity = 'info';
    summary = 'DMARC enforced (p=reject)';
  } else if (policy === 'quarantine') {
    status = 'pass';
    severity = 'low';
    summary = 'DMARC enforced (p=quarantine)';
    recommendation = 'Move to "p=reject" once reports confirm all legitimate mail passes.';
  } else {
    status = 'warn';
    severity = 'high';
    summary = 'DMARC in monitor-only mode (p=none)';
    recommendation =
      'p=none does not stop spoofing. After reviewing reports, raise the policy to "p=quarantine" then "p=reject".';
  }

  if (!hasReporting && !recommendation) {
    recommendation = 'Add a "rua=" address so you receive aggregate reports about who is sending as your domain.';
  }

  return {
    id: 'dmarc',
    category: 'Email Deliverability',
    title: 'DMARC',
    status,
    severity,
    summary,
    detail: `Record: ${parsed.record}`,
    recommendation,
    evidence: {
      policy,
      reporting: hasReporting,
      record: parsed.record,
      tags: parsed.tags,
      rua: parsed.rua,
      count: parsed.count,
    },
  };
}

// DKIM has no way to enumerate selectors from DNS, so we probe the selectors
// used by the most common mail providers, plus any the SPF senders imply.
export const COMMON_DKIM_SELECTORS = [
  'google', 'default', 'selector1', 'selector2', 'k1', 'k2', 'k3',
  'mandrill', 's1', 's2', 'mail', 'dkim', 'protonmail', 'zoho', 'pm',
  'fm1', 'fm2', 'fm3', 'mxvault', 'everlytickey1', 'everlytickey2',
];

// A usable key has a non-empty p= value (an empty p= means the key is revoked).
export function isValidDkimRecord(record) {
  return /(?:^|;)\s*p=\s*[A-Za-z0-9+/]/.test(String(record));
}

export async function checkDkim(resolver, domain, { sendsMail = true, extraSelectors = [] } = {}) {
  const selectors = [...new Set([...COMMON_DKIM_SELECTORS, ...extraSelectors])];
  const found = [];
  await Promise.all(
    selectors.map(async (sel) => {
      const txt = await resolver.txt(`${sel}._domainkey.${domain}`);
      if (txt.some(isValidDkimRecord)) found.push(sel);
    }),
  );
  found.sort((a, b) => selectors.indexOf(a) - selectors.indexOf(b));

  if (found.length > 0) {
    return {
      id: 'dkim',
      category: 'Email Deliverability',
      title: 'DKIM',
      status: 'pass',
      severity: 'info',
      summary: `DKIM key found (${found.join(', ')})`,
      detail: `Discovered DKIM selectors: ${found.join(', ')}.`,
      evidence: { selectors: found, checked: selectors },
    };
  }

  return {
    id: 'dkim',
    category: 'Email Deliverability',
    title: 'DKIM',
    status: sendsMail ? 'warn' : 'info',
    severity: sendsMail ? 'medium' : 'info',
    summary: 'No DKIM key found on common selectors',
    detail: `No DKIM record was found on the ${selectors.length} selectors we probe. DKIM may still be configured under a custom selector.`,
    recommendation: sendsMail
      ? 'Confirm DKIM signing is enabled with your mail provider and that the published selector matches your DNS.'
      : undefined,
    evidence: { selectors: [], checked: selectors },
  };
}

// Fetches https://mta-sts.<domain>/.well-known/mta-sts.txt and resolves its
// text, or null if it is missing or unreachable. Small and time-boxed.
export function fetchMtaStsPolicy(domain, { timeoutMs = 5000, requestImpl = https.request } = {}) {
  return new Promise((resolve) => {
    let body = '';
    let done = false;
    const finish = (v) => {
      if (done) return;
      done = true;
      resolve(v);
    };
    const req = requestImpl(
      { host: `mta-sts.${domain}`, port: 443, path: '/.well-known/mta-sts.txt', method: 'GET', timeout: timeoutMs },
      (res) => {
        if (res.statusCode !== 200) {
          res.resume?.();
          return finish(null);
        }
        res.setEncoding?.('utf8');
        res.on('data', (c) => {
          body += c;
          if (body.length > 64 * 1024) req.destroy();
        });
        res.on('end', () => finish(body));
        res.on('error', () => finish(null));
      },
    );
    req.on('timeout', () => {
      req.destroy();
      finish(null);
    });
    req.on('error', () => finish(null));
    req.end();
  });
}

export function isValidMtaStsPolicy(text) {
  return typeof text === 'string' && /^\s*version:\s*STSv1\s*$/im.test(text) && /^\s*mode:\s*(enforce|testing|none)\s*$/im.test(text);
}

export async function checkMtaSts(resolver, domain, { sendsMail = true, fetchPolicy = fetchMtaStsPolicy } = {}) {
  const txt = await resolver.txt(`_mta-sts.${domain}`);
  const has = txt.some((r) => /^v=stsv1\b/i.test(r.trim()));
  // The policy file only matters once the DNS record points to it.
  const policy = has ? isValidMtaStsPolicy(await fetchPolicy(domain).catch(() => null)) : false;
  const evidence = { txt: has, policy };
  if (!sendsMail) {
    return {
      id: 'mta-sts',
      category: 'Email Deliverability',
      title: 'MTA-STS',
      status: 'info',
      severity: 'info',
      summary: 'Not applicable (domain receives no mail)',
      detail: 'MTA-STS only applies to domains that receive email.',
      evidence,
    };
  }
  if (has && !policy) {
    return {
      id: 'mta-sts',
      category: 'Email Deliverability',
      title: 'MTA-STS',
      status: 'warn',
      severity: 'low',
      summary: 'MTA-STS record found, but the policy file is missing',
      detail: `The _mta-sts record exists, but https://mta-sts.${domain}/.well-known/mta-sts.txt did not return a valid policy.`,
      recommendation: `Publish the policy file at https://mta-sts.${domain}/.well-known/mta-sts.txt so senders can read it.`,
      evidence,
    };
  }
  return {
    id: 'mta-sts',
    category: 'Email Deliverability',
    title: 'MTA-STS',
    status: has ? 'pass' : 'warn',
    severity: has ? 'info' : 'low',
    summary: has ? 'MTA-STS policy published' : 'No MTA-STS policy',
    detail: has
      ? 'An MTA-STS TXT record and policy file are present, enforcing TLS for inbound mail.'
      : `${domain} has no MTA-STS policy, so inbound mail can be delivered over unencrypted connections.`,
    recommendation: has
      ? undefined
      : 'Publish an MTA-STS policy and TLS-RPT record to require encryption for mail sent to you.',
    evidence,
  };
}

export async function checkBimi(resolver, domain) {
  const txt = await resolver.txt(`default._bimi.${domain}`);
  const has = txt.some((r) => /^v=bimi1\b/i.test(r.trim()));
  return {
    id: 'bimi',
    category: 'Email Deliverability',
    title: 'BIMI',
    status: has ? 'pass' : 'info',
    severity: 'info',
    summary: has ? 'BIMI logo published' : 'No BIMI record',
    detail: has
      ? 'A BIMI record is present, allowing your verified logo to appear in supporting inboxes.'
      : 'BIMI is optional and requires enforced DMARC first. It displays your brand logo in supporting inboxes.',
    recommendation: has
      ? undefined
      : 'Once DMARC is at enforcement, consider BIMI (with a VMC) to show your verified logo in inboxes.',
  };
}
