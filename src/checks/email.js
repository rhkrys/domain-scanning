// Email authentication checks. These are the highest-impact findings for most
// domains: weak SPF/DMARC is what lets attackers spoof a business's address.

export function parseSpf(txtRecords) {
  return txtRecords.find((r) => /^v=spf1\b/i.test(r.trim())) ?? null;
}

export async function checkSpf(resolver, domain, { sendsMail = true } = {}) {
  const txt = await resolver.txt(domain);
  const spf = parseSpf(txt);

  if (!spf) {
    return {
      id: 'spf',
      category: 'Email Authentication',
      title: 'SPF',
      status: 'fail',
      severity: sendsMail ? 'high' : 'medium',
      summary: 'No SPF record',
      detail: `${domain} publishes no SPF record, so receivers cannot tell which servers are allowed to send as this domain.`,
      recommendation:
        'Publish an SPF TXT record listing your legitimate senders and ending in "-all" (hard fail), e.g. "v=spf1 include:_spf.google.com -all".',
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
  const lookups = (spf.match(/\b(include|a|mx|ptr|exists|redirect)[:=]/gi) ?? []).length;
  if (lookups > 10 && status === 'pass') {
    status = 'warn';
    severity = 'medium';
    summary = 'SPF exceeds the 10 DNS-lookup limit';
    recommendation = 'Flatten or consolidate includes so SPF stays within 10 DNS lookups, otherwise it returns permerror.';
  }

  return {
    id: 'spf',
    category: 'Email Authentication',
    title: 'SPF',
    status,
    severity,
    summary,
    detail: `Record: ${spf}`,
    recommendation,
    evidence: { record: spf, lookups },
  };
}

export function parseDmarc(txtRecords) {
  const rec = txtRecords.find((r) => /^v=dmarc1\b/i.test(r.trim())) ?? null;
  if (!rec) return null;
  const tags = {};
  for (const part of rec.split(';')) {
    const [k, v] = part.split('=').map((s) => s && s.trim());
    if (k && v) tags[k.toLowerCase()] = v;
  }
  return { record: rec, tags };
}

export async function checkDmarc(resolver, domain, { sendsMail = true } = {}) {
  const txt = await resolver.txt(`_dmarc.${domain}`);
  const parsed = parseDmarc(txt);

  if (!parsed) {
    return {
      id: 'dmarc',
      category: 'Email Authentication',
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
    category: 'Email Authentication',
    title: 'DMARC',
    status,
    severity,
    summary,
    detail: `Record: ${parsed.record}`,
    recommendation,
    evidence: { policy, reporting: hasReporting },
  };
}

// DKIM has no way to enumerate selectors from DNS, so we probe the selectors
// used by the most common mail providers.
const COMMON_DKIM_SELECTORS = [
  'google', 'selector1', 'selector2', 'k1', 'k2', 'k3',
  's1', 's2', 'dkim', 'mail', 'default', 'mandrill',
  'mxvault', 'zoho', 'fm1', 'fm2', 'fm3', 'protonmail', 'pic',
];

export async function checkDkim(resolver, domain, { sendsMail = true } = {}) {
  const found = [];
  await Promise.all(
    COMMON_DKIM_SELECTORS.map(async (sel) => {
      const txt = await resolver.txt(`${sel}._domainkey.${domain}`);
      if (txt.some((r) => /v=dkim1|k=rsa|p=/i.test(r))) found.push(sel);
    }),
  );

  if (found.length > 0) {
    return {
      id: 'dkim',
      category: 'Email Authentication',
      title: 'DKIM',
      status: 'pass',
      severity: 'info',
      summary: `DKIM key found (${found.join(', ')})`,
      detail: `Discovered DKIM selectors: ${found.join(', ')}.`,
      evidence: { selectors: found },
    };
  }

  return {
    id: 'dkim',
    category: 'Email Authentication',
    title: 'DKIM',
    status: sendsMail ? 'warn' : 'info',
    severity: sendsMail ? 'medium' : 'info',
    summary: 'No DKIM key found on common selectors',
    detail: `No DKIM record was found on the ${COMMON_DKIM_SELECTORS.length} selectors we probe. DKIM may still be configured under a custom selector.`,
    recommendation: sendsMail
      ? 'Confirm DKIM signing is enabled with your mail provider and that the published selector matches your DNS.'
      : undefined,
  };
}

export async function checkMtaSts(resolver, domain, { sendsMail = true } = {}) {
  const txt = await resolver.txt(`_mta-sts.${domain}`);
  const has = txt.some((r) => /^v=stsv1\b/i.test(r.trim()));
  if (!sendsMail) {
    return {
      id: 'mta-sts',
      category: 'Email Authentication',
      title: 'MTA-STS',
      status: 'info',
      severity: 'info',
      summary: 'Not applicable (domain receives no mail)',
      detail: 'MTA-STS only applies to domains that receive email.',
    };
  }
  return {
    id: 'mta-sts',
    category: 'Email Authentication',
    title: 'MTA-STS',
    status: has ? 'pass' : 'warn',
    severity: has ? 'info' : 'low',
    summary: has ? 'MTA-STS policy published' : 'No MTA-STS policy',
    detail: has
      ? 'An MTA-STS TXT record is present, enforcing TLS for inbound mail.'
      : `${domain} has no MTA-STS policy, so inbound mail can be delivered over unencrypted connections.`,
    recommendation: has
      ? undefined
      : 'Publish an MTA-STS policy and TLS-RPT record to require encryption for mail sent to you.',
  };
}

export async function checkBimi(resolver, domain) {
  const txt = await resolver.txt(`default._bimi.${domain}`);
  const has = txt.some((r) => /^v=bimi1\b/i.test(r.trim()));
  return {
    id: 'bimi',
    category: 'Email Authentication',
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
