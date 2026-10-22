// Foundational DNS checks: does the domain resolve, can it receive mail,
// is its nameserver setup diverse, and does it pin a certificate authority.

export async function checkAddressing(resolver, domain) {
  const [a, aaaa] = await Promise.all([
    resolver.query(domain, 'A'),
    resolver.query(domain, 'AAAA'),
  ]);
  const hasA = a.records.length > 0;
  const hasAAAA = aaaa.records.length > 0;

  if (!hasA && !hasAAAA) {
    return {
      id: 'addressing',
      category: 'DNS Foundation',
      title: 'A / AAAA records',
      status: 'warn',
      severity: 'low',
      summary: 'No A or AAAA records found',
      detail: `${domain} does not resolve to an IPv4 or IPv6 address.`,
      recommendation:
        'If this domain is meant to host a website, add an A (and ideally AAAA) record pointing at your server.',
    };
  }
  return {
    id: 'addressing',
    category: 'DNS Foundation',
    title: 'A / AAAA records',
    status: hasAAAA ? 'pass' : 'info',
    severity: 'info',
    summary: hasAAAA ? 'IPv4 and IPv6 reachable' : 'IPv4 only (no IPv6)',
    detail: `A: ${a.records.map((r) => r.data).join(', ') || 'none'}; AAAA: ${
      aaaa.records.map((r) => r.data).join(', ') || 'none'
    }.`,
    recommendation: hasAAAA
      ? undefined
      : 'Consider adding an AAAA record so IPv6-only clients can reach you.',
  };
}

// MX data arrives as "<priority> <exchange>" from both DoH and the native
// fallback; the exchange is the final whitespace-separated token.
function mxExchange(data) {
  const parts = String(data).trim().split(/\s+/);
  return (parts[parts.length - 1] || '').replace(/\.$/, '').toLowerCase();
}

export async function checkMx(resolver, domain) {
  const mx = await resolver.query(domain, 'MX');
  const exchanges = mx.records.map((r) => mxExchange(r.data));
  // RFC 7505 "null MX": a single record with an empty exchange ("0 .") is an
  // explicit declaration that the domain neither sends nor receives mail.
  const nullMx = exchanges.length === 1 && exchanges[0] === '';
  const hosts = exchanges.filter((h) => h !== '');

  if (hosts.length === 0) {
    return {
      id: 'mx',
      category: 'DNS Foundation',
      title: 'MX records',
      status: 'info',
      severity: 'info',
      summary: nullMx ? 'Null MX — domain declines mail' : 'No mail servers configured',
      detail: nullMx
        ? `${domain} publishes a null MX (RFC 7505), explicitly declaring it sends and receives no email.`
        : `${domain} has no MX records, so it does not receive email directly.`,
      recommendation: nullMx
        ? undefined
        : 'If this domain should not send or receive mail, publish "v=spf1 -all", a strict DMARC policy and a null MX record to stop spoofing.',
      evidence: { sendsMail: false, nullMx },
    };
  }
  return {
    id: 'mx',
    category: 'DNS Foundation',
    title: 'MX records',
    status: 'pass',
    severity: 'info',
    summary: `${hosts.length} mail server${hosts.length > 1 ? 's' : ''} configured`,
    detail: `Mail is routed to: ${hosts.join(', ')}.`,
    evidence: { sendsMail: true, hosts },
  };
}

export async function checkNameservers(resolver, domain) {
  const ns = await resolver.query(domain, 'NS');
  const hosts = ns.records.map((r) => r.data.replace(/\.$/, '').toLowerCase());

  if (hosts.length === 0) {
    return {
      id: 'nameservers',
      category: 'DNS Foundation',
      title: 'Nameservers',
      status: 'fail',
      severity: 'high',
      summary: 'No nameservers found',
      detail: `${domain} has no delegated nameservers, which usually means the domain is misconfigured or expired.`,
      recommendation: 'Check the domain registration and DNS delegation at your registrar.',
    };
  }

  // A second-level-domain summary tells us whether the zone is served by a
  // single provider (single point of failure) or spread across providers.
  const providers = new Set(
    hosts.map((h) => h.split('.').slice(-2).join('.')),
  );
  const diverse = hosts.length >= 2;

  return {
    id: 'nameservers',
    category: 'DNS Foundation',
    title: 'Nameservers',
    status: diverse ? 'pass' : 'warn',
    severity: diverse ? 'info' : 'low',
    summary: diverse
      ? `${hosts.length} nameservers (${providers.size} provider${providers.size > 1 ? 's' : ''})`
      : 'Only one nameserver',
    detail: `Nameservers: ${hosts.join(', ')}.`,
    recommendation: diverse
      ? undefined
      : 'Add at least one more nameserver (ideally on separate infrastructure) so DNS stays up if one fails.',
  };
}

export async function checkCaa(resolver, domain) {
  const caa = await resolver.query(domain, 'CAA');
  const has = caa.records.length > 0;
  return {
    id: 'caa',
    category: 'DNS Foundation',
    title: 'CAA record',
    status: has ? 'pass' : 'warn',
    severity: has ? 'info' : 'low',
    summary: has ? 'Certificate issuance restricted' : 'No CAA record',
    detail: has
      ? `CAA records present: ${caa.records.map((r) => r.data).join('; ')}.`
      : `${domain} has no CAA record, so any certificate authority can issue certificates for it.`,
    recommendation: has
      ? undefined
      : 'Publish a CAA record naming only the CAs you use (e.g. "0 issue \\"letsencrypt.org\\"") to limit mis-issuance.',
  };
}
