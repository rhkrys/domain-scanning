// DNSSEC presence. We look for a DS record at the parent (the signal that the
// delegation is signed) and corroborate with the resolver's Authenticated Data
// flag.

export async function checkDnssec(resolver, domain) {
  const [ds, soa] = await Promise.all([
    resolver.query(domain, 'DS'),
    resolver.query(domain, 'A'),
  ]);
  const signed = ds.records.length > 0 || ds.ad || soa.ad;

  return {
    id: 'dnssec',
    category: 'DNS Foundation',
    title: 'DNSSEC',
    status: signed ? 'pass' : 'warn',
    severity: signed ? 'info' : 'medium',
    summary: signed ? 'DNSSEC enabled' : 'DNSSEC not enabled',
    detail: signed
      ? `${domain} is DNSSEC-signed, protecting against DNS spoofing and cache poisoning.`
      : `${domain} is not DNSSEC-signed, so DNS responses cannot be cryptographically verified.`,
    recommendation: signed
      ? undefined
      : 'Enable DNSSEC at your DNS provider and add the DS record at your registrar to protect against DNS tampering.',
  };
}
