// Who hosts a domain's DNS, from its nameservers. This is where the owner adds
// or changes SPF, DKIM and DMARC records, so the report names it next to the
// email provider. Unknown hosts fall back to the nameservers' own domain.

export const DNS_HOSTS = [
  { id: 'godaddy', name: 'GoDaddy', match: ['domaincontrol.com'] },
  { id: 'route53', name: 'Amazon Route 53', match: ['awsdns-'] },
  { id: 'cloudflare', name: 'Cloudflare', match: ['ns.cloudflare.com'] },
  { id: 'google', name: 'Google Cloud DNS', match: ['googledomains.com', 'google.com'] },
  { id: 'squarespace', name: 'Squarespace', match: ['squarespacedns.com'] },
  { id: 'wix', name: 'Wix', match: ['wixdns.net'] },
  { id: 'namecheap', name: 'Namecheap', match: ['registrar-servers.com'] },
  { id: 'hostinger', name: 'Hostinger', match: ['dns-parking.com', 'hostinger.com'] },
  { id: 'bluehost', name: 'Bluehost', match: ['bluehost.com'] },
  { id: 'hostgator', name: 'HostGator', match: ['hostgator.com'] },
  { id: 'dreamhost', name: 'DreamHost', match: ['dreamhost.com'] },
  { id: 'ionos', name: 'IONOS', match: ['ui-dns.com', 'ui-dns.de', 'ui-dns.org', 'ui-dns.biz'] },
  { id: 'namecom', name: 'Name.com', match: ['name.com'] },
  { id: 'networksolutions', name: 'Network Solutions', match: ['worldnic.com'] },
  { id: 'digitalocean', name: 'DigitalOcean', match: ['digitalocean.com'] },
  { id: 'azure', name: 'Azure DNS', match: ['azure-dns.com', 'azure-dns.net', 'azure-dns.org', 'azure-dns.info'] },
  { id: 'ns1', name: 'NS1', match: ['nsone.net'] },
  { id: 'akamai', name: 'Akamai', match: ['akam.net'] },
  { id: 'ultradns', name: 'UltraDNS', match: ['ultradns.com', 'ultradns.net', 'ultradns.org', 'ultradns.biz'] },
  { id: 'dnsimple', name: 'DNSimple', match: ['dnsimple.com'] },
  { id: 'hover', name: 'Hover', match: ['hover.com'] },
  { id: 'siteground', name: 'SiteGround', match: ['siteground.net'] },
  { id: 'wpengine', name: 'WP Engine', match: ['wpengine.com'] },
  { id: 'shopify', name: 'Shopify', match: ['shopify.com'] },
  { id: 'ovh', name: 'OVH', match: ['ovh.net'] },
  { id: 'gandi', name: 'Gandi', match: ['gandi.net'] },
];

function cleanHost(host) {
  return String(host ?? '').trim().toLowerCase().replace(/\.$/, '');
}

// Returns { id, name, nameservers, known }. For an unknown host, name is the
// nameservers' shared domain (for example "someisp.net") so the owner still
// knows where to look.
export function detectDnsHost(nameservers = []) {
  const hosts = nameservers.map(cleanHost).filter(Boolean);
  if (hosts.length === 0) return { id: null, name: null, nameservers: [], known: false };
  for (const h of hosts) {
    const hit = DNS_HOSTS.find((d) => d.match.some((m) => (m.endsWith('-') ? h.includes(m) : h === m || h.endsWith(`.${m}`))));
    if (hit) return { id: hit.id, name: hit.name, nameservers: hosts, known: true };
  }
  const domains = [...new Set(hosts.map((h) => h.split('.').slice(-2).join('.')))];
  return { id: null, name: domains.join(' and '), nameservers: hosts, known: false };
}
