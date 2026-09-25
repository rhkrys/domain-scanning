// DNS resolver used by every check.
//
// The deployed environment frequently blocks outbound UDP/53, so we resolve
// over DNS-over-HTTPS (RFC 8484 JSON form) and fall back to the native
// resolver only when DoH is unreachable. The public surface is intentionally
// tiny so checks can be unit-tested against a fake resolver.

import dns from 'node:dns';

const DOH_ENDPOINTS = [
  'https://cloudflare-dns.com/dns-query',
  'https://dns.google/resolve',
];

const TYPE_NAMES = {
  1: 'A',
  28: 'AAAA',
  2: 'NS',
  15: 'MX',
  16: 'TXT',
  257: 'CAA',
  43: 'DS',
  48: 'DNSKEY',
  5: 'CNAME',
};

// Strip the quoting/segmentation DoH applies to long TXT records so callers
// see the same string a recursive resolver would hand back.
function normaliseTxt(data) {
  return data
    .replace(/^"|"$/g, '')
    .replace(/"\s+"/g, '')
    .replace(/\\"/g, '"');
}

export class Resolver {
  constructor({ timeoutMs = 6000, fetchImpl = fetch } = {}) {
    this.timeoutMs = timeoutMs;
    this.fetchImpl = fetchImpl;
  }

  async _doh(name, type) {
    let lastError;
    for (const endpoint of DOH_ENDPOINTS) {
      const url = `${endpoint}?name=${encodeURIComponent(name)}&type=${type}`;
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this.timeoutMs);
      try {
        const res = await this.fetchImpl(url, {
          headers: { accept: 'application/dns-json' },
          signal: controller.signal,
        });
        if (!res.ok) throw new Error(`DoH HTTP ${res.status}`);
        return await res.json();
      } catch (err) {
        lastError = err;
      } finally {
        clearTimeout(timer);
      }
    }
    throw lastError ?? new Error('All DoH endpoints failed');
  }

  // Returns { status, ad, records: [{type, data}] }.
  // status mirrors the DNS RCODE (0 = NOERROR, 3 = NXDOMAIN).
  async query(name, type) {
    const typeName = typeof type === 'number' ? TYPE_NAMES[type] ?? String(type) : type;
    try {
      const json = await this._doh(name, typeName);
      const answers = (json.Answer ?? []).map((a) => ({
        type: TYPE_NAMES[a.type] ?? String(a.type),
        data: a.type === 16 ? normaliseTxt(a.data) : a.data,
        ttl: a.TTL,
      }));
      return { status: json.Status ?? 0, ad: Boolean(json.AD), records: answers };
    } catch (err) {
      return this._native(name, typeName, err);
    }
  }

  async _native(name, typeName, dohError) {
    const r = dns.promises;
    try {
      let records = [];
      switch (typeName) {
        case 'A':
          records = (await r.resolve4(name)).map((d) => ({ type: 'A', data: d }));
          break;
        case 'AAAA':
          records = (await r.resolve6(name)).map((d) => ({ type: 'AAAA', data: d }));
          break;
        case 'NS':
          records = (await r.resolveNs(name)).map((d) => ({ type: 'NS', data: d }));
          break;
        case 'MX':
          // Mirror the DoH wire form "<priority> <exchange>"; a null MX has an
          // empty exchange which we render as "." to match RFC 7505.
          records = (await r.resolveMx(name)).map((d) => ({ type: 'MX', data: `${d.priority} ${d.exchange || '.'}` }));
          break;
        case 'TXT':
          records = (await r.resolveTxt(name)).map((d) => ({ type: 'TXT', data: d.join('') }));
          break;
        case 'CAA':
          records = (await r.resolveCaa(name)).map((d) => ({ type: 'CAA', data: JSON.stringify(d) }));
          break;
        default:
          throw dohError ?? new Error(`Unsupported type ${typeName} for native resolver`);
      }
      return { status: 0, ad: false, records };
    } catch (err) {
      if (err.code === 'ENOTFOUND' || err.code === 'ENODATA') {
        return { status: err.code === 'ENOTFOUND' ? 3 : 0, ad: false, records: [] };
      }
      // Surface the original DoH failure: it is the more informative one.
      throw dohError ?? err;
    }
  }

  async txt(name) {
    return (await this.query(name, 'TXT')).records.map((r) => r.data);
  }
}
