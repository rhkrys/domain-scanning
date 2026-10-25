// Six fixed scans for the report model and email snapshot tests. Everything is
// offline: fake DNS, a fake home page, a fake certificate, and a fixed clock.

import { FakeResolver } from '../helpers.js';
import { runAudit } from '../../src/audit.js';
import { evaluateCertificate } from '../../src/checks/tls.js';

export const NOW = new Date('2026-10-25T15:00:00Z');
const DKIM_KEY = 'v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC';

const ALL_HEADERS = {
  'strict-transport-security': 'max-age=31536000',
  'content-security-policy': "default-src 'self'",
  'x-frame-options': 'DENY',
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'strict-origin-when-cross-origin',
  'permissions-policy': 'camera=()',
};

const certIn = (days) => {
  const validTo = new Date(NOW.getTime() + days * 86400000);
  return async () =>
    evaluateCertificate(
      { valid_from: 'Jan 1 00:00:00 2026 GMT', valid_to: validTo.toUTCString(), subject: { CN: 'x' }, issuer: { O: 'CA' } },
      'TLSv1.3',
      NOW,
    );
};

function dns(domain, extra = {}) {
  return new FakeResolver({
    [`${domain}|MX`]: ['1 aspmx.l.google.com.'],
    [`${domain}|A`]: ['192.0.2.10'],
    [`${domain}|NS`]: ['ns1.a.net.', 'ns2.b.net.'],
    '_spf.google.com|TXT': ['v=spf1 include:_netblocks.google.com ~all'],
    ...extra,
  });
}

const page = (headers = ALL_HEADERS, html = '<h1>Hello</h1>') => async () => ({
  headers,
  html,
  url: 'https://example.com/',
  redirects: [],
});

const policy = async () => 'version: STSv1\nmode: enforce\nmx: aspmx.l.google.com\nmax_age: 86400\n';

export const SCENARIOS = {
  'all-pass': () =>
    runAudit('allpass.com', {
      resolver: dns('allpass.com', {
        'allpass.com|TXT': ['v=spf1 include:_spf.google.com -all'],
        '_dmarc.allpass.com|TXT': ['v=DMARC1; p=reject; rua=mailto:dmarc@allpass.com'],
        'google._domainkey.allpass.com|TXT': [DKIM_KEY],
        '_mta-sts.allpass.com|TXT': ['v=STSv1; id=20261001'],
        'default._bimi.allpass.com|TXT': ['v=BIMI1; l=https://allpass.com/logo.svg'],
        'allpass.com|CAA': ['0 issue "letsencrypt.org"'],
        'allpass.com|DS': ['12345 13 2 ABCD'],
      }),
      loadPage: page(),
      fetchPolicy: policy,
      tlsCheck: certIn(90),
      now: NOW,
    }),

  'spf-ok-dmarc-missing': () =>
    runAudit('nodmarc.com', {
      resolver: dns('nodmarc.com', {
        'nodmarc.com|TXT': ['v=spf1 include:_spf.google.com ~all'],
        'google._domainkey.nodmarc.com|TXT': [DKIM_KEY],
      }),
      loadPage: page(),
      fetchPolicy: policy,
      tlsCheck: certIn(90),
      now: NOW,
    }),

  'dkim-missing-one-sender': () =>
    runAudit('twosenders.com', {
      resolver: dns('twosenders.com', {
        'twosenders.com|TXT': ['v=spf1 include:_spf.google.com include:servers.mcsv.net ~all'],
        '_dmarc.twosenders.com|TXT': ['v=DMARC1; p=quarantine; rua=mailto:reports@twosenders.com'],
        'google._domainkey.twosenders.com|TXT': [DKIM_KEY],
      }),
      loadPage: page(),
      fetchPolicy: policy,
      tlsCheck: certIn(90),
      now: NOW,
    }),

  'no-cert': () =>
    runAudit('nocert.com', {
      resolver: dns('nocert.com', {
        'nocert.com|TXT': ['v=spf1 include:_spf.google.com ~all'],
        '_dmarc.nocert.com|TXT': ['v=DMARC1; p=none; rua=mailto:dmarc@nocert.com'],
        'google._domainkey.nocert.com|TXT': [DKIM_KEY],
      }),
      loadPage: async () => null,
      fetchPolicy: policy,
      tlsCheck: async () => evaluateCertificate(null, null, NOW),
      now: NOW,
    }),

  'wordpress-headers': () =>
    runAudit('wpsite.com', {
      resolver: dns('wpsite.com', {
        'wpsite.com|TXT': ['v=spf1 include:_spf.google.com ~all'],
        '_dmarc.wpsite.com|TXT': ['v=DMARC1; p=reject; rua=mailto:dmarc@wpsite.com'],
        'google._domainkey.wpsite.com|TXT': [DKIM_KEY],
      }),
      loadPage: page(
        { 'x-powered-by': 'PHP/8.4.27', server: 'Apache/2.4.58', 'x-content-type-options': 'nosniff' },
        '<meta name="generator" content="WordPress 6.5.2"><link href="/wp-content/themes/x.css">',
      ),
      fetchPolicy: policy,
      tlsCheck: certIn(90),
      now: NOW,
    }),

  'cert-expiring-soon': () =>
    runAudit('soon.com', {
      resolver: dns('soon.com', {
        'soon.com|TXT': ['v=spf1 include:_spf.google.com ~all'],
        '_dmarc.soon.com|TXT': ['v=DMARC1; p=reject; rua=mailto:dmarc@soon.com'],
        'google._domainkey.soon.com|TXT': [DKIM_KEY],
      }),
      loadPage: page(),
      fetchPolicy: policy,
      tlsCheck: certIn(20),
      now: NOW,
    }),
};
