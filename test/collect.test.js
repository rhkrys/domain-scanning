import { test } from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { FakeResolver } from './helpers.js';
import { detectVersionLeaks } from '../src/checks/software.js';
import { securityHeaderPresence } from '../src/checks/headers.js';
import { evaluateCertificate } from '../src/checks/tls.js';
import { checkMtaSts, isValidMtaStsPolicy, fetchMtaStsPolicy } from '../src/checks/email.js';
import { runAudit } from '../src/audit.js';

const page = (headers = {}, html = '') => ({ headers, html, url: 'https://example.com/' });
const now = new Date('2026-10-25T12:00:00Z');
const cert = (validTo) => ({
  valid_from: 'Jan 1 00:00:00 2026 GMT',
  valid_to: validTo,
  subject: { CN: 'example.com' },
  issuer: { O: "Let's Encrypt" },
});

test('version leaks: X-Powered-By PHP, Server version, X-Generator, WordPress tag', () => {
  const r = detectVersionLeaks(
    page(
      { 'x-powered-by': 'PHP/8.3.20', server: 'nginx/1.24.0', 'x-generator': 'Drupal 10' },
      '<meta name="generator" content="WordPress 6.5.2">',
    ),
  );
  assert.deepEqual(r.leaks.map((l) => l.header), ['X-Powered-By', 'Server', 'X-Generator', 'generator tag']);
  assert.equal(r.wordpress, true);
  assert.equal(r.checked, true);
});

test('version leaks: a bare Server name or Express is not a leak', () => {
  const r = detectVersionLeaks(page({ server: 'cloudflare', 'x-powered-by': 'Express' }));
  assert.deepEqual(r.leaks, []);
  assert.equal(r.wordpress, false);
  assert.deepEqual(detectVersionLeaks(null), { checked: false, leaks: [], wordpress: false });
});

test('security headers: lists the six in place and missing, in order', () => {
  const r = securityHeaderPresence(page({ 'strict-transport-security': 'max-age=1', 'permissions-policy': 'camera=()' }));
  assert.deepEqual(r.present, ['Strict-Transport-Security', 'Permissions-Policy']);
  assert.deepEqual(r.missing, ['Content-Security-Policy', 'X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy']);
  assert.equal(securityHeaderPresence(null), null);
});

test('certificate: records the exact expiry and a working cert', () => {
  const r = evaluateCertificate(cert('Dec 20 12:00:00 2026 GMT'), 'TLSv1.3', now);
  assert.equal(r.evidence.valid, true);
  assert.equal(r.evidence.expiresAt, '2026-12-20T12:00:00.000Z');
});

test('certificate: a name mismatch or untrusted cert is not working', () => {
  const mismatch = evaluateCertificate(cert('Dec 20 12:00:00 2026 GMT'), 'TLSv1.3', now, { hostnameMatch: false });
  assert.equal(mismatch.status, 'fail');
  assert.equal(mismatch.evidence.valid, false);
  const untrusted = evaluateCertificate(cert('Dec 20 12:00:00 2026 GMT'), 'TLSv1.3', now, { authorized: false });
  assert.equal(untrusted.status, 'fail');
  assert.equal(untrusted.evidence.valid, false);
  const expired = evaluateCertificate(cert('Oct 1 12:00:00 2026 GMT'), 'TLSv1.3', now);
  assert.equal(expired.evidence.valid, false);
  const none = evaluateCertificate(null, null, now);
  assert.equal(none.evidence.valid, false);
  assert.equal(none.evidence.expiresAt, null);
});

test('MTA-STS: needs both the DNS record and a valid policy file', async () => {
  const resolver = new FakeResolver({ '_mta-sts.x.com|TXT': ['v=STSv1; id=1'] });
  const good = 'version: STSv1\nmode: enforce\nmx: mx.x.com\nmax_age: 86400\n';
  const both = await checkMtaSts(resolver, 'x.com', { fetchPolicy: async () => good });
  assert.deepEqual(both.evidence, { txt: true, policy: true });
  assert.equal(both.status, 'pass');
  const noFile = await checkMtaSts(resolver, 'x.com', { fetchPolicy: async () => null });
  assert.deepEqual(noFile.evidence, { txt: true, policy: false });
  assert.equal(noFile.status, 'warn');
  let fetched = false;
  const noTxt = await checkMtaSts(new FakeResolver(), 'x.com', { fetchPolicy: async () => { fetched = true; return good; } });
  assert.deepEqual(noTxt.evidence, { txt: false, policy: false });
  assert.equal(fetched, false, 'no policy fetch without the DNS record');
  assert.equal(isValidMtaStsPolicy('hello'), false);
});

test('MTA-STS policy fetch reads the well-known path on the mta-sts host', async () => {
  let asked;
  const requestImpl = (opts, cb) => {
    asked = opts;
    const req = new EventEmitter();
    req.end = () => {
      const res = new EventEmitter();
      res.statusCode = 200;
      res.setEncoding = () => {};
      cb(res);
      res.emit('data', 'version: STSv1\nmode: testing\n');
      res.emit('end');
    };
    req.destroy = () => {};
    return req;
  };
  const text = await fetchMtaStsPolicy('x.com', { requestImpl });
  assert.equal(asked.host, 'mta-sts.x.com');
  assert.equal(asked.path, '/.well-known/mta-sts.txt');
  assert.equal(isValidMtaStsPolicy(text), true);
});

test('the audit report carries the page facts', async () => {
  const resolver = new FakeResolver({ 'x.com|A': ['1.2.3.4'] });
  const report = await runAudit('x.com', {
    resolver,
    loadPage: async () => page({ server: 'Apache/2.4.58', 'referrer-policy': 'no-referrer' }),
    fetchPolicy: async () => null,
  });
  assert.deepEqual(report.facts.website.leaks, [{ header: 'Server', value: 'Apache/2.4.58' }]);
  assert.deepEqual(report.facts.headers.present, ['Referrer-Policy']);
});
