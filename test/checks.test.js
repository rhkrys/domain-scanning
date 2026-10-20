import { test } from 'node:test';
import assert from 'node:assert/strict';
import { FakeResolver } from './helpers.js';
import { checkMx, checkNameservers, checkCaa, checkAddressing } from '../src/checks/records.js';
import { checkDnssec } from '../src/checks/dnssec.js';
import { evaluateCertificate } from '../src/checks/tls.js';
import { evaluateHeaders, detectSensitiveSite, checkHeaders } from '../src/checks/headers.js';
import { EventEmitter } from 'node:events';

test('checkMx: detects mail vs no mail', async () => {
  const withMx = new FakeResolver({ 'x.com|MX': ['10 mail.x.com.'] });
  const r1 = await checkMx(withMx, 'x.com');
  assert.equal(r1.evidence.sendsMail, true);

  const r2 = await checkMx(new FakeResolver(), 'x.com');
  assert.equal(r2.evidence.sendsMail, false);
});

test('checkMx: null MX (RFC 7505) means no mail', async () => {
  const res = new FakeResolver({ 'x.com|MX': ['0 .'] });
  const r = await checkMx(res, 'x.com');
  assert.equal(r.evidence.sendsMail, false);
  assert.equal(r.evidence.nullMx, true);
  assert.match(r.summary, /[Nn]ull MX/);
});

test('checkNameservers: single ns warns, diverse passes', async () => {
  const one = new FakeResolver({ 'x.com|NS': ['ns1.host.com.'] });
  assert.equal((await checkNameservers(one, 'x.com')).status, 'warn');

  const many = new FakeResolver({ 'x.com|NS': ['ns1.a.com.', 'ns2.b.com.'] });
  assert.equal((await checkNameservers(many, 'x.com')).status, 'pass');
});

test('checkCaa: missing warns', async () => {
  assert.equal((await checkCaa(new FakeResolver(), 'x.com')).status, 'warn');
});

test('checkAddressing: no records warns', async () => {
  assert.equal((await checkAddressing(new FakeResolver(), 'x.com')).status, 'warn');
});

test('checkDnssec: DS record means signed', async () => {
  const signed = new FakeResolver({ 'x.com|DS': ['12345 13 2 abcd'] });
  assert.equal((await checkDnssec(signed, 'x.com')).status, 'pass');
  assert.equal((await checkDnssec(new FakeResolver(), 'x.com')).status, 'warn');
});

test('evaluateCertificate: valid cert passes', () => {
  const now = new Date('2026-06-01T00:00:00Z');
  const cert = {
    valid_from: 'May 1 00:00:00 2026 GMT',
    valid_to: 'Aug 1 00:00:00 2026 GMT',
    subject: { CN: 'x.com' },
    issuer: { O: "Let's Encrypt" },
  };
  const r = evaluateCertificate(cert, 'TLSv1.3', now);
  assert.equal(r.status, 'pass');
});

test('evaluateCertificate: expired cert is critical', () => {
  const now = new Date('2026-06-01T00:00:00Z');
  const cert = { valid_from: 'Jan 1 2026 GMT', valid_to: 'Mar 1 00:00:00 2026 GMT' };
  const r = evaluateCertificate(cert, 'TLSv1.3', now);
  assert.equal(r.status, 'fail');
  assert.equal(r.severity, 'critical');
});

test('evaluateCertificate: near-expiry warns', () => {
  const now = new Date('2026-06-01T00:00:00Z');
  const cert = { valid_from: 'Jan 1 2026 GMT', valid_to: 'Jun 8 00:00:00 2026 GMT' };
  const r = evaluateCertificate(cert, 'TLSv1.3', now);
  assert.equal(r.status, 'warn');
  assert.equal(r.severity, 'high');
});

test('evaluateCertificate: legacy protocol warns', () => {
  const now = new Date('2026-06-01T00:00:00Z');
  const cert = { valid_from: 'Jan 1 2026 GMT', valid_to: 'Dec 1 00:00:00 2026 GMT' };
  const r = evaluateCertificate(cert, 'TLSv1', now);
  assert.equal(r.status, 'warn');
});

test('evaluateHeaders: all present passes', () => {
  const headers = {
    'strict-transport-security': 'max-age=63072000',
    'content-security-policy': "default-src 'self'",
    'x-content-type-options': 'nosniff',
    'x-frame-options': 'DENY',
    'referrer-policy': 'strict-origin',
  };
  assert.equal(evaluateHeaders(headers).status, 'pass');
});

test('evaluateHeaders: a basic site missing HSTS is Medium, not High', () => {
  const r = evaluateHeaders({ 'x-frame-options': 'DENY' });
  assert.equal(r.status, 'fail');
  assert.equal(r.severity, 'medium');
  assert.equal(r.evidence.siteType, 'basic');
  const hsts = r.evidence.items.find((i) => i.name === 'HSTS');
  assert.equal(hsts.severity, 'medium');
});

test('evaluateHeaders: a site with logins, payments, or patient or donor data is High for HSTS', () => {
  for (const signal of ['login', 'payments', 'donations', 'patient']) {
    const r = evaluateHeaders({ 'x-frame-options': 'DENY' }, { signals: [signal] });
    assert.equal(r.severity, 'high', signal);
    assert.equal(r.evidence.siteType, 'sensitive');
  }
});

test('evaluateHeaders: X-Frame-Options depends on site type', () => {
  const allBut = { 'strict-transport-security': 'max-age=1', 'x-content-type-options': 'nosniff', 'content-security-policy': "default-src 'self'", 'referrer-policy': 'no-referrer' };
  const basic = evaluateHeaders(allBut);
  assert.equal(basic.severity, 'low');
  assert.equal(basic.status, 'warn');
  const sensitive = evaluateHeaders(allBut, { signals: ['payments'] });
  assert.equal(sensitive.severity, 'medium');
  assert.equal(sensitive.evidence.items.find((i) => i.name === 'X-Frame-Options').effort, 'site type');
});

test('evaluateHeaders: labels HSTS and nosniff as quick wins and CSP as a planned project', () => {
  const r = evaluateHeaders({});
  const effort = Object.fromEntries(r.evidence.items.map((i) => [i.name, i.effort]));
  assert.equal(effort.HSTS, 'quick win');
  assert.equal(effort['X-Content-Type-Options'], 'quick win');
  assert.equal(effort['X-Frame-Options'], 'site type');
  assert.equal(effort['Content-Security-Policy'], 'project');
  assert.match(r.summary, /5 security headers missing, 2 are quick wins/);
  const rec = r.recommendation;
  const order = ['Quick wins:', 'Depends on your site:', 'Planned project:', 'Also worth adding:'].map((l) => rec.indexOf(l));
  assert.ok(order.every((i) => i >= 0), 'every group is present');
  assert.deepEqual([...order].sort((a, b) => a - b), order, 'groups appear in order');
  assert.match(rec, /report-only mode/);
});

test('evaluateHeaders: the HSTS note says what we saw', () => {
  const basic = evaluateHeaders({}).recommendation;
  assert.match(basic, /Medium for a basic site and High for a site with logins, payments, or patient or donor data/);
  assert.match(basic, /did not see logins, payments, or patient or donor data on your home page, so HSTS is rated Medium/);
  assert.match(basic, /treat it as High/);
  const sensitive = evaluateHeaders({}, { signals: ['login', 'payments'] }).recommendation;
  assert.match(sensitive, /signs of a login area and payments on your home page, so HSTS is rated High/);
});

test('evaluateHeaders: report copy has no em dashes', () => {
  assert.ok(!evaluateHeaders({}).recommendation.includes('\u2014'));
  assert.ok(!evaluateHeaders({}, { signals: ['login'] }).recommendation.includes('\u2014'));
});

test('detectSensitiveSite: finds logins, payments, donations and patient data', () => {
  assert.deepEqual(detectSensitiveSite('<form><input type="password" name="p"></form>'), ['login']);
  assert.deepEqual(detectSensitiveSite('<a href="/x">Client Portal</a>'), ['login']);
  assert.deepEqual(detectSensitiveSite('<script src="https://js.stripe.com/v3"></script>'), ['payments']);
  assert.deepEqual(detectSensitiveSite('<button>Add to cart</button>'), ['payments']);
  assert.deepEqual(detectSensitiveSite('<a href="https://donorbox.org/x">Give</a>'), ['donations']);
  assert.deepEqual(detectSensitiveSite('<a>Donate today</a>'), ['donations']);
  assert.deepEqual(detectSensitiveSite('<a>Patient Portal</a>'), ['patient']);
});

test('detectSensitiveSite: a plain brochure page has no signals', () => {
  assert.deepEqual(detectSensitiveSite('<h1>Welcome</h1><p>We fix computers. Call us.</p>'), []);
  assert.deepEqual(detectSensitiveSite(''), []);
  assert.deepEqual(detectSensitiveSite(undefined), []);
});

// A tiny stand-in for https.request that answers with a canned response.
function fakeRequest({ statusCode = 200, headers = {}, body = '' } = {}, { fail = false } = {}) {
  return (_opts, onResponse) => {
    const req = new EventEmitter();
    req.end = () => {
      setImmediate(() => {
        if (fail) return req.emit('error', new Error('boom'));
        const res = new EventEmitter();
        res.statusCode = statusCode;
        res.headers = headers;
        res.setEncoding = () => {};
        res.resume = () => {};
        res.destroy = () => {};
        onResponse(res);
        setImmediate(() => {
          if (body) res.emit('data', body);
          res.emit('end');
        });
      });
    };
    req.destroy = () => {};
    return req;
  };
}

test('checkHeaders: reads the home page and rates a login site High', async () => {
  const requestImpl = fakeRequest({ headers: { 'content-type': 'text/html; charset=utf-8' }, body: '<a href="/login">Log in</a>' });
  const r = await checkHeaders('shop.example', { requestImpl });
  assert.equal(r.severity, 'high');
  assert.deepEqual(r.evidence.signals, ['login']);
});

test('checkHeaders: a plain page is a basic site', async () => {
  const requestImpl = fakeRequest({ headers: { 'content-type': 'text/html' }, body: '<p>Hello</p>' });
  const r = await checkHeaders('plain.example', { requestImpl });
  assert.equal(r.severity, 'medium');
  assert.equal(r.evidence.siteType, 'basic');
});

test('checkHeaders: a redirect or non-HTML response is rated as a basic site', async () => {
  const redirect = fakeRequest({ statusCode: 301, headers: { location: 'https://www.example.com/' }, body: '' });
  assert.equal((await checkHeaders('a.example', { requestImpl: redirect })).evidence.siteType, 'basic');
  const json = fakeRequest({ headers: { 'content-type': 'application/json' }, body: '{"login": true}' });
  assert.equal((await checkHeaders('b.example', { requestImpl: json })).evidence.siteType, 'basic');
});

test('checkHeaders: no response still warns instead of crashing', async () => {
  const r = await checkHeaders('down.example', { requestImpl: fakeRequest({}, { fail: true }) });
  assert.equal(r.status, 'warn');
  assert.match(r.summary, /Could not retrieve/);
});
