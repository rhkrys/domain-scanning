import { test } from 'node:test';
import assert from 'node:assert/strict';
import { FakeResolver } from './helpers.js';
import { checkMx, checkNameservers, checkCaa, checkAddressing } from '../src/checks/records.js';
import { checkDnssec } from '../src/checks/dnssec.js';
import { evaluateCertificate } from '../src/checks/tls.js';
import { evaluateHeaders } from '../src/checks/headers.js';

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

test('evaluateHeaders: missing HSTS fails', () => {
  const r = evaluateHeaders({ 'x-frame-options': 'DENY' });
  assert.equal(r.status, 'fail');
  assert.equal(r.severity, 'high');
});
