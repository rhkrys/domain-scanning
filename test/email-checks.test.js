import { test } from 'node:test';
import assert from 'node:assert/strict';
import { FakeResolver } from './helpers.js';
import {
  parseSpf, parseDmarc, checkSpf, checkDmarc, checkDkim, checkMtaSts, checkBimi, validateSpfSyntax,
} from '../src/checks/email.js';

test('parseSpf finds the spf1 record only', () => {
  assert.equal(parseSpf(['v=spf1 -all', 'other']), 'v=spf1 -all');
  assert.equal(parseSpf(['google-site-verification=abc']), null);
});

test('parseDmarc extracts tags', () => {
  const p = parseDmarc(['v=DMARC1; p=reject; rua=mailto:d@x.com']);
  assert.equal(p.tags.p, 'reject');
  assert.equal(p.tags.rua, 'mailto:d@x.com');
});

test('checkSpf: missing record fails', async () => {
  const r = await checkSpf(new FakeResolver(), 'x.com');
  assert.equal(r.status, 'fail');
  assert.equal(r.severity, 'high');
});

test('checkSpf: hard fail passes', async () => {
  const res = new FakeResolver({ 'x.com|TXT': ['v=spf1 include:_spf.google.com -all'] });
  const r = await checkSpf(res, 'x.com');
  assert.equal(r.status, 'pass');
});

test('checkSpf: +all is a hard failure', async () => {
  const res = new FakeResolver({ 'x.com|TXT': ['v=spf1 +all'] });
  const r = await checkSpf(res, 'x.com');
  assert.equal(r.status, 'fail');
  assert.match(r.summary, /\+all/);
});

test('checkSpf: ~all is a soft warning', async () => {
  const res = new FakeResolver({ 'x.com|TXT': ['v=spf1 ~all'] });
  const r = await checkSpf(res, 'x.com');
  assert.equal(r.status, 'warn');
});

test('checkSpf: too many lookups warns', async () => {
  const includes = Array.from({ length: 12 }, (_, i) => `include:s${i}.com`).join(' ');
  const res = new FakeResolver({ 'x.com|TXT': [`v=spf1 ${includes} -all`] });
  const r = await checkSpf(res, 'x.com');
  assert.equal(r.status, 'warn');
  assert.match(r.summary, /10 DNS-lookup/);
});

test('validateSpfSyntax accepts well-formed records', () => {
  for (const rec of [
    'v=spf1 -all',
    'v=spf1 include:_spf.google.com include:amazonses.com ~all',
    'v=spf1 ip4:192.0.2.0/24 ip6:2001:db8::/32 a mx a:mail.example.com/28 mx//64 ?all',
    'v=spf1 include:%{d}._spf.example.com exists:%{i}.bl.example.com -all',
    'v=spf1 redirect=_spf.example.com',
    'v=spf1 include:spf.protection.outlook.com exp=explain.example.com -all',
  ]) {
    assert.deepEqual(validateSpfSyntax(rec).problems, [], rec);
  }
});

test('validateSpfSyntax repairs a stray comma and a missing include (the techinpeace.com case)', () => {
  const r = validateSpfSyntax('v=spf1 include:_spf.google.com, amazonses.com ~all');
  assert.equal(r.problems.length, 2);
  assert.match(r.problems[0], /comma/);
  assert.match(r.problems[1], /missing "include:"/);
  assert.equal(r.fixed, 'v=spf1 include:_spf.google.com include:amazonses.com ~all');
});

test('validateSpfSyntax flags parts it cannot repair and offers no fix', () => {
  for (const rec of [
    'v=spf1 includes:_spf.google.com -all',
    'v=spf1 ip4:300.1.1.1 -all',
    'v=spf1 include: -all',
    'v=spf1 redirect=a.example.com redirect=b.example.com',
    'v=spf1, include:_spf.google.com -all',
  ]) {
    const r = validateSpfSyntax(rec);
    assert.ok(r.problems.length > 0, rec);
    assert.equal(r.fixed, null, rec);
  }
});

test('checkSpf: a malformed record fails and gives the exact corrected record', async () => {
  const res = new FakeResolver({ 'x.com|TXT': ['v=spf1 include:_spf.google.com, amazonses.com ~all'] });
  const r = await checkSpf(res, 'x.com');
  assert.equal(r.status, 'fail');
  assert.equal(r.severity, 'high');
  assert.match(r.summary, /typo/);
  assert.match(r.recommendation, /do not add a second one/);
  assert.match(r.recommendation, /v=spf1 include:_spf\.google\.com include:amazonses\.com ~all$/);
  assert.equal(r.evidence.fixed, 'v=spf1 include:_spf.google.com include:amazonses.com ~all');
  for (const v of [r.summary, r.detail, r.recommendation]) assert.ok(!v.includes('\u2014'), v);
});

test('checkSpf: two SPF records fail', async () => {
  const res = new FakeResolver({ 'x.com|TXT': ['v=spf1 include:_spf.google.com ~all', 'v=spf1 include:amazonses.com ~all'] });
  const r = await checkSpf(res, 'x.com');
  assert.equal(r.status, 'fail');
  assert.match(r.summary, /2 SPF records/);
  assert.match(r.recommendation, /single SPF record/);
});

test('checkDmarc: missing record is critical when sending mail', async () => {
  const r = await checkDmarc(new FakeResolver(), 'x.com', { sendsMail: true });
  assert.equal(r.status, 'fail');
  assert.equal(r.severity, 'critical');
});

test('checkDmarc: p=reject passes', async () => {
  const res = new FakeResolver({ '_dmarc.x.com|TXT': ['v=DMARC1; p=reject; rua=mailto:d@x.com'] });
  const r = await checkDmarc(res, 'x.com');
  assert.equal(r.status, 'pass');
});

test('checkDmarc: p=none warns', async () => {
  const res = new FakeResolver({ '_dmarc.x.com|TXT': ['v=DMARC1; p=none'] });
  const r = await checkDmarc(res, 'x.com');
  assert.equal(r.status, 'warn');
  assert.equal(r.severity, 'high');
});

test('checkDkim: finds a known selector', async () => {
  const res = new FakeResolver({
    'google._domainkey.x.com|TXT': ['v=DKIM1; k=rsa; p=MIGf...'],
  });
  const r = await checkDkim(res, 'x.com', { sendsMail: true });
  assert.equal(r.status, 'pass');
  assert.deepEqual(r.evidence.selectors, ['google']);
});

test('checkDkim: none found warns when sending mail', async () => {
  const r = await checkDkim(new FakeResolver(), 'x.com', { sendsMail: true });
  assert.equal(r.status, 'warn');
});

test('checkMtaSts: not applicable when no mail', async () => {
  const r = await checkMtaSts(new FakeResolver(), 'x.com', { sendsMail: false });
  assert.equal(r.status, 'info');
});

test('checkBimi: present passes', async () => {
  const res = new FakeResolver({ 'default._bimi.x.com|TXT': ['v=BIMI1; l=https://x.com/logo.svg'] });
  const r = await checkBimi(res, 'x.com');
  assert.equal(r.status, 'pass');
});
