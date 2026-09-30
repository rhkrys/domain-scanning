import { test } from 'node:test';
import assert from 'node:assert/strict';
import { FakeResolver } from './helpers.js';
import {
  parseSpf, parseDmarc, checkSpf, checkDmarc, checkDkim, checkMtaSts, checkBimi,
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
