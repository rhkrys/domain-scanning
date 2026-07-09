import { test } from 'node:test';
import assert from 'node:assert/strict';
import { FakeResolver } from './helpers.js';
import { runAudit, normaliseDomain } from '../src/audit.js';
import { renderEmail } from '../src/email/render.js';

test('normaliseDomain strips scheme, path, port and trailing dot', () => {
  assert.equal(normaliseDomain('https://Example.com/path?x=1'), 'example.com');
  assert.equal(normaliseDomain('example.com:8080'), 'example.com');
  assert.equal(normaliseDomain('sub.example.co.nz.'), 'sub.example.co.nz');
});

test('normaliseDomain rejects junk', () => {
  assert.equal(normaliseDomain('not a domain'), null);
  assert.equal(normaliseDomain('localhost'), null);
  assert.equal(normaliseDomain(''), null);
  assert.equal(normaliseDomain(123), null);
});

test('runAudit rejects an invalid domain', async () => {
  await assert.rejects(() => runAudit('nope'), /Invalid domain/);
});

test('runAudit produces a full scored report (network checks degrade gracefully)', async () => {
  const resolver = new FakeResolver({
    'good.com|MX': ['10 aspmx.l.google.com.'],
    'good.com|A': ['93.184.216.34'],
    'good.com|NS': ['ns1.a.com.', 'ns2.b.com.'],
    'good.com|DS': ['12345 13 2 abcd'],
    'good.com|CAA': ['0 issue "letsencrypt.org"'],
    'good.com|TXT': ['v=spf1 include:_spf.google.com -all'],
    '_dmarc.good.com|TXT': ['v=DMARC1; p=reject; rua=mailto:d@good.com'],
    'google._domainkey.good.com|TXT': ['v=DKIM1; k=rsa; p=abc'],
    '_mta-sts.good.com|TXT': ['v=STSv1; id=20260101'],
  });

  const report = await runAudit('good.com', { resolver });

  assert.equal(report.domain, 'good.com');
  assert.equal(report.sendsMail, true);
  assert.equal(report.findings.length, 12);
  assert.ok(report.score >= 0 && report.score <= 100);
  assert.ok(['A', 'B', 'C', 'D', 'E', 'F'].includes(report.grade));

  // The strong email config should pass its checks.
  const byId = Object.fromEntries(report.findings.map((f) => [f.id, f]));
  assert.equal(byId.spf.status, 'pass');
  assert.equal(byId.dmarc.status, 'pass');
  assert.equal(byId.dkim.status, 'pass');
  assert.equal(byId.dnssec.status, 'pass');
});

test('renderEmail produces subject, text and html that mention the grade', async () => {
  const resolver = new FakeResolver({ 'x.com|A': ['1.2.3.4'], 'x.com|NS': ['ns1.a.com.', 'ns2.b.com.'] });
  const report = await runAudit('x.com', { resolver });
  const email = renderEmail(report);

  assert.match(email.subject, /x\.com/);
  assert.match(email.subject, new RegExp(`grade ${report.grade}`));
  assert.match(email.text, /next steps|action item|every check passed/i);
  assert.match(email.html, /<html/);
  assert.match(email.html, new RegExp(`${report.score}/100`));
});
