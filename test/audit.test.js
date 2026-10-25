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
  assert.equal(report.findings.length, 13);
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

  assert.equal(email.subject, 'Your domain and website security report for x.com');
  assert.match(email.text, new RegExp(`Grade: ${report.grade} \\(${report.score}/100\\)`));
  assert.match(email.text, /^WHAT TO DO$/m);
  assert.match(email.html, /<html/);
  assert.match(email.html, new RegExp(`${report.score}/100`));
});

test('the email footer links back to the scan page to check the score again', async () => {
  const resolver = new FakeResolver({ 'x.com|A': ['1.2.3.4'] });
  const report = await runAudit('x.com', { resolver, loadPage: async () => null });
  const email = renderEmail(report);
  assert.match(email.text, /^After making changes to your DNS or website, be sure to check your score again: https:\/\/www\.techinpeace\.com\/scan$/m);
  assert.match(email.html, /<a href="https:\/\/www\.techinpeace\.com\/scan"[^>]*>check your score again<\/a>/);
});

test('the report email opens with Hi and keeps the CPI header, not Cyber Protection', async () => {
  const resolver = new FakeResolver({ 'x.com|A': ['1.2.3.4'] });
  const report = await runAudit('x.com', { resolver, loadPage: async () => null });
  const email = renderEmail(report);
  assert.match(email.text, /^Hi,\n\nHere is your free Tech in Peace report for x\.com, scanned /);
  assert.match(email.html, />CPI</);
  assert.match(email.html, /CPI · Consulting Services/);
  assert.doesNotMatch(email.text + email.html, /cyber protection/i);
});
