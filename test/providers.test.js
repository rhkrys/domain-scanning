import { test } from 'node:test';
import assert from 'node:assert/strict';
import { FakeResolver } from './helpers.js';
import { detectEmailProviders, PROVIDERS } from '../src/providers.js';
import { runAudit } from '../src/audit.js';
import { renderEmail } from '../src/email/render.js';

test('MX records identify Google Workspace, including the new single MX', () => {
  for (const mx of ['aspmx.l.google.com', 'alt1.aspmx.l.google.com.', 'smtp.google.com', 'ASPMX2.GOOGLEMAIL.COM']) {
    const r = detectEmailProviders({ mxHosts: [mx] });
    assert.equal(r.mailbox?.id, 'google', mx);
    assert.equal(r.known, true);
  }
});

test('MX records identify Microsoft 365, old and new MX names', () => {
  for (const mx of ['contoso-com.mail.protection.outlook.com', 'contoso-com.l-v1.mx.microsoft']) {
    assert.equal(detectEmailProviders({ mxHosts: [mx] }).mailbox?.id, 'microsoft', mx);
  }
});

test('MX records identify Zoho Mail in each region', () => {
  for (const mx of ['mx.zoho.com', 'mx2.zoho.eu', 'mx.zoho.in', 'mx3.zoho.com.au', 'mx.zohomail.com']) {
    assert.equal(detectEmailProviders({ mxHosts: [mx] }).mailbox?.id, 'zoho', mx);
  }
});

test('MX records identify Amazon SES inbound', () => {
  const r = detectEmailProviders({ mxHosts: ['inbound-smtp.us-east-1.amazonaws.com'] });
  assert.equal(r.mailbox?.id, 'ses');
});

test('lookalike hosts are not matched', () => {
  for (const mx of ['google.com.evil.net', 'notgoogle.com', 'zoho.evil.net', 'outlook.com.attacker.io']) {
    assert.equal(detectEmailProviders({ mxHosts: [mx] }).mailbox, null, mx);
  }
});

test('SPF includes find sending services that never appear in MX', () => {
  const r = detectEmailProviders({
    mxHosts: ['aspmx.l.google.com'],
    spfRecord:
      'v=spf1 include:_spf.google.com include:servers.mcsv.net include:sendgrid.net ' +
      'include:spf.mandrillapp.com include:amazonses.com ~all',
  });
  assert.equal(r.mailbox.id, 'google');
  assert.deepEqual(r.senders.map((s) => s.id).sort(), ['mailchimp', 'mandrill', 'sendgrid', 'ses']);
  // The mailbox provider is not repeated as a sender.
  assert.ok(!r.senders.some((s) => s.id === 'google'));
});

test('an unknown provider is reported as unknown, so the report says check with your provider', () => {
  const r = detectEmailProviders({ mxHosts: ['mx1.someisp.net'], spfRecord: 'v=spf1 include:spf.someisp.net -all' });
  assert.equal(r.mailbox, null);
  assert.deepEqual(r.senders, []);
  assert.equal(r.known, false);
  assert.equal(detectEmailProviders().known, false);
});

test('a security gateway in MX gives no mailbox, but SPF can still name the sender', () => {
  const r = detectEmailProviders({
    mxHosts: ['mx1-us1.ppe-hosted.com'],
    spfRecord: 'v=spf1 include:spf.protection.outlook.com -all',
  });
  assert.equal(r.mailbox, null);
  assert.deepEqual(r.senders.map((s) => s.id), ['microsoft']);
});

test('every provider has https links for SPF, DKIM and DMARC', () => {
  for (const p of PROVIDERS) {
    for (const key of ['spf', 'dkim', 'dmarc']) {
      assert.match(p.links[key], /^https:\/\//, `${p.id} ${key}`);
    }
  }
});

test('the audit report and email carry the provider links', async () => {
  const resolver = new FakeResolver({
    'acme.com|MX': ['10 acme-com.mail.protection.outlook.com.'],
    'acme.com|TXT': ['v=spf1 include:spf.protection.outlook.com include:servers.mcsv.net -all'],
  });
  const report = await runAudit('acme.com', { resolver, loadPage: async () => null });
  assert.equal(report.emailSetup.mailbox.id, 'microsoft');
  assert.deepEqual(report.emailSetup.senders.map((s) => s.id), ['mailchimp']);

  const email = renderEmail(report);
  assert.match(email.text, /hosted by Microsoft 365/);
  assert.match(email.text, /email-authentication-dkim-configure/);
  assert.match(email.html, /Where to set up SPF, DKIM, and DMARC/);
  assert.match(email.html, /set-up-email-domain-authentication/);
});

test('the email says check with your provider when the provider is unknown', async () => {
  const resolver = new FakeResolver({ 'odd.com|MX': ['10 mail.odd-host.net.'] });
  const report = await runAudit('odd.com', { resolver, loadPage: async () => null });
  const email = renderEmail(report);
  assert.match(email.text, /Check with your email provider/);
  assert.match(email.html, /Check with your email provider/);
});

test('a broken SPF record still lists the sender the owner meant to include', async () => {
  const resolver = new FakeResolver({
    'tip.com|MX': ['1 aspmx.l.google.com.'],
    'tip.com|TXT': ['v=spf1 include:_spf.google.com, amazonses.com ~all'],
  });
  const report = await runAudit('tip.com', { resolver, loadPage: async () => null });
  assert.equal(report.emailSetup.mailbox.id, 'google');
  assert.deepEqual(report.emailSetup.senders.map((s) => s.id), ['ses']);
});
