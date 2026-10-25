import { test } from 'node:test';
import assert from 'node:assert/strict';
import { FakeResolver } from './helpers.js';
import { sendersFromSpf, selectorsForSenders, SENDING_SYSTEMS } from '../src/senders.js';
import { countSpfLookups, parseDmarc, checkDkim, isValidDkimRecord } from '../src/checks/email.js';
import { runAudit } from '../src/audit.js';

test('SPF includes map to friendly names, unknown includes stay raw', () => {
  const s = sendersFromSpf(
    'v=spf1 include:_spf.google.com include:servers.mcsv.net include:_spf.mailgun.org ' +
      'include:spf.example-crm.net ip4:203.0.113.5 mx ~all',
  );
  assert.deepEqual(s.map((x) => x.name), [
    'Google Workspace', 'Mailchimp', 'Mailgun', 'spf.example-crm.net', '203.0.113.5', 'your own mail servers',
  ]);
});

test('every friendly name from the brief is mapped', () => {
  const pairs = {
    '_spf.google.com': 'Google Workspace', 'spf.protection.outlook.com': 'Microsoft 365',
    'servers.mcsv.net': 'Mailchimp', 'sendgrid.net': 'SendGrid', '_spf.mailgun.org': 'Mailgun',
    'mailgun.org': 'Mailgun', 'amazonses.com': 'Amazon SES', 'spf.constantcontact.com': 'Constant Contact',
    '_spf.salesforce.com': 'Salesforce', 'mail.zendesk.com': 'Zendesk', 'spf.mandrillapp.com': 'Mandrill',
    '_spf.mail.hostinger.com': 'Hostinger', 'secureserver.net': 'GoDaddy', 'spf.resend.com': 'Resend',
    'spf.klaviyo.com': 'Klaviyo', 'shops.shopify.com': 'Shopify', 'spf.squarespace.com': 'Squarespace',
    '_spf.wix.com': 'Wix',
  };
  for (const [include, name] of Object.entries(pairs)) {
    assert.equal(sendersFromSpf(`v=spf1 include:${include} ~all`)[0]?.name, name, include);
  }
});

test('lookalike includes are not given a friendly name', () => {
  assert.equal(sendersFromSpf('v=spf1 include:sendgrid.net.evil.io ~all')[0].system, null);
  assert.equal(sendersFromSpf('v=spf1 include:notsendgrid.net ~all')[0].system, null);
});

test('SPF senders add the DKIM selectors those systems use', () => {
  const sel = selectorsForSenders(sendersFromSpf('v=spf1 include:servers.mcsv.net include:spf.constantcontact.com ~all'));
  assert.deepEqual(sel, ['k1', 'k2', 'k3', 'ctct1', 'ctct2']);
});

test('systems with random DKIM names are marked as not verifiable', () => {
  const unverifiable = SENDING_SYSTEMS.filter((s) => !s.verifiable).map((s) => s.id);
  for (const id of ['ses', 'salesforce', 'mailgun']) assert.ok(unverifiable.includes(id), id);
  assert.ok(SENDING_SYSTEMS.every((s) => s.dashboard && !s.dashboard.includes('—')));
});

test('countSpfLookups follows includes like a receiver does', async () => {
  const resolver = new FakeResolver({
    '_spf.google.com|TXT': ['v=spf1 include:_netblocks.google.com include:_netblocks2.google.com include:_netblocks3.google.com ~all'],
    '_netblocks.google.com|TXT': ['v=spf1 ip4:35.190.247.0/24 ~all'],
    'amazonses.com|TXT': ['v=spf1 ip4:199.255.192.0/22 ~all'],
  });
  // 4 at the top (2 includes, mx, a) plus Google's 3 nested includes.
  assert.equal(await countSpfLookups(resolver, 'v=spf1 include:_spf.google.com include:amazonses.com mx a ~all'), 7);
});

test('countSpfLookups does not loop on a record that includes itself', async () => {
  const resolver = new FakeResolver({ 'loop.com|TXT': ['v=spf1 include:loop.com -all'] });
  assert.equal(await countSpfLookups(resolver, 'v=spf1 include:loop.com -all'), 2);
});

test('parseDmarc pulls report addresses and counts records', () => {
  const d = parseDmarc(['v=DMARC1; p=none; rua=mailto:a@x.com!10m,mailto:b@y.com']);
  assert.deepEqual(d.rua, ['a@x.com', 'b@y.com']);
  assert.equal(d.count, 1);
  assert.equal(parseDmarc(['v=DMARC1; p=none', 'v=DMARC1; p=reject']).count, 2);
});

test('a revoked DKIM key (empty p=) does not count', () => {
  assert.equal(isValidDkimRecord('v=DKIM1; k=rsa; p='), false);
  assert.equal(isValidDkimRecord('v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEB'), true);
});

test('checkDkim tests extra selectors on top of the common list', async () => {
  const resolver = new FakeResolver({ 'ctct1._domainkey.x.com|TXT': ['v=DKIM1; k=rsa; p=MIGfMA0'] });
  const plain = await checkDkim(resolver, 'x.com');
  assert.deepEqual(plain.evidence.selectors, []);
  const withExtra = await checkDkim(resolver, 'x.com', { extraSelectors: ['ctct1', 'ctct2'] });
  assert.deepEqual(withExtra.evidence.selectors, ['ctct1']);
  assert.ok(withExtra.evidence.checked.includes('everlytickey2'));
});

test('the audit tests DKIM selectors implied by SPF', async () => {
  const resolver = new FakeResolver({
    'cc.com|MX': ['10 aspmx.l.google.com.'],
    'cc.com|TXT': ['v=spf1 include:spf.constantcontact.com ~all'],
    'ctct2._domainkey.cc.com|TXT': ['v=DKIM1; k=rsa; p=MIGfMA0'],
  });
  const report = await runAudit('cc.com', { resolver, loadPage: async () => null });
  const dkim = report.findings.find((f) => f.id === 'dkim');
  assert.deepEqual(dkim.evidence.selectors, ['ctct2']);
});
