import { test } from 'node:test';
import assert from 'node:assert/strict';
import { SCENARIOS } from './fixtures/scans.js';
import { buildReportModel, formatDate } from '../src/report-model.js';

const result = async (name) => (await SCENARIOS[name]()).result;

test('all pass: one-line email summary naming the report address', async () => {
  const r = await result('all-pass');
  assert.equal(r.email.all_correct, true);
  assert.equal(
    r.email.summary_line,
    "Your emails are locked down and any errors go to dmarc@allpass.com. That's great! Who is reviewing DMARC notices for you?",
  );
  assert.deepEqual(r.email.dns_changes, []);
  assert.equal(r.can_be_faked, false);
  assert.equal(r.likely_lands_in_inbox, true);
  assert.equal(r.website.line, 'Your website is not sharing version details with the public. Good.');
  assert.deepEqual(r.advanced.http_security.missing, []);
  assert.ok(r.advanced.great_to_haves.items.every((i) => i.set));
  assert.equal(r.top_fix, 'Nothing urgent to fix. Scan again after any change to your email or website settings.');
});

test('SPF ok, DMARC missing: correct list, attention list, exact records, p=none advice', async () => {
  const r = await result('spf-ok-dmarc-missing');
  assert.equal(r.email.all_correct, false);
  assert.deepEqual(r.email.correct_lines, [
    'SPF',
    'You are sending mail or newsletters from Google Workspace. Is that correct?',
    'DKIM',
  ]);
  assert.deepEqual(r.email.attention_lines, [
    'DMARC is missing. Nothing tells inboxes what to do with email that fakes your domain.',
  ]);
  const [spf, dmarc, dkim] = r.email.dns_changes;
  assert.deepEqual([spf.setting, dmarc.setting, dkim.setting], ['SPF', 'DMARC', 'DKIM']);
  assert.equal(spf.change, false);
  assert.equal(dkim.change, false);
  assert.deepEqual(
    { type: dmarc.type, host: dmarc.host, value: dmarc.value },
    { type: 'TXT', host: '_dmarc', value: 'v=DMARC1; p=none; rua=mailto:dmarc@nodmarc.com' },
  );
  assert.match(r.email.dmarc_advice, /p=none.*two weeks.*p=quarantine/);
  assert.equal(r.can_be_faked, true);
  assert.equal(r.likely_lands_in_inbox, false);
  assert.match(r.top_fix, /tells inboxes what to do with email pretending to be from you/);
});

test('DKIM missing for one sender names that sender and its dashboard', async () => {
  const r = await result('dkim-missing-one-sender');
  assert.deepEqual(r.email.sending_systems, ['Google Workspace', 'Mailchimp']);
  assert.equal(r.email.dkim.status, 'missing');
  assert.deepEqual(r.email.dkim.systems.map((s) => [s.name, s.status]), [['Google Workspace', 'found'], ['Mailchimp', 'missing']]);
  assert.deepEqual(r.email.attention_lines, ['DKIM is missing. No DKIM signature found for Mailchimp.']);
  assert.match(r.email.dns_changes[2].steps[0], /^Turn on DKIM in Mailchimp\. In Mailchimp, go to Account and billing, Domains/);
  assert.equal(r.email.dmarc_advice, null, 'no new DMARC record, so no p=none advice');
  assert.match(r.top_fix, /email signing in Mailchimp/);
});

test('no certificate: the certificate line is replaced', async () => {
  const r = await result('no-cert');
  assert.equal(r.certificate.valid, false);
  assert.deepEqual(r.certificate.lines, [
    'HTTPS can give your website a small boost in SEO when paired with content people want to read.',
    'Your website does not have a working SSL certificate. Browsers will warn visitors away.',
  ]);
  assert.equal(r.website.checked, false);
  assert.equal(r.advanced.http_security.checked, false);
});

test('WordPress headers: the WordPress line wins', async () => {
  const r = await result('wordpress-headers');
  assert.equal(r.website.wordpress, true);
  assert.equal(r.website.line, 'If you are using WordPress, please run updates asap.');
  assert.deepEqual(r.website.version_leaks.map((l) => l.header), ['X-Powered-By', 'Server', 'generator tag']);
  assert.deepEqual(r.advanced.http_security.in_place, ['X-Content-Type-Options']);
});

test('a non-WordPress version leak says what the site is running', async () => {
  const report = await SCENARIOS['all-pass']();
  report.facts.website = { checked: true, leaks: [{ header: 'Server', value: 'nginx/1.24.0' }], wordpress: false };
  assert.equal(buildReportModel(report).website.line, 'Your website is running nginx/1.24.0.');
});

test('certificate expiring in under 30 days adds the renew line', async () => {
  const r = await result('cert-expiring-soon');
  assert.equal(r.certificate.expiring_soon, true);
  assert.equal(r.certificate.days_left, 20);
  assert.deepEqual(r.certificate.lines.slice(1), ['Your SSL cert expires November 14, 2026.', 'That is soon. Renew it now.']);
});

test('contract fields are present and checks use pass, warn, or fail only', async () => {
  const r = await result('all-pass');
  for (const key of ['domain', 'checked_at', 'can_be_faked', 'likely_lands_in_inbox', 'top_fix', 'checks']) {
    assert.ok(key in r, key);
  }
  assert.ok(r.checks.every((c) => ['pass', 'warn', 'fail'].includes(c.status) && c.plain_summary));
  assert.equal(formatDate('2026-10-25T15:00:00Z'), 'October 25, 2026');
});

test('no text in any scenario contains an em dash', async () => {
  for (const name of Object.keys(SCENARIOS)) {
    const json = JSON.stringify((await SCENARIOS[name]()).result);
    assert.ok(!json.includes('—'), name);
  }
});

test('top_fix never uses an acronym', async () => {
  for (const name of Object.keys(SCENARIOS)) {
    const fix = (await SCENARIOS[name]()).result.top_fix;
    assert.doesNotMatch(fix, /\b(SPF|DKIM|DMARC|DNS|SSL|TLS|HTTPS|MTA|BIMI|CAA)\b/, `${name}: ${fix}`);
  }
});

test('the website section lists load balancers in a plain line', async () => {
  const report = await SCENARIOS['all-pass']();
  report.facts.website = { checked: true, leaks: [], wordpress: false, infrastructure: ['AWS Elastic Load Balancing', 'Amazon CloudFront'] };
  const w = buildReportModel(report).website;
  assert.equal(w.line, 'Your website is not sharing version details with the public. Good.');
  assert.deepEqual(w.load_balancers, ['AWS Elastic Load Balancing', 'Amazon CloudFront']);
  assert.equal(w.load_balancer_line, 'Your website is served through AWS Elastic Load Balancing and Amazon CloudFront.');
  const none = (await SCENARIOS['no-cert']()).result.website;
  assert.equal(none.load_balancer_line, null);
});

test('the website section reports the address checked and its HTTP status', async () => {
  const report = await SCENARIOS['all-pass']();
  report.facts.page = { url: 'https://www.allpass.com/', statusCode: 200, redirects: ['https://allpass.com/'] };
  const w = buildReportModel(report).website;
  assert.equal(w.checked_url, 'https://www.allpass.com/');
  assert.equal(w.status_code, 200);
});
