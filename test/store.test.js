import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createApp } from '../server.js';
import { buildScanRecord, createDynamoStore, createMemoryStore, RETENTION_DAYS } from '../src/store.js';
import { createMemoryLimiter } from '../src/ratelimit.js';
import { loadConfig } from '../src/config.js';
import { renderEmail } from '../src/email/render.js';
import { SCENARIOS } from './fixtures/scans.js';

const ALLOWED_FIELDS = new Set([
  'scan_id', 'domain', 'checked_at', 'result_json', 'source', 'email', 'newsletter_opt_in',
  'consent_at', 'email_subject', 'email_text', 'email_html', 'expires_at',
]);

test('a scan record holds only the agreed fields, with the rendered email', async () => {
  const report = await SCENARIOS['all-pass']();
  const rendered = renderEmail(report);
  const r = buildScanRecord({ scanId: 'id-1', report, source: 'web', email: 'a@b.com', newsletterOptIn: true, rendered, consentAt: '2026-10-25T15:00:01.000Z' });
  for (const k of Object.keys(r)) assert.ok(ALLOWED_FIELDS.has(k), k);
  assert.equal(r.email_text, rendered.text);
  assert.equal(r.email_subject, 'Your domain and website security report for allpass.com');
  assert.deepEqual(JSON.parse(r.result_json).result, report.result);
  assert.equal(r.newsletter_opt_in, true);
  assert.equal(r.consent_at, '2026-10-25T15:00:01.000Z');
});

test('retention: 12 months with an email, 90 days without', async () => {
  const report = await SCENARIOS['all-pass']();
  const rendered = renderEmail(report);
  const start = Math.floor(new Date(report.scannedAt).getTime() / 1000);
  const withEmail = buildScanRecord({ scanId: 'a', report, source: 'api', email: 'a@b.com', rendered });
  const anon = buildScanRecord({ scanId: 'b', report, source: 'api', rendered });
  assert.equal(withEmail.expires_at - start, RETENTION_DAYS.withEmail * 86400);
  assert.equal(anon.expires_at - start, RETENTION_DAYS.anonymous * 86400);
  assert.equal('email' in anon, false);
});

test('opt-in needs an explicit true and an email; consent time only when opted in', async () => {
  const report = await SCENARIOS['all-pass']();
  const rendered = renderEmail(report);
  for (const value of ['true', 1, 'yes', undefined, null, false]) {
    const r = buildScanRecord({ scanId: 'x', report, source: 'api', email: 'a@b.com', newsletterOptIn: value, rendered });
    assert.equal(r.newsletter_opt_in, false, String(value));
    assert.equal('consent_at' in r, false);
  }
  const noEmail = buildScanRecord({ scanId: 'y', report, source: 'api', newsletterOptIn: true, rendered });
  assert.equal(noEmail.newsletter_opt_in, false);
});

test('DynamoDB store writes typed attributes and reads them back', async () => {
  const sent = [];
  const items = new Map();
  const client = {
    async send(cmd) {
      sent.push(cmd.constructor.name);
      if (cmd.constructor.name === 'PutItemCommand') items.set(cmd.input.Item.scan_id.S, cmd.input.Item);
      if (cmd.constructor.name === 'GetItemCommand') return { Item: items.get(cmd.input.Key.scan_id.S) };
      return {};
    },
  };
  const store = createDynamoStore({ table: 'scans', client });
  const record = { scan_id: 'id-9', domain: 'x.com', newsletter_opt_in: false, expires_at: 123, source: 'api' };
  await store.save(record);
  assert.deepEqual(items.get('id-9').newsletter_opt_in, { BOOL: false });
  assert.deepEqual(items.get('id-9').expires_at, { N: '123' });
  assert.deepEqual(await store.get('id-9'), record);
  assert.equal(await store.get('missing'), null);
  assert.deepEqual(sent, ['PutItemCommand', 'GetItemCommand', 'GetItemCommand']);
});

// End to end: both routes save, and a report link never shows the email.
let server;
let base;
const store = createMemoryStore();
const saved = [];
const spyStore = {
  save: async (r) => {
    saved.push(r);
    return store.save(r);
  },
  get: (id) => store.get(id),
};

before(async () => {
  const fixture = await SCENARIOS['spf-ok-dmarc-missing']();
  const app = createApp({
    audit: async () => fixture,
    send: async (to, report, rendered) => ({ delivered: true, mode: 'test', subject: rendered.subject }),
    config: loadConfig({}),
    apiLimiter: createMemoryLimiter({ max: 100 }),
    store: spyStore,
  });
  await new Promise((resolve) => {
    server = app.listen(0, resolve);
  });
  base = `http://127.0.0.1:${server.address().port}`;
});

after(() => server.close());

test('the web scan saves the record with source web and the email given', async () => {
  const res = await fetch(`${base}/api/scan`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-forwarded-for': '192.0.2.50' },
    body: JSON.stringify({ domain: 'nodmarc.com', email: 'owner@nodmarc.com', ignored: 'not stored' }),
  });
  assert.equal(res.status, 200);
  const body = await res.json();
  const rec = saved.at(-1);
  assert.equal(rec.source, 'web');
  assert.equal(rec.email, 'owner@nodmarc.com');
  assert.ok(!JSON.stringify(rec).includes('not stored'), 'extra request fields are never stored');
  assert.ok(!JSON.stringify(rec).includes('192.0.2.50'), 'the IP is never stored');
  assert.match(body.report_url, /scan\?report=/);

  const link = await (await fetch(`${base}/api/report/${rec.scan_id}`)).json();
  assert.ok(!JSON.stringify(link).includes('owner@nodmarc.com'), 'report links never show the email');
});

test('the API scan saves with source api', async () => {
  const res = await fetch(`${base}/api/v1/scan`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-forwarded-for': '192.0.2.51' },
    body: JSON.stringify({ domain: 'nodmarc.com' }),
  });
  assert.equal(res.status, 200);
  assert.equal(saved.at(-1).source, 'api');
  assert.match(saved.at(-1).email_text, /^Hi,/);
});

test('a storage failure never costs the visitor their result', async () => {
  const app = createApp({
    audit: async () => SCENARIOS['all-pass'](),
    config: loadConfig({}),
    apiLimiter: createMemoryLimiter({ max: 100 }),
    store: { save: async () => { throw new Error('table missing'); }, get: async () => null },
  });
  const s = await new Promise((resolve) => {
    const srv = app.listen(0, () => resolve(srv));
  });
  const original = console.error;
  console.error = () => {};
  try {
    const res = await fetch(`http://127.0.0.1:${s.address().port}/api/v1/scan`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ domain: 'allpass.com' }),
    });
    assert.equal(res.status, 200);
  } finally {
    console.error = original;
    s.close();
  }
});

const post = (path, body, ip) =>
  fetch(`${base}${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-forwarded-for': ip },
    body: JSON.stringify(body),
  });

test('API: email and newsletter_opt_in are optional; opt-in must be exactly true', async () => {
  let res = await post('/api/v1/scan', { domain: 'nodmarc.com', email: 'jo@nodmarc.com', newsletter_opt_in: 'true' }, '192.0.2.60');
  assert.equal(res.status, 200);
  assert.equal((await res.json()).report_emailed, true);
  assert.equal(saved.at(-1).email, 'jo@nodmarc.com');
  assert.equal(saved.at(-1).newsletter_opt_in, false);
  assert.equal('consent_at' in saved.at(-1), false);

  res = await post('/api/v1/scan', { domain: 'nodmarc.com', email: 'jo@nodmarc.com', newsletter_opt_in: true }, '192.0.2.61');
  assert.equal(saved.at(-1).newsletter_opt_in, true);
  assert.match(saved.at(-1).consent_at, /^\d{4}-\d{2}-\d{2}T/);

  res = await post('/api/v1/scan', { domain: 'nodmarc.com', newsletter_opt_in: true }, '192.0.2.62');
  assert.equal((await res.json()).report_emailed, false);
  assert.equal(saved.at(-1).newsletter_opt_in, false, 'no email, no subscription');
});

test('API: a mistyped email is a 400 on the email field', async () => {
  const res = await post('/api/v1/scan', { domain: 'nodmarc.com', email: 'jo@gmial.com' }, '192.0.2.63');
  assert.equal(res.status, 400);
  assert.equal((await res.json()).field, 'email');
});

test('web form: the newsletter box records opt-in and consent time only when ticked', async () => {
  await post('/api/scan', { domain: 'nodmarc.com', email: 'sam@nodmarc.com', newsletter_opt_in: true }, '192.0.2.64');
  assert.equal(saved.at(-1).newsletter_opt_in, true);
  assert.ok(saved.at(-1).consent_at);
  await post('/api/scan', { domain: 'nodmarc.com', email: 'sam@nodmarc.com', newsletter_opt_in: false }, '192.0.2.65');
  assert.equal(saved.at(-1).newsletter_opt_in, false);
  assert.equal('consent_at' in saved.at(-1), false);
});
