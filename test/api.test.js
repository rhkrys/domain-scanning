import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createApp } from '../server.js';
import { createMemoryLimiter, hashIp } from '../src/ratelimit.js';
import { loadConfig } from '../src/config.js';
import { SCENARIOS } from './fixtures/scans.js';

let server;
let base;
const audited = [];

before(async () => {
  const fixture = await SCENARIOS['dkim-missing-one-sender']();
  const app = createApp({
    audit: async (domain) => {
      audited.push(domain);
      return { ...fixture, domain, result: { ...fixture.result, domain } };
    },
    send: async () => ({ delivered: true, mode: 'test' }),
    config: loadConfig({ ALLOWED_ORIGINS: 'https://chatgpt.com, https://app.example.org', PUBLIC_BASE_URL: 'https://www.techinpeace.com/' }),
    apiLimiter: createMemoryLimiter({ max: 3 }),
  });
  await new Promise((resolve) => {
    server = app.listen(0, resolve);
  });
  base = `http://127.0.0.1:${server.address().port}`;
});

after(() => server.close());

const scan = (body, headers = {}) =>
  fetch(`${base}/api/v1/scan`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-forwarded-for': '198.51.100.1', ...headers },
    body: JSON.stringify(body),
  });

test('POST /api/v1/scan needs only a domain and returns the contract fields', async () => {
  const res = await scan({ domain: 'https://www.Example.com/path' });
  assert.equal(res.status, 200);
  const json = await res.json();
  assert.equal(audited.at(-1), 'example.com');
  for (const key of ['domain', 'checked_at', 'can_be_faked', 'likely_lands_in_inbox', 'top_fix', 'checks', 'report_url']) {
    assert.ok(key in json, key);
  }
  assert.equal(typeof json.can_be_faked, 'boolean');
  assert.ok(json.checks.every((c) => ['pass', 'warn', 'fail'].includes(c.status) && typeof c.plain_summary === 'string'));
  assert.match(json.report_url, /^https:\/\/www\.techinpeace\.com\/scan\?report=[0-9a-f-]{36}$/);
});

test('the JSON carries the same section data the email reads', async () => {
  const json = await (await scan({ domain: 'twosenders.com' }, { 'x-forwarded-for': '198.51.100.2' })).json();
  assert.deepEqual(json.email.sending_systems, ['Google Workspace', 'Mailchimp']);
  assert.equal(json.email.dkim.correct, false);
  assert.equal(json.certificate.expires_on, 'January 23, 2027');
  assert.equal(typeof json.website.line, 'string');
  assert.ok(Array.isArray(json.advanced.great_to_haves.items));
});

test('report_url resolves to the saved report', async () => {
  const json = await (await scan({ domain: 'saved.com' }, { 'x-forwarded-for': '198.51.100.3' })).json();
  const id = json.report_url.split('report=')[1];
  const res = await fetch(`${base}/api/report/${id}`);
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.report.domain, 'saved.com');
  assert.deepEqual(Object.keys(body), ['report']);
  assert.equal((await fetch(`${base}/api/report/not-a-real-id`)).status, 404);
  assert.equal((await fetch(`${base}/api/report/${crypto.randomUUID()}`)).status, 404);
});

test('a bad domain is a 400 with the field named', async () => {
  const res = await scan({ domain: 'not a domain' }, { 'x-forwarded-for': '198.51.100.4' });
  assert.equal(res.status, 400);
  assert.equal((await res.json()).field, 'domain');
  assert.equal((await scan({}, { 'x-forwarded-for': '198.51.100.4' })).status, 400);
});

test('rate limit: the 4th scan from one IP in the hour is refused', async () => {
  const ip = { 'x-forwarded-for': '203.0.113.77' };
  for (let i = 0; i < 3; i += 1) assert.equal((await scan({ domain: 'a.com' }, ip)).status, 200);
  const res = await scan({ domain: 'a.com' }, ip);
  assert.equal(res.status, 429);
  assert.equal((await scan({ domain: 'a.com' }, { 'x-forwarded-for': '203.0.113.78' })).status, 200, 'other IPs unaffected');
});

test('CORS: allowed origins from config get headers, others do not', async () => {
  const ok = await scan({ domain: 'b.com' }, { origin: 'https://chatgpt.com', 'x-forwarded-for': '198.51.100.9' });
  assert.equal(ok.headers.get('access-control-allow-origin'), 'https://chatgpt.com');
  const other = await scan({ domain: 'b.com' }, { origin: 'https://evil.example', 'x-forwarded-for': '198.51.100.10' });
  assert.equal(other.headers.get('access-control-allow-origin'), null);
  const pre = await fetch(`${base}/api/v1/scan`, {
    method: 'OPTIONS',
    headers: { origin: 'https://app.example.org', 'access-control-request-method': 'POST' },
  });
  assert.equal(pre.status, 204);
  assert.equal(pre.headers.get('access-control-allow-origin'), 'https://app.example.org');
  assert.match(pre.headers.get('access-control-allow-methods'), /POST/);
});

test('config reads origins and base URL from the environment, not code', () => {
  const c = loadConfig({});
  assert.deepEqual(c.allowedOrigins, []);
  assert.equal(c.publicBaseUrl, 'https://www.techinpeace.com');
  assert.equal(c.apiScansPerHour, 10);
});

test('the rate-limit key is a salted hash, never the IP', () => {
  const h = hashIp('203.0.113.5', 'salt');
  assert.match(h, /^[0-9a-f]{64}$/);
  assert.ok(!h.includes('203'));
  assert.notEqual(h, hashIp('203.0.113.5', 'other-salt'));
});
