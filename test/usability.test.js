// End-to-end tests for the ways non-technical users actually fill in the
// form: pasted links, www. prefixes, stray spaces, emails in the wrong box,
// and mistyped mail providers. Runs the real Express app over HTTP with the
// audit and mailer stubbed out, so it is fast and needs no network.

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import { createApp, emailInputProblem } from '../server.js';
import { normaliseDomain, domainInputProblem } from '../src/audit.js';

function fixtureReport(domain) {
  return {
    domain,
    scannedAt: new Date().toISOString(),
    sendsMail: true,
    score: 72,
    grade: 'C',
    counts: { pass: 8, warn: 3, fail: 1, info: 0 },
    priorities: [
      {
        id: 'dmarc', title: 'DMARC', severity: 'high', status: 'warn',
        summary: 'DMARC in monitor-only mode (p=none)',
        recommendation: 'Raise the policy to p=quarantine then p=reject.',
      },
    ],
    findings: [
      { id: 'mx', category: 'DNS Foundation', title: 'MX records', status: 'pass', severity: 'info', summary: '2 mail servers configured' },
      { id: 'dmarc', category: 'Email Authentication', title: 'DMARC', status: 'warn', severity: 'high', summary: 'DMARC in monitor-only mode (p=none)' },
    ],
  };
}

let server;
let base;
const sentEmails = [];

before(async () => {
  const app = createApp({
    audit: async (domain) => fixtureReport(domain),
    send: async (to, report) => {
      sentEmails.push({ to, domain: report.domain });
      return { delivered: true, mode: 'smtp', messageId: 'test-1' };
    },
    rateLimit: { max: 1000 },
  });
  await new Promise((resolve) => {
    server = app.listen(0, resolve);
  });
  base = `http://localhost:${server.address().port}`;
});

after(() => server.close());

async function scan(body) {
  const res = await fetch(`${base}/api/scan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  return { status: res.status, body: await res.json() };
}

// ---- Domain field: forgiving input ----------------------------------------

test('user pastes their full website link', async () => {
  const r = await scan({ domain: 'https://www.example.com/about-us?ref=home' });
  assert.equal(r.status, 200);
  assert.equal(r.body.report.domain, 'example.com');
});

test('user types www. and mixed case', async () => {
  const r = await scan({ domain: 'WWW.Example.COM' });
  assert.equal(r.status, 200);
  assert.equal(r.body.report.domain, 'example.com');
});

test('user leaves stray spaces around and inside the domain', async () => {
  const r = await scan({ domain: '  example .com  ' });
  assert.equal(r.status, 200);
  assert.equal(r.body.report.domain, 'example.com');
});

test('user types a trailing dot or slash', async () => {
  assert.equal((await scan({ domain: 'example.com.' })).body.report.domain, 'example.com');
  assert.equal((await scan({ domain: 'example.com/' })).body.report.domain, 'example.com');
});

// ---- Domain field: clear guidance when we can't help -----------------------

test('user types their email in the domain box', async () => {
  const r = await scan({ domain: 'jane@example.com' });
  assert.equal(r.status, 400);
  assert.equal(r.body.field, 'domain');
  assert.match(r.body.error, /looks like an email address/i);
  assert.match(r.body.error, /example\.com/);
});

test('user types a name with no dot', async () => {
  const r = await scan({ domain: 'mycompany' });
  assert.equal(r.status, 400);
  assert.equal(r.body.field, 'domain');
  assert.match(r.body.error, /mycompany\.com/);
});

test('user leaves the domain empty', async () => {
  const r = await scan({ domain: '' });
  assert.equal(r.status, 400);
  assert.match(r.body.error, /website address/i);
});

test('gibberish gets a friendly, non-technical message', async () => {
  const r = await scan({ domain: '!!!.???' });
  assert.equal(r.status, 400);
  assert.match(r.body.error, /example\.com/);
  assert.doesNotMatch(r.body.error, /regex|invalid input|null|undefined/i);
});

// ---- Email field -----------------------------------------------------------

test('valid email gets the report sent', async () => {
  sentEmails.length = 0;
  const r = await scan({ domain: 'example.com', email: 'jane@company.co.nz' });
  assert.equal(r.status, 200);
  assert.equal(r.body.mail.delivered, true);
  assert.deepEqual(sentEmails, [{ to: 'jane@company.co.nz', domain: 'example.com' }]);
});

test('email with surrounding spaces is accepted and trimmed', async () => {
  sentEmails.length = 0;
  const r = await scan({ domain: 'example.com', email: '  jane@company.co.nz  ' });
  assert.equal(r.status, 200);
  assert.equal(sentEmails[0].to, 'jane@company.co.nz');
});

test('common provider typo is caught with a suggestion', async () => {
  const r = await scan({ domain: 'example.com', email: 'jane@gmial.com' });
  assert.equal(r.status, 400);
  assert.equal(r.body.field, 'email');
  assert.match(r.body.error, /gmail\.com/);
});

test('clearly broken email gets a plain-language message', async () => {
  const r = await scan({ domain: 'example.com', email: 'jane.com' });
  assert.equal(r.status, 400);
  assert.equal(r.body.field, 'email');
  assert.match(r.body.error, /you@example\.com/);
});

test('email is optional — report still returned without one', async () => {
  const r = await scan({ domain: 'example.com' });
  assert.equal(r.status, 200);
  assert.equal(r.body.mail, null);
  assert.equal(r.body.report.grade, 'C');
});

// ---- The page itself -------------------------------------------------------

test('landing page uses plain language, not jargon, for the form', async () => {
  const res = await fetch(`${base}/`);
  const html = await res.text();
  assert.match(html, /Your website address/);
  assert.match(html, /Check my website/);
  assert.match(html, /paste your full website link/i);
  assert.match(html, /no spam/i);
  // The form labels themselves should not lead with acronyms.
  assert.doesNotMatch(html.match(/<label[^>]*>.*?<\/label>/gs).join(' '), /\b(SPF|DKIM|DMARC|DNS|TLS)\b/);
});

test('frontend script renders friendly status labels', async () => {
  const js = await fs.readFile(new URL('../public/app.js', import.meta.url), 'utf8');
  assert.match(js, /Worth a look/);
  assert.match(js, /Needs fixing/);
  assert.match(js, /we checked/i);
});

test('rate limiting replies in plain language', async () => {
  const app = createApp({
    audit: async (d) => fixtureReport(d),
    rateLimit: { max: 2 },
  });
  const srv = await new Promise((resolve) => {
    const s = app.listen(0, () => resolve(s));
  });
  try {
    const url = `http://localhost:${srv.address().port}/api/scan`;
    const post = () => fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domain: 'example.com' }),
    });
    await post();
    await post();
    const res = await post();
    assert.equal(res.status, 429);
    const body = await res.json();
    assert.match(body.error, /wait a minute/i);
  } finally {
    srv.close();
  }
});

// ---- Unit coverage for the helpers ----------------------------------------

test('normaliseDomain handles real-world messy input', () => {
  assert.equal(normaliseDomain('https://www.shop.example.co.nz/cart'), 'shop.example.co.nz');
  assert.equal(normaliseDomain('www.example.com'), 'example.com');
  assert.equal(normaliseDomain('Example . Com'), 'example.com');
  assert.equal(normaliseDomain('http://example.com:8080/x'), 'example.com');
});

test('domainInputProblem explains each failure mode', () => {
  assert.equal(domainInputProblem('example.com'), null);
  assert.match(domainInputProblem(''), /website address/);
  assert.match(domainInputProblem('me@x.com'), /email address/);
  assert.match(domainInputProblem('mysite'), /mysite\.com/);
});

test('emailInputProblem accepts good addresses and flags typos', () => {
  assert.equal(emailInputProblem('a@b.co'), null);
  assert.match(emailInputProblem('a@hotmial.com'), /hotmail\.com/);
  assert.match(emailInputProblem('nope'), /you@example\.com/);
});
