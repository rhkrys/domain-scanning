import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createApp } from '../server.js';
import { createMemoryLimiter } from '../src/ratelimit.js';
import { createMemoryStore } from '../src/store.js';
import { loadConfig } from '../src/config.js';
import { scoreQuiz, validateQuizInput, POINTS } from '../src/wisp-quiz.js';
import { renderWispEmail } from '../src/email/render-wisp.js';

// compute() copied verbatim from the quiz page, so a change on either side
// that breaks the match fails here.
/* eslint-disable */
function pageCompute(inp, answers){
  var R = Math.max(0, +inp.R || 0), N = Math.max(0, +inp.N || 0), F = Math.max(0, +inp.F || 0), D = Math.max(1, Math.round(+inp.D || 1));
  var score = 0, answered = 0;
  for (var i = 0; i < answers.length; i++){ if (answers[i] !== null && answers[i] !== undefined){ answered++; score += answers[i]; } }
  var backup = answers[5];
  var days = backup === 2 ? 3 : (backup === 0 ? 21 : 10);
  var A = R * 181;
  var B = Math.round((N * F / 75) * days);
  var C = Math.min(R * 250, 10000);
  var missing = 0;
  [2,3,4,8].forEach(function(ix){ if (answers[ix] === 0) missing++; });
  var band = answered < 10 ? "none" : (score >= 16 ? "good" : (score >= 9 ? "mid" : "low"));
  return {score:score, answered:answered, days:days, A:A, B:B, C:C, total:A+B+C, missing:missing, ceiling:missing*53088, band:band,
          prices:[29 + D*15, 29 + D*75, 29 + D*120], devices:D};
}
/* eslint-enable */

const DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), '__snapshots__');
const TAKEN = '2026-11-10T15:00:00.000Z';
const SAMPLE = { answers: [1, 1, 0, 1, 2, 1, 0, 1, 1, 0], devices: 3, returns: 300, records: 400, fee: 250 };

test('scoring matches the quiz page for 500 random offices', () => {
  let seed = 7;
  const rand = (n) => ((seed = (seed * 48271) % 2147483647) % n);
  for (let k = 0; k < 500; k++) {
    const input = {
      answers: Array.from({ length: 10 }, () => rand(3)),
      devices: 1 + rand(40),
      returns: rand(5000),
      records: rand(20000),
      fee: rand(900),
    };
    const mine = scoreQuiz(input);
    const page = pageCompute({ R: input.records, N: input.returns, F: input.fee, D: input.devices }, input.answers.map((a) => POINTS[a]));
    assert.equal(mine.score, page.score);
    assert.equal(mine.band, page.band);
    assert.equal(mine.exposure.days_down, page.days);
    assert.equal(mine.exposure.breach_response, page.A);
    assert.equal(mine.exposure.filing_days_lost, page.B);
    assert.equal(mine.exposure.disclosure_penalty, page.C);
    assert.equal(mine.exposure.total, page.total);
    assert.equal(mine.missing_written_items, page.missing);
    assert.equal(mine.legal_ceiling, page.ceiling);
    assert.deepEqual(mine.prices.map((p) => p.monthly), page.prices);
  }
});

test('input checks need all ten answers and sane numbers', () => {
  assert.equal(validateQuizInput({ ...SAMPLE, answers: [0, 1] }).field, 'answers');
  assert.equal(validateQuizInput({ ...SAMPLE, answers: [0, 1, 2, 0, 1, 2, 0, 1, 2, 3] }).field, 'q10');
  assert.equal(validateQuizInput({ ...SAMPLE, devices: 0 }).field, 'devices');
  assert.equal(validateQuizInput({ ...SAMPLE, fee: 'abc' }).field, 'fee');
  assert.equal(validateQuizInput({ ...SAMPLE, records: undefined }).field, 'records');
  assert.deepEqual(validateQuizInput(SAMPLE).value, SAMPLE);
});

test('risk report email snapshot', () => {
  const email = renderWispEmail(scoreQuiz(SAMPLE), TAKEN);
  const text = `Subject: ${email.subject}\n\n${email.text}\n`;
  const file = path.join(DIR, 'wisp-quiz-partly-covered.txt');
  if (process.env.UPDATE_SNAPSHOTS === '1' || !fs.existsSync(file)) fs.writeFileSync(file, text);
  assert.equal(text, fs.readFileSync(file, 'utf8'));
  assert.equal(email.subject, 'Your WISP readiness report: 12 of 20, Partly covered');
  assert.ok(!email.text.includes('—') && !email.html.includes('—'), 'no em dashes');
  assert.match(email.html, /name="viewport" content="width=device-width,initial-scale=1"/);
  for (const s of ['Where to tighten up', 'Estimated exposure', 'Cost to cover it, per month', 'https://calendly.com/cpconsulting/15min', '$254']) {
    assert.ok(email.html.includes(s), s);
  }
});

test('a perfect score has no tighten-up section and suggests Plan', () => {
  const r = scoreQuiz({ ...SAMPLE, answers: Array(10).fill(0) });
  const email = renderWispEmail(r, TAKEN);
  assert.equal(r.score, 20);
  assert.equal(r.suggested_tier, 'Plan');
  assert.ok(!email.text.includes('WHERE TO TIGHTEN UP'));
  assert.match(email.text, /no missing written items/);
});

// ---- HTTP -------------------------------------------------------------------

let server;
let base;
const sent = [];
const store = createMemoryStore();

before(async () => {
  const app = createApp({
    sendEmail: async (to, rendered, label) => {
      sent.push({ to, rendered, label });
      return { delivered: true, mode: 'test' };
    },
    config: loadConfig({ QUIZ_NOTIFY_TO: 'owner@example.org' }),
    apiLimiter: createMemoryLimiter({ max: 2 }),
    store,
  });
  await new Promise((resolve) => {
    server = app.listen(0, resolve);
  });
  base = `http://127.0.0.1:${server.address().port}`;
});

after(() => server.close());

const post = (body, ip = '203.0.113.9') =>
  fetch(`${base}/api/v1/wisp-report`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-forwarded-for': ip },
    body: JSON.stringify(body),
  });

test('POST /api/v1/wisp-report emails the report, sends the copy, and returns the score', async () => {
  sent.length = 0;
  const res = await post({ ...SAMPLE, email: ' preparer@example.com ', newsletter_opt_in: true });
  assert.equal(res.status, 200);
  const json = await res.json();
  assert.equal(json.score, 12);
  assert.equal(json.band, 'mid');
  assert.equal(json.report_emailed, true);
  assert.equal(json.exposure.total, 72400 + 10000 + 10000);
  assert.deepEqual(sent.map((s) => s.to), ['preparer@example.com', 'owner@example.org']);
  assert.match(sent[0].rendered.subject, /^Your WISP readiness report: 12 of 20/);
  assert.match(sent[1].rendered.subject, /^WISP quiz: preparer@example.com scored 12 of 20/);
});

test('the server scores the answers itself and ignores a score sent by the browser', async () => {
  const json = await (await post({ ...SAMPLE, email: 'a@example.com', score: 20, band: 'good' }, '203.0.113.10')).json();
  assert.equal(json.score, 12);
});

test('email is required and checked for typos', async () => {
  let res = await post({ ...SAMPLE }, '203.0.113.11');
  assert.equal(res.status, 400);
  assert.equal((await res.json()).field, 'email');
  res = await post({ ...SAMPLE, email: 'me@gmial.com' }, '203.0.113.11');
  assert.match((await res.json()).error, /gmail\.com/);
});

test('missing answers are rejected before any email is sent', async () => {
  sent.length = 0;
  const res = await post({ ...SAMPLE, answers: [0, 0, 0], email: 'b@example.com' }, '203.0.113.12');
  assert.equal(res.status, 400);
  assert.equal(sent.length, 0);
});

test('reports are rate limited per IP, separately from scans', async () => {
  const ip = '203.0.113.13';
  assert.equal((await post({ ...SAMPLE, email: 'c@example.com' }, ip)).status, 200);
  assert.equal((await post({ ...SAMPLE, email: 'c@example.com' }, ip)).status, 200);
  assert.equal((await post({ ...SAMPLE, email: 'c@example.com' }, ip)).status, 429);
});

test('quiz submissions are saved but never served as scan reports', async () => {
  const saved = [];
  const spyStore = { save: async (r) => { saved.push(r); return store.save(r); }, get: (id) => store.get(id) };
  const app = createApp({ sendEmail: async () => ({ delivered: true }), config: loadConfig({}), apiLimiter: createMemoryLimiter(), store: spyStore });
  const srv = await new Promise((resolve) => { const s = app.listen(0, () => resolve(s)); });
  const url = `http://127.0.0.1:${srv.address().port}`;
  await fetch(`${url}/api/v1/wisp-report`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ ...SAMPLE, email: 'd@example.com' }) });
  const rec = saved[0];
  assert.equal(rec.source, 'wisp-quiz');
  assert.equal(rec.email, 'd@example.com');
  assert.equal(rec.newsletter_opt_in, false);
  assert.ok(!('consent_at' in rec));
  assert.ok(rec.expires_at - Date.now() / 1000 > 360 * 86400);
  assert.equal((await fetch(`${url}/api/report/${rec.scan_id}`)).status, 404);
  srv.close();
});
