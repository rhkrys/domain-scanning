import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  parsePhpVersion,
  phpPatchStatus,
  detectPhp,
  evaluateSoftware,
  checkSoftware,
} from '../src/checks/software.js';
import { runAudit } from '../src/audit.js';
import { FakeResolver } from './helpers.js';

const page = (headers = {}, html = '', url = 'https://example.com/') => ({ headers, html, url });

test('parsePhpVersion reads X-Powered-By and Server headers', () => {
  assert.equal(parsePhpVersion({ 'x-powered-by': 'PHP/8.3.20' }).raw, '8.3.20');
  const v = parsePhpVersion({ server: 'Apache/2.4.58 (Ubuntu) PHP/8.1.2-1ubuntu2.19' });
  assert.equal(v.minor, 1);
  assert.equal(v.distroBuild, true);
  assert.equal(parsePhpVersion({ 'x-powered-by': 'Express' }), null);
  assert.equal(parsePhpVersion({}), null);
});

test('phpPatchStatus compares against the fixed releases', () => {
  const s = (raw) => phpPatchStatus(parsePhpVersion({ 'x-powered-by': `PHP/${raw}` }));
  assert.equal(s('8.5.12'), 'patched');
  assert.equal(s('8.5.11'), 'unpatched');
  assert.equal(s('8.4.27'), 'patched');
  assert.equal(s('8.3.35'), 'unpatched');
  assert.equal(s('8.2.35'), 'patched');
  assert.equal(s('8.1.30'), 'unpatched');
  assert.equal(s('7.4.33'), 'unpatched');
  assert.equal(s('5.6.40'), 'unpatched');
  assert.equal(s('8.3'), 'unknown');
  assert.equal(s('9.0.0'), 'patched');
  assert.equal(phpPatchStatus(null), 'unknown');
});

test('detectPhp spots cookies, .php URLs and common platforms', () => {
  assert.equal(detectPhp(page({ 'set-cookie': ['PHPSESSID=abc; path=/'] })).signs.length, 1);
  assert.equal(detectPhp(page({}, '', 'https://example.com/index.php')).signs.length, 1);
  assert.equal(detectPhp(page({}, '<link href="/wp-content/themes/x/style.css">')).platform, 'WordPress');
  assert.equal(detectPhp(page({ 'x-generator': 'Drupal 10' })).platform, 'Drupal');
  assert.equal(detectPhp(page({}, '<meta name="generator" content="Joomla! - Open Source">')).platform, 'Joomla');
  assert.equal(detectPhp(page({ 'x-magento-cache-debug': 'HIT' })).platform, 'Magento');
  assert.deepEqual(detectPhp(page({ server: 'nginx' }, '<h1>Hi</h1>')).signs, []);
});

test('evaluateSoftware: unpatched version shown is a critical fail', () => {
  const r = evaluateSoftware(page({ 'x-powered-by': 'PHP/8.3.20' }));
  assert.equal(r.id, 'php');
  assert.equal(r.status, 'fail');
  assert.equal(r.severity, 'critical');
  assert.match(r.summary, /8\.3\.20/);
  assert.match(r.recommendation, /8\.3\.36/);
  assert.match(r.recommendation, /June 2026/);
});

test('evaluateSoftware: an old branch says it needs an upgrade', () => {
  const r = evaluateSoftware(page({ 'x-powered-by': 'PHP/7.4.33' }));
  assert.equal(r.status, 'fail');
  assert.match(r.detail, /no fix/);
});

test('evaluateSoftware: a distro build asks the host to confirm', () => {
  const r = evaluateSoftware(page({ server: 'Apache/2.4.58 (Ubuntu) PHP/8.3.6-0ubuntu0.24.04.5' }));
  assert.equal(r.status, 'fail');
  assert.match(r.detail, /Ask them to confirm/);
});

test('evaluateSoftware: patched version passes', () => {
  const r = evaluateSoftware(page({ 'x-powered-by': 'PHP/8.4.27' }));
  assert.equal(r.status, 'pass');
  assert.match(r.recommendation, /expose_php/);
});

test('evaluateSoftware: PHP with a hidden version is a high warning', () => {
  const r = evaluateSoftware(page({ 'cf-ray': 'abc' }, '<script src="/wp-includes/js/x.js"></script>'));
  assert.equal(r.status, 'warn');
  assert.equal(r.severity, 'high');
  assert.match(r.summary, /WordPress/);
  assert.match(r.detail, /Cloudflare/);
  assert.equal(r.evidence.behindCloudflare, true);
});

test('evaluateSoftware: no PHP signs passes and says it only checked one page', () => {
  const r = evaluateSoftware(page({ server: 'nginx' }, '<h1>Hello</h1>'));
  assert.equal(r.status, 'pass');
  assert.match(r.detail, /one public page/);
});

test('evaluateSoftware: unreachable site is a low warning', () => {
  const r = evaluateSoftware(null);
  assert.equal(r.status, 'warn');
  assert.equal(r.severity, 'low');
});

test('copy has no em dashes', () => {
  const samples = [
    evaluateSoftware(null),
    evaluateSoftware(page({ 'x-powered-by': 'PHP/8.3.20', 'cf-ray': 'x' })),
    evaluateSoftware(page({ 'x-powered-by': 'PHP/8.4.27' })),
    evaluateSoftware(page({}, '/wp-content/')),
    evaluateSoftware(page()),
  ];
  for (const r of samples) {
    for (const v of [r.summary, r.detail, r.recommendation ?? '']) assert.ok(!v.includes('—'), v);
  }
});

test('checkSoftware uses the shared page loader', async () => {
  const r = await checkSoftware('example.com', { loadPage: async () => page({ 'x-powered-by': 'PHP/8.2.10' }) });
  assert.equal(r.status, 'fail');
});

test('runAudit fetches the home page once for both checks', async () => {
  let calls = 0;
  const loadPage = async () => {
    calls += 1;
    return page({ 'x-powered-by': 'PHP/8.1.2', 'content-type': 'text/html' }, '<p>hi</p>');
  };
  const report = await runAudit('example.com', {
    resolver: new FakeResolver({ 'example.com|A': ['1.2.3.4'] }),
    loadPage,
  });
  assert.equal(calls, 1);
  const byId = Object.fromEntries(report.findings.map((f) => [f.id, f]));
  assert.equal(byId.php.status, 'fail');
  assert.equal(byId.headers.status, 'fail');
  assert.equal(report.priorities[0].id, 'php');
});
