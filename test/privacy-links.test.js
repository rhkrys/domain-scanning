// Every form that collects an email address links to the privacy policy, and
// the privacy policy itself has no em dashes.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const read = (p) => fs.readFileSync(path.join(ROOT, p), 'utf8');

// The privacy link must appear between the form's start and this many
// characters after its end.
function formLinksPrivacy(html, formStart, after = 600) {
  const a = html.indexOf(formStart);
  assert.ok(a >= 0, `form not found: ${formStart}`);
  const b = html.indexOf('</form>', a);
  return /\/privacy#privacy/.test(html.slice(a, b + after));
}

const FORMS = [
  ['public/index.html', '<form id="scan-form"', 'scan form'],
  ['public/index.html', '<form id="capture-form"', 'email me the report form'],
  ['landing/wisp.html', '<form class="quiz" id="quiz-form"', 'WISP quiz on /wisp'],
  ['landing/wisp-quiz.html', '<form class="quiz" id="quiz-form"', 'WISP quiz on /wisp/quiz'],
  ['landing/index.html', '<form class="signup" id="waitlist-form"', 'home waitlist'],
  ['gumroad/profile.html', '<form data-gumroad-follow>', 'Gumroad profile newsletter'],
];

for (const [file, start, name] of FORMS) {
  test(`${name} links to the privacy policy`, () => {
    assert.ok(formLinksPrivacy(read(file), start), `${name} in ${file} has no privacy link`);
  });
}

test('the quiz and scan newsletter boxes start unchecked', () => {
  for (const file of ['public/index.html', 'landing/wisp.html', 'landing/wisp-quiz.html']) {
    const box = read(file).match(/<input id="newsletter"[^>]*>/)[0];
    assert.ok(!/\bchecked\b/.test(box), `${file} newsletter box is pre-checked`);
  }
});

test('the privacy policy has no em dashes and keeps its key sections', () => {
  const html = read('landing/privacy.html');
  const policy = html.slice(html.indexOf('<article class="doc" id="privacy">'), html.indexOf('<article class="doc" id="terms">'));
  assert.ok(!policy.includes('—'), 'no em dashes');
  for (const s of ['3.2 Quizzes', '3.3 Newsletter', 'Beehiiv', 'HoneyBook', 'Amazon Simple Email Service', 'Cookies and tracking', 'Quiz answers, office details, and quiz reports', '[PRIVACY CONTACT EMAIL]', 'Last updated:']) {
    assert.ok(policy.includes(s), `privacy policy is missing: ${s}`);
  }
});
