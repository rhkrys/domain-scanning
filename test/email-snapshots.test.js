// Snapshot tests for the report email. Each fixture scan's plain-text email is
// compared with test/__snapshots__/<name>.txt. To accept a deliberate change,
// rerun with UPDATE_SNAPSHOTS=1 and review the diff before committing.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { SCENARIOS } from './fixtures/scans.js';
import { renderEmail } from '../src/email/render.js';

const DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), '__snapshots__');

function matchSnapshot(name, text) {
  const file = path.join(DIR, `${name}.txt`);
  if (process.env.UPDATE_SNAPSHOTS === '1' || !fs.existsSync(file)) {
    fs.mkdirSync(DIR, { recursive: true });
    fs.writeFileSync(file, text);
    return;
  }
  assert.equal(text, fs.readFileSync(file, 'utf8'), `email text for ${name} changed; see ${file}`);
}

for (const name of Object.keys(SCENARIOS)) {
  test(`email snapshot: ${name}`, async () => {
    const report = await SCENARIOS[name]();
    const email = renderEmail(report);
    matchSnapshot(name, `Subject: ${email.subject}\n\n${email.text}\n`);

    // Same words in both versions, no em dashes, and built for phones.
    assert.equal(email.subject, `Your domain and website security report for ${report.domain}`);
    assert.ok(!email.text.includes('—') && !email.html.includes('—'), 'no em dashes');
    assert.match(email.html, /name="viewport" content="width=device-width,initial-scale=1"/);
    assert.match(email.html, /max-width:640px;width:100%/);
    for (const heading of ['What to do', '1. Your website', '2. Your email', '3. Your security certificate', '4. Advanced settings']) {
      assert.ok(email.html.includes(heading), heading);
    }
    assert.ok(email.html.includes(report.result.website.line.replace(/'/g, '&#39;')) || email.html.includes(report.result.website.line));
  });
}

test('the email and the JSON result read the same object', async () => {
  const report = await SCENARIOS['dkim-missing-one-sender']();
  const text = renderEmail(report).text;
  for (const line of [...report.result.email.attention_lines, ...report.result.certificate.lines, report.result.website.line]) {
    assert.ok(text.includes(line), line);
  }
});
