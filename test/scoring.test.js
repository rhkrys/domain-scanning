import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scoreFindings, gradeFor } from '../src/scoring.js';

test('gradeFor maps scores to letters', () => {
  assert.equal(gradeFor(100), 'A');
  assert.equal(gradeFor(90), 'A');
  assert.equal(gradeFor(85), 'B');
  assert.equal(gradeFor(72), 'C');
  assert.equal(gradeFor(61), 'D');
  assert.equal(gradeFor(55), 'E');
  assert.equal(gradeFor(10), 'F');
});

test('all passing findings score 100 / grade A', () => {
  const findings = [
    { id: 'a', status: 'pass', severity: 'info' },
    { id: 'b', status: 'pass', severity: 'info' },
  ];
  const r = scoreFindings(findings);
  assert.equal(r.score, 100);
  assert.equal(r.grade, 'A');
  assert.equal(r.priorities.length, 0);
});

test('failures subtract by severity; warnings cost half', () => {
  const findings = [
    { id: 'a', status: 'fail', severity: 'critical', recommendation: 'fix a' }, // -25
    { id: 'b', status: 'warn', severity: 'high', recommendation: 'fix b' }, //     -8 (round 7.5)
    { id: 'c', status: 'pass', severity: 'info' }, //                              0
    { id: 'd', status: 'info', severity: 'info' }, //                             0
  ];
  const r = scoreFindings(findings);
  assert.equal(r.score, 100 - 25 - 8);
  assert.equal(r.counts.fail, 1);
  assert.equal(r.counts.warn, 1);
  assert.equal(r.counts.pass, 1);
  assert.equal(r.counts.info, 1);
});

test('priorities are sorted worst-first and only include actionable findings', () => {
  const findings = [
    { id: 'low', status: 'warn', severity: 'low', recommendation: 'l' },
    { id: 'crit', status: 'fail', severity: 'critical', recommendation: 'c' },
    { id: 'med', status: 'fail', severity: 'medium', recommendation: 'm' },
    { id: 'passnorec', status: 'pass', severity: 'info' },
    { id: 'warnnorec', status: 'warn', severity: 'high' }, // no recommendation -> excluded
  ];
  const r = scoreFindings(findings);
  assert.deepEqual(r.priorities.map((f) => f.id), ['crit', 'med', 'low']);
});

test('score is clamped to 0', () => {
  const findings = Array.from({ length: 10 }, (_, i) => ({
    id: String(i), status: 'fail', severity: 'critical', recommendation: 'x',
  }));
  assert.equal(scoreFindings(findings).score, 0);
});
