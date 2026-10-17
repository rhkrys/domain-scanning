// Pure scoring: turn a list of findings into a 0-100 score and a letter grade.
//
// We start from 100 and subtract a penalty for every finding that is not a
// pass, weighted by severity. Informational findings never cost points.

const PENALTY = {
  critical: 25,
  high: 15,
  medium: 8,
  low: 3,
  info: 0,
};

// A failing check costs full penalty; a warning costs half.
function penaltyFor(finding) {
  if (finding.status === 'pass' || finding.status === 'info') return 0;
  const base = PENALTY[finding.severity] ?? 0;
  return finding.status === 'fail' ? base : Math.round(base / 2);
}

export function gradeFor(score) {
  if (score >= 90) return 'A';
  if (score >= 80) return 'B';
  if (score >= 70) return 'C';
  if (score >= 60) return 'D';
  if (score >= 50) return 'E';
  return 'F';
}

export function scoreFindings(findings) {
  let score = 100;
  for (const f of findings) score -= penaltyFor(f);
  score = Math.max(0, Math.min(100, score));

  const counts = { pass: 0, warn: 0, fail: 0, info: 0 };
  for (const f of findings) counts[f.status] = (counts[f.status] ?? 0) + 1;

  // Surface the issues that matter most, worst first.
  const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const priorities = findings
    .filter((f) => (f.status === 'fail' || f.status === 'warn') && f.recommendation)
    .sort((a, b) => (order[a.severity] ?? 9) - (order[b.severity] ?? 9));

  return {
    score,
    grade: gradeFor(score),
    counts,
    priorities,
  };
}
