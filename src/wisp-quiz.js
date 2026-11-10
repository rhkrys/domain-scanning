// The WISP readiness quiz for tax preparers: the twelve questions, input
// checks, and the scoring. The math is a copy of the quiz page's compute(),
// so the emailed report always matches what the page showed. The server
// scores the answers itself and never trusts a score sent by the browser.
//
// Questions 1 to 10 are scored: option 0 is worth 2 points, option 1 is worth
// 1, option 2 is worth 0. Questions 11 (devices) and 12 (returns a year) size
// the estimate, with client records and average fee from the results panel.

export const QUESTIONS = [
  { q: 'Which email do you use for client work?', o: ['Business email: Google Workspace or Microsoft 365', 'Paid email from another provider', 'Free Gmail, Yahoo, AOL, or not sure'] },
  { q: 'Where is that email backed up?', o: ['A separate backup service', 'My email provider keeps it', 'Nowhere, or not sure'] },
  { q: 'Do you use a second sign-in step on email and tax software?', o: ['On both', 'On one', 'On neither, or not sure'] },
  { q: "Do you have a written security plan with your office's details?", o: ['Yes, dated in the last 12 months', 'A template or an older plan', 'No'] },
  { q: 'Who is your named security lead?', o: ['Named in writing', 'Me, informally', 'Nobody'] },
  { q: 'When did you last restore a file from backup as a test?', o: ['In the last 12 months', 'We back up but never tested', 'No backup, or not sure'] },
  { q: 'Are your computers and laptops encrypted?', o: ['All of them', 'Some of them', 'None, or not sure'] },
  { q: 'Do you have a list of every device that opens client data?', o: ['A written list', 'In my head', 'No'] },
  { q: 'A laptop is stolen tonight. Who do you call first?', o: ['I have written steps, starting with IT and the IRS Stakeholder Liaison', 'I know to call the IRS, nothing written', 'I would figure it out'] },
  { q: 'When someone leaves, how fast is their access removed?', o: ['Same day, from a checklist', 'Within a week', 'Not sure, or we share logins'] },
];

export const POINTS = [2, 1, 0];
// Questions 3, 4, 5 and 9 (zero-based 2, 3, 4, 8) are the written items the
// FTC ceiling line counts.
const WRITTEN_ITEMS = [2, 3, 4, 8];
const BACKUP_TEST = 5;

export const FTC_MAX_PER_VIOLATION = 53088;
export const COST_PER_RECORD = 181;
export const PENALTY_PER_RECORD = 250;
export const PENALTY_CAP = 10000;
export const SEASON_DAYS = 75;

export const TIERS = [
  { name: 'Plan', perDevice: 15 },
  { name: 'Protect', perDevice: 75 },
  { name: 'Concierge', perDevice: 120 },
];
export const OFFICE_FEE = 29;

export const BANDS = {
  good: { label: 'In good shape', message: 'You have most of it in place. A yearly review keeps it that way. The Plan tier fits.' },
  mid: { label: 'Partly covered', message: 'You have the pieces. They need to be written down and checked. Start with Secure in a Day, then Protect.' },
  low: { label: 'Starting point', message: 'Plenty of offices start here. One working session gets you a real plan. Start with Secure in a Day.' },
};

// Upper bounds keep a typo from producing an absurd report.
const LIMITS = {
  devices: { min: 1, max: 1000, label: 'Number of devices' },
  returns: { min: 0, max: 100000, label: 'Returns a year' },
  records: { min: 0, max: 1000000, label: 'Client records' },
  fee: { min: 0, max: 100000, label: 'Average fee per return' },
};

// Checks the request body. Returns { value } or { error, field }.
export function validateQuizInput(body = {}) {
  const { answers } = body;
  if (!Array.isArray(answers) || answers.length !== QUESTIONS.length) {
    return { error: `Answer all ${QUESTIONS.length} scored questions before sending your report.`, field: 'answers' };
  }
  for (let i = 0; i < answers.length; i++) {
    if (!Number.isInteger(answers[i]) || answers[i] < 0 || answers[i] > 2) {
      return { error: `Question ${i + 1} needs an answer.`, field: `q${i + 1}` };
    }
  }
  const value = { answers: [...answers] };
  for (const [key, { min, max, label }] of Object.entries(LIMITS)) {
    const n = Number(body[key]);
    if (body[key] === undefined || body[key] === null || body[key] === '' || !Number.isFinite(n) || n < min || n > max) {
      return { error: `${label} must be a number from ${min.toLocaleString('en-US')} to ${max.toLocaleString('en-US')}.`, field: key };
    }
    value[key] = key === 'devices' ? Math.round(n) : n;
  }
  return { value };
}

// Same rules as the quiz page. answers holds option indexes (0, 1 or 2).
export function scoreQuiz({ answers, devices, returns, records, fee }) {
  const points = answers.map((a) => POINTS[a]);
  const score = points.reduce((s, p) => s + p, 0);
  const backup = points[BACKUP_TEST];
  const days = backup === 2 ? 3 : backup === 0 ? 21 : 10;
  const daysWhy = backup === 2 ? 'backup tested' : backup === 0 ? 'no backup' : 'backup not tested';
  const breach = records * COST_PER_RECORD;
  const filing = Math.round(((returns * fee) / SEASON_DAYS) * days);
  const penalty = Math.min(records * PENALTY_PER_RECORD, PENALTY_CAP);
  const missing = WRITTEN_ITEMS.filter((ix) => points[ix] === 0).length;
  const band = score >= 16 ? 'good' : score >= 9 ? 'mid' : 'low';
  const prices = TIERS.map((t) => ({ name: t.name, perDevice: t.perDevice, monthly: OFFICE_FEE + devices * t.perDevice }));
  return {
    score,
    max_score: QUESTIONS.length * 2,
    band,
    band_label: BANDS[band].label,
    message: BANDS[band].message,
    answers: QUESTIONS.map((item, i) => ({
      number: i + 1,
      question: item.q,
      answer: item.o[answers[i]],
      points: points[i],
      full_points_answer: item.o[0],
    })),
    office: { devices, returns, records, fee },
    exposure: {
      breach_response: breach,
      filing_days_lost: filing,
      days_down: days,
      days_down_reason: daysWhy,
      disclosure_penalty: penalty,
      total: breach + filing + penalty,
    },
    missing_written_items: missing,
    legal_ceiling: missing * FTC_MAX_PER_VIOLATION,
    prices,
    // The tier the quiz page highlights: Plan for a good score, Protect otherwise.
    suggested_tier: band === 'good' ? 'Plan' : 'Protect',
  };
}

export function money(n) {
  return '$' + Math.round(n).toLocaleString('en-US');
}
