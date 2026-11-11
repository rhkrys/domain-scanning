// Renders the WISP readiness risk report email from scoreQuiz()'s result.
// Plain text and HTML carry the same words. Wording comes from the quiz page;
// the only new lines are the section headings and the per-question
// "Full points" line, which repeats the quiz's own top answer.

import { CPI, esc, LOGO_CID, NEED_A_HAND, SIGNATURE } from '../../../email/render.js';
import { money, FTC_MAX_PER_VIOLATION, OFFICE_FEE } from './scoring.js';

export const BOOK_URL = 'https://calendly.com/cpconsulting/15min';
const BOOK_LABEL = 'Book Secure in a Day';

const SOURCES = [
  'This is a planning estimate. It is not a prediction, a quote or legal advice. The IRS does not set a fixed fine for a missing WISP.',
  "Where the numbers come from: $181 per record is an average cost per sensitive record cited by Tax Protection Plus. Filing days lost assumes a 75 working day season and 3, 10 or 21 days down depending on your backup answer. These day counts are assumptions. The disclosure penalty follows IRC 6713. The legal ceiling uses the FTC's 2025 maximum of $53,088 per violation.",
  'Tech in Peace by CPI. Brooklyn, New York.',
];

function takenOn(iso) {
  return new Date(iso).toLocaleDateString('en-US', { timeZone: 'America/New_York', year: 'numeric', month: 'long', day: 'numeric' });
}

export function wispSubject(r) {
  return `Your WISP readiness report: ${r.score} of ${r.max_score}, ${r.band_label}`;
}

function plural(n, word) {
  return `${n.toLocaleString('en-US')} ${word}${n === 1 ? '' : 's'}`;
}

function officeLine(o) {
  return `Your office: ${plural(o.devices, 'device')}, about ${plural(o.returns, 'return')} a year, ${plural(o.records, 'client record')}, ${money(o.fee)} average fee per return.`;
}

function ceilingLine(r) {
  const ftc = `The FTC ceiling is ${money(FTC_MAX_PER_VIOLATION)} per violation.`;
  if (r.missing_written_items === 0) {
    return `Legal maximum, not a forecast. ${ftc} Your answers show no missing written items from questions 3, 4, 5 and 9.`;
  }
  const n = r.missing_written_items;
  return `Legal maximum, not a forecast: ${money(r.legal_ceiling)}. ${ftc} Your answers show ${n} missing written item${n > 1 ? 's' : ''} from questions 3, 4, 5 and 9. Small offices rarely see the full amount.`;
}

function exposureRows(r) {
  const e = r.exposure;
  return [
    ['Breach response', `${r.office.records.toLocaleString('en-US')} records x $181`, money(e.breach_response)],
    ['Filing days lost', `${e.days_down} days down assumed (${e.days_down_reason})`, money(e.filing_days_lost)],
    ['Disclosure penalty', '$250 per record, capped at $10,000 a year', money(e.disclosure_penalty)],
  ];
}

function priceNote(r) {
  const d = r.office.devices;
  return `$${OFFICE_FEE} a month per office, plus the device fee for each of your ${d} device${d > 1 ? 's' : ''}. A device is any computer, laptop, tablet or phone that opens client tax data.`;
}

const gaps = (r) => r.answers.filter((a) => a.points < 2);
const inPlace = (r) => r.answers.filter((a) => a.points === 2);

export function renderWispText(r, takenAt) {
  const L = [];
  L.push('Hi,');
  L.push('');
  L.push(`Here is your WISP readiness report from Tech in Peace, from the quiz you took on ${takenOn(takenAt)}.`);
  L.push('');
  L.push(`Your readiness score: ${r.score} of ${r.max_score} points. ${r.band_label}.`);
  L.push(r.message);
  L.push(officeLine(r.office));
  L.push('');
  if (gaps(r).length) {
    L.push('WHERE TO TIGHTEN UP');
    for (const a of gaps(r)) {
      L.push(`${a.number}. ${a.question}`);
      L.push(`   Your answer: ${a.answer} (${a.points} of 2 points)`);
      L.push(`   Full points: ${a.full_points_answer}`);
    }
    L.push('');
  }
  if (inPlace(r).length) {
    L.push('ALREADY IN PLACE');
    for (const a of inPlace(r)) L.push(`- ${a.number}. ${a.question} ${a.answer}`);
    L.push('');
  }
  L.push('ESTIMATED EXPOSURE');
  for (const [name, note, value] of exposureRows(r)) {
    L.push(`${name}: ${value}`);
    L.push(`   ${note}`);
  }
  L.push(`Estimated exposure: ${money(r.exposure.total)}`);
  L.push(ceilingLine(r));
  L.push('');
  L.push('COST TO COVER IT, PER MONTH');
  for (const t of r.prices) {
    L.push(`${t.name}: ${money(t.monthly)} ($${t.perDevice} a device)${t.name === r.suggested_tier ? ', suggested for your score' : ''}`);
  }
  L.push(priceNote(r));
  L.push('');
  L.push(`${BOOK_LABEL}: ${BOOK_URL}`);
  L.push('');
  L.push('Need a hand?');
  L.push(NEED_A_HAND);
  L.push('');
  for (const line of SIGNATURE) L.push(line);
  L.push('');
  for (const line of SOURCES) L.push(line);
  return L.join('\n');
}

// ---- HTML ------------------------------------------------------------------

const P = `margin:0 0 10px;color:${CPI.ink};font-size:15px;line-height:1.5`;
const H2 = `font-family:${CPI.fontDisplay};font-weight:400;text-transform:uppercase;letter-spacing:0.02em;color:${CPI.navyDeep};margin:0 0 12px;font-size:20px;border-bottom:2px solid ${CPI.gold};padding-bottom:6px;display:inline-block`;
const TD = `padding:8px 8px;border-bottom:1px solid ${CPI.border};vertical-align:top;font-size:14px;line-height:1.45`;
const MUTED = `display:block;color:${CPI.muted};font-size:12px`;
const p = (text) => `<p style="${P}">${esc(text)}</p>`;
const BAND_COLOUR = { good: CPI.pass, mid: CPI.warn, low: CPI.fail };

export function renderWispHtml(r, takenAt) {
  const colour = BAND_COLOUR[r.band];
  const gapRows = gaps(r)
    .map((a) => `<tr>
        <td style="${TD};color:${CPI.navyDeep};font-weight:700;width:28px">${a.number}.</td>
        <td style="${TD}"><strong style="color:${CPI.navyDeep}">${esc(a.question)}</strong>
          <span style="display:block;margin-top:4px">Your answer: ${esc(a.answer)} <span style="color:${a.points === 0 ? CPI.fail : CPI.warn};font-weight:700;white-space:nowrap">(${a.points} of 2 points)</span></span>
          <span style="display:block;margin-top:2px;color:${CPI.pass}">Full points: ${esc(a.full_points_answer)}</span></td>
      </tr>`)
    .join('');
  const placeItems = inPlace(r)
    .map((a) => `<li style="margin:0 0 6px;color:${CPI.ink};font-size:14px;line-height:1.45">${a.number}. ${esc(a.question)} <span style="color:${CPI.pass}">${esc(a.answer)}</span></li>`)
    .join('');
  const expRows = exposureRows(r)
    .map(([name, note, value]) => `<tr><td style="${TD}">${esc(name)}<span style="${MUTED}">${esc(note)}</span></td><td style="${TD};text-align:right;white-space:nowrap">${esc(value)}</td></tr>`)
    .join('');
  const tierCells = r.prices
    .map((t) => {
      const on = t.name === r.suggested_tier;
      return `<td style="width:33%;padding:10px 6px;text-align:center;border:1px solid ${on ? CPI.gold : CPI.border};background:${on ? CPI.paperAlt : CPI.surface};vertical-align:top">
          <span style="${MUTED}">${esc(t.name)}</span>
          <span style="display:block;font-family:${CPI.fontDisplay};font-size:22px;color:${CPI.navy};margin:4px 0">${esc(money(t.monthly))}</span>
          <span style="${MUTED}">$${t.perDevice} a device</span>
          ${on ? `<span style="display:block;margin-top:6px;font-size:11px;font-weight:700;color:${CPI.navyDeep};text-transform:uppercase;letter-spacing:0.06em">Suggested</span>` : ''}
        </td>`;
    })
    .join('<td style="width:6px"></td>');

  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <meta name="x-apple-disable-message-reformatting">
  <link href="https://fonts.googleapis.com/css2?family=Oswald:wght@400;600&family=Lato:wght@400;700&display=swap" rel="stylesheet"></head>
  <body style="margin:0;padding:0;background:${CPI.paper};font-family:${CPI.fontBody};font-weight:400;color:${CPI.ink};-webkit-text-size-adjust:100%">
  <div style="max-width:640px;width:100%;margin:0 auto;padding:16px 0;box-sizing:border-box">
    <div style="background:${CPI.surface};border:1px solid ${CPI.border};border-radius:2px;overflow:hidden;margin:0 12px">
      <div style="padding:16px 20px;background:${CPI.navyDeep};border-bottom:2px solid ${CPI.gold}">
        <table role="presentation" cellpadding="0" cellspacing="0"><tr>
          <td style="padding-right:12px;vertical-align:middle"><img src="cid:${LOGO_CID}" width="40" height="40" alt="CPI" style="display:block;border:0"></td>
          <td style="vertical-align:middle">
            <div style="font-family:${CPI.fontBody};font-weight:700;color:#ffffff;font-size:16px;letter-spacing:0.14em;text-transform:uppercase">Tech in Peace</div>
            <div style="font-family:${CPI.fontBody};font-weight:700;color:${CPI.gold};font-size:9px;letter-spacing:0.26em;text-transform:uppercase;margin-top:5px">WISP readiness report</div>
          </td>
        </tr></table>
      </div>

      <div style="padding:20px 20px 4px">
        ${p('Hi,')}
        ${p(`Here is your WISP readiness report from Tech in Peace, from the quiz you took on ${takenOn(takenAt)}.`)}
        <table role="presentation" cellpadding="0" cellspacing="0" style="margin:6px 0 12px"><tr>
          <td style="font-family:${CPI.fontDisplay};font-size:40px;line-height:1;color:${CPI.navy};padding-right:10px;vertical-align:middle">${r.score}</td>
          <td style="vertical-align:middle;color:${CPI.muted};font-size:14px;padding-right:12px">of ${r.max_score} points</td>
          <td style="vertical-align:middle"><span style="display:inline-block;padding:3px 10px;border:1px solid ${colour};color:${colour};border-radius:999px;font-size:13px;font-weight:700">${esc(r.band_label)}</span></td>
        </tr></table>
        ${p(r.message)}
        <p style="${P};color:${CPI.muted};font-size:13px">${esc(officeLine(r.office))}</p>
      </div>

      ${gapRows ? `<div style="padding:14px 20px 4px">
        <h2 style="${H2}">Where to tighten up</h2>
        <table role="presentation" style="width:100%;border-collapse:collapse">${gapRows}</table>
      </div>` : ''}

      ${placeItems ? `<div style="padding:14px 20px 4px">
        <h2 style="${H2}">Already in place</h2>
        <ul style="padding-left:20px;margin:0 0 12px">${placeItems}</ul>
      </div>` : ''}

      <div style="padding:14px 20px 4px">
        <h2 style="${H2}">Estimated exposure</h2>
        <table role="presentation" style="width:100%;border-collapse:collapse">${expRows}
          <tr><td style="${TD};border-bottom:0;font-weight:700;font-size:16px;color:${CPI.navyDeep}">Estimated exposure</td><td style="${TD};border-bottom:0;text-align:right;font-weight:700;font-size:16px;color:${CPI.navyDeep};white-space:nowrap">${esc(money(r.exposure.total))}</td></tr>
        </table>
        <p style="${P};font-size:13px;color:${CPI.muted};border:1px dashed ${CPI.border};padding:10px;margin-top:8px">${esc(ceilingLine(r))}</p>
      </div>

      <div style="padding:14px 20px 4px">
        <h2 style="${H2}">Cost to cover it, per month</h2>
        <table role="presentation" cellpadding="0" cellspacing="0" style="width:100%;border-collapse:separate"><tr>${tierCells}</tr></table>
        <p style="${P};font-size:13px;color:${CPI.muted};margin-top:10px">${esc(priceNote(r))}</p>
        <p style="margin:14px 0 6px"><a href="${BOOK_URL}" style="display:inline-block;background:${CPI.gold};color:${CPI.navyDeep};font-weight:700;font-size:15px;text-decoration:none;padding:11px 18px;border-radius:2px">${BOOK_LABEL}</a></p>
      </div>

      <div style="padding:6px 20px 16px">
        <h3 style="font-family:${CPI.fontBody};font-weight:700;color:${CPI.navy};font-size:16px;margin:18px 0 8px">Need a hand?</h3>
        ${p(NEED_A_HAND)}
        <p style="${P};margin-top:14px">${SIGNATURE.map(esc).join('<br>')}</p>
      </div>

      <div style="padding:14px 20px;background:${CPI.paperAlt};color:${CPI.muted};font-size:12px;line-height:1.5">
        ${SOURCES.map((s) => `<p style="margin:0 0 6px">${esc(s)}</p>`).join('')}
      </div>
    </div>
  </div>
</body></html>`;
}

export function renderWispEmail(result, takenAt = new Date().toISOString()) {
  return {
    subject: wispSubject(result),
    text: renderWispText(result, takenAt),
    html: renderWispHtml(result, takenAt),
  };
}
