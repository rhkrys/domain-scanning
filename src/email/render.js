// Renders the report email from the scan result object (report.result), the
// same object the JSON endpoint returns. Plain text and HTML carry the same
// words. Pure functions so they can be snapshot-tested without a mail server.

import { buildReportModel } from '../report-model.js';

// CPI brand tokens. Email clients rarely load web fonts, so
// the display face falls back through Oswald → Arial Narrow → Arial.
const CPI = {
  navy: '#203a7b',
  navyDeep: '#142534',
  gold: '#e8ae5c',
  surface: '#ffffff',
  paper: '#f1f8fa',
  paperAlt: '#faf6ef',
  ink: '#0d1a26',
  muted: '#6a7886',
  border: '#d9dee4',
  pass: '#1f7a5a',
  warn: '#c98a2b',
  fail: '#c0392b',
  info: '#6a7886',
  fontBody: "'Lato', Arial, Helvetica, sans-serif",
  fontDisplay: "'Oswald', 'Arial Narrow', Arial, sans-serif",
};

// Grade fill uses the added semantic status set (the brand defines none).
const GRADE_COLOUR = {
  A: CPI.pass, B: CPI.pass, C: CPI.warn, D: CPI.warn, E: CPI.fail, F: CPI.fail,
};

const STATUS_LABEL = { pass: 'OK', warn: 'Review', fail: 'Action needed', info: 'Info' };

// Content-ID the mailer uses when attaching the logo inline.
export const LOGO_CID = 'cpi-logo';

// Where the email sends people to scan again after they fix something.
const RESCAN_URL = 'https://www.techinpeace.com/scan';
const RESCAN_LINE = 'After making changes to your DNS or website, be sure to check your score again';
const NEED_A_HAND = "Reply to this email. If I don't hear back, I'll check in once in two weeks.";
const SIGNATURE = ['Crystal Pugh', 'Trust Architect', 'Tech in Peace', 'techinpeace.com'];
const DISCLAIMER = 'This automated scan is a starting point, not a full security audit.';

function esc(s) {
  return String(s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c]);
}

function resultOf(report) {
  return report.result ?? buildReportModel(report);
}

export function subjectFor(report) {
  return `Your domain and website security report for ${report.domain}`;
}

function opening(r) {
  return `Here is your free Tech in Peace report for ${r.domain}, scanned ${r.checked_on}.`;
}

// "Great to haves" line: "MTA-STS (request emails to use a secure connection): Set."
function haveLine(item) {
  return `${item.name} (${item.description.replace(/\.$/, '')}): ${item.status}`;
}

// The numbered DNS steps as plain lines (number, then indented detail lines).
function changeBlocks(email) {
  return email.dns_changes.map((c, i) => {
    const n = `${i + 1}. ${c.setting}`;
    if (!c.change) return { head: `${n}: no change needed.`, lines: [] };
    if (c.steps) return { head: `${n}:`, lines: c.steps };
    if (!c.value) return { head: `${n}: change needed.`, lines: [c.note] };
    const verb = c.action === 'add' ? 'Add this record.' : 'Change it to this record.';
    return {
      head: `${n}: ${verb}`,
      lines: [`Type: ${c.type}`, `Host: ${c.host}`, `Value: ${c.value}`, ...(c.note ? [c.note] : [])],
      record: true,
    };
  });
}

export function renderText(report) {
  const r = resultOf(report);
  const L = [];
  L.push('Hi,');
  L.push('');
  L.push(opening(r));
  L.push(`Grade: ${r.grade} (${r.score}/100)`);
  L.push('');
  L.push('WHAT TO DO');
  L.push('');
  L.push('1. Your website');
  L.push(r.website.line);
  if (r.website.load_balancer_line) L.push(r.website.load_balancer_line);
  L.push('');
  L.push('2. Your email');
  if (r.email.all_correct) {
    L.push(r.email.summary_line);
  } else {
    if (r.email.correct_lines.length) {
      L.push('These email settings are correct:');
      for (const line of r.email.correct_lines) L.push(`- ${line}`);
    }
    if (r.email.attention_lines.length) {
      L.push('These email settings need attention:');
      for (const line of r.email.attention_lines) L.push(`- ${line}`);
    }
    L.push('Changes to make in your DNS, in this order:');
    for (const b of changeBlocks(r.email)) {
      L.push(b.head);
      for (const line of b.lines) L.push(`   ${line}`);
    }
    if (r.email.dmarc_advice) L.push(r.email.dmarc_advice);
  }
  L.push('');
  L.push('3. Your security certificate');
  for (const line of r.certificate.lines) L.push(line);
  L.push('');
  L.push('4. Advanced settings');
  L.push('HTTP security');
  L.push(r.advanced.http_security.intro);
  if (r.advanced.http_security.checked) {
    L.push(`In place: ${r.advanced.http_security.in_place.join(', ') || 'none'}`);
    L.push(`Missing: ${r.advanced.http_security.missing.join(', ') || 'none'}`);
  } else {
    L.push('We could not read these settings because your website did not answer over HTTPS.');
  }
  L.push('');
  L.push('Great to haves');
  L.push(r.advanced.great_to_haves.intro);
  for (const item of r.advanced.great_to_haves.items) L.push(`- ${haveLine(item)}`);
  L.push('');
  L.push('Need a hand?');
  L.push(NEED_A_HAND);
  L.push('');
  for (const line of SIGNATURE) L.push(line);
  L.push('');
  L.push(`${RESCAN_LINE}: ${RESCAN_URL}`);
  L.push('');
  L.push('Full list of checks');
  for (const f of report.findings) L.push(`- ${f.title} [${STATUS_LABEL[f.status]}]: ${f.summary}`);
  L.push('');
  L.push(`Scanned at ${r.checked_at}. ${DISCLAIMER}`);
  return L.join('\n');
}

// ---- HTML ------------------------------------------------------------------
// One column, fluid width, no fixed pixel widths on content, long values wrap.

const P = `margin:0 0 10px;color:${CPI.ink};font-size:15px;line-height:1.5`;
const H2 = `font-family:${CPI.fontDisplay};font-weight:400;text-transform:uppercase;letter-spacing:0.02em;color:${CPI.navyDeep};margin:0 0 12px;font-size:20px;border-bottom:2px solid ${CPI.gold};padding-bottom:6px;display:inline-block`;
const H3 = `font-family:${CPI.fontBody};font-weight:700;color:${CPI.navy};font-size:16px;margin:18px 0 8px`;
const H4 = `font-family:${CPI.fontBody};font-weight:700;color:${CPI.navyDeep};font-size:14px;margin:12px 0 6px;text-transform:uppercase;letter-spacing:0.08em`;
const UL = 'padding-left:20px;margin:0 0 12px';
const LI = `margin:0 0 6px;color:${CPI.ink};font-size:15px;line-height:1.5`;
const CODE = `font-family:Menlo,Consolas,monospace;font-size:13px;background:${CPI.paper};padding:1px 4px;word-break:break-all`;

const p = (text) => `<p style="${P}">${esc(text)}</p>`;
const list = (items) => `<ul style="${UL}">${items.map((i) => `<li style="${LI}">${esc(i)}</li>`).join('')}</ul>`;

function emailHtml(email) {
  if (email.all_correct) return p(email.summary_line);
  let out = '';
  if (email.correct_lines.length) out += p('These email settings are correct:') + list(email.correct_lines);
  if (email.attention_lines.length) out += p('These email settings need attention:') + list(email.attention_lines);
  out += p('Changes to make in your DNS, in this order:');
  const items = changeBlocks(email).map((b) => {
    const detail = b.lines
      .map((line) => {
        const m = line.match(/^(Type|Host|Value): (.*)$/);
        return m
          ? `<br><span style="color:${CPI.muted}">${m[1]}:</span> <code style="${CODE}">${esc(m[2])}</code>`
          : `<br>${esc(line)}`;
      })
      .join('');
    return `<li style="${LI};margin-bottom:10px">${esc(b.head.replace(/^\d+\.\s/, ''))}${detail}</li>`;
  });
  out += `<ol style="${UL}">${items.join('')}</ol>`;
  if (email.dmarc_advice) out += p(email.dmarc_advice);
  return out;
}

export function renderHtml(report) {
  const r = resultOf(report);
  const colour = GRADE_COLOUR[r.grade] ?? CPI.info;
  const hs = r.advanced.http_security;

  const rows = report.findings
    .map((f) => {
      const badge = { pass: CPI.pass, warn: CPI.warn, fail: CPI.fail, info: CPI.info }[f.status];
      return `<tr>
        <td style="padding:7px 8px;border-bottom:1px solid ${CPI.border};color:${CPI.navyDeep};font-weight:700;vertical-align:top">${esc(f.title)}</td>
        <td style="padding:7px 8px;border-bottom:1px solid ${CPI.border};color:${badge};font-weight:700;vertical-align:top;white-space:nowrap">${esc(STATUS_LABEL[f.status])}</td>
        <td style="padding:7px 8px;border-bottom:1px solid ${CPI.border};color:${CPI.muted};vertical-align:top">${esc(f.summary)}</td>
      </tr>`;
    })
    .join('');

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
            <div style="font-family:${CPI.fontBody};font-weight:700;color:#ffffff;font-size:16px;letter-spacing:0.14em;text-transform:uppercase">CPI</div>
            <div style="font-family:${CPI.fontBody};font-weight:700;color:${CPI.gold};font-size:9px;letter-spacing:0.26em;text-transform:uppercase;margin-top:5px">Consulting Services</div>
          </td>
        </tr></table>
      </div>

      <div style="padding:20px 20px 4px">
        ${p('Hi,')}
        ${p(opening(r))}
        <table role="presentation" cellpadding="0" cellspacing="0" style="margin:6px 0 4px"><tr>
          <td style="width:60px;height:60px;background:${colour};color:#ffffff;font-family:${CPI.fontDisplay};font-size:32px;text-align:center;vertical-align:middle;border-radius:2px">${esc(r.grade)}</td>
          <td style="padding-left:14px;vertical-align:middle;font-family:${CPI.fontDisplay};font-size:22px;color:${CPI.navy}">${esc(r.score)}/100</td>
        </tr></table>
      </div>

      <div style="padding:14px 20px 4px">
        <h2 style="${H2}">What to do</h2>
        <h3 style="${H3}">1. Your website</h3>
        ${p(r.website.line)}
        ${r.website.load_balancer_line ? p(r.website.load_balancer_line) : ''}
        <h3 style="${H3}">2. Your email</h3>
        ${emailHtml(r.email)}
        <h3 style="${H3}">3. Your security certificate</h3>
        ${r.certificate.lines.map(p).join('')}
        <h3 style="${H3}">4. Advanced settings</h3>
        <h4 style="${H4}">HTTP security</h4>
        ${p(hs.intro)}
        ${hs.checked
          ? p(`In place: ${hs.in_place.join(', ') || 'none'}`) + p(`Missing: ${hs.missing.join(', ') || 'none'}`)
          : p('We could not read these settings because your website did not answer over HTTPS.')}
        <h4 style="${H4}">Great to haves</h4>
        ${p(r.advanced.great_to_haves.intro)}
        ${list(r.advanced.great_to_haves.items.map(haveLine))}
      </div>

      <div style="padding:6px 20px 16px">
        <h3 style="${H3}">Need a hand?</h3>
        ${p(NEED_A_HAND)}
        <p style="${P};margin-top:14px">${SIGNATURE.map(esc).join('<br>')}</p>
        <p style="${P};margin-top:14px">${esc(RESCAN_LINE.replace(/check your score again$/, ''))}<a href="${RESCAN_URL}" style="color:${CPI.navy};font-weight:700">check your score again</a>.</p>
      </div>

      <div style="padding:14px 20px 20px;border-top:1px solid ${CPI.border}">
        <h2 style="${H2}">Full list of checks</h2>
        <table role="presentation" style="width:100%;border-collapse:collapse;font-size:13px;table-layout:auto">${rows}</table>
      </div>
      <div style="padding:14px 20px;background:${CPI.paperAlt};color:${CPI.muted};font-size:12px">
        Scanned at ${esc(r.checked_at)}. ${esc(DISCLAIMER)}
      </div>
    </div>
    <div style="text-align:center;color:${CPI.muted};font-size:11px;margin-top:14px;letter-spacing:0.14em;text-transform:uppercase">CPI · Consulting Services</div>
  </div>
</body></html>`;
}

export function renderEmail(report) {
  return {
    subject: subjectFor(report),
    text: renderText(report),
    html: renderHtml(report),
  };
}
