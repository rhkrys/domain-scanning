// Renders the audit report into the email we send the user: a plain-English
// summary, the grade, and a prioritised list of next steps. Pure functions so
// they can be unit-tested without a mail server.

// Cyber Protection (CPI) brand tokens. Email clients rarely load web fonts, so
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
  fontBody: "'Open Sans', Arial, Helvetica, sans-serif",
  fontDisplay: "'Oswald', 'Arial Narrow', Arial, sans-serif",
};

// Grade fill uses the added semantic status set (the brand defines none).
const GRADE_COLOUR = {
  A: CPI.pass, B: CPI.pass, C: CPI.warn, D: CPI.warn, E: CPI.fail, F: CPI.fail,
};

const STATUS_LABEL = { pass: 'OK', warn: 'Review', fail: 'Action needed', info: 'Info' };

// Content-ID the mailer uses when attaching the logo inline.
export const LOGO_CID = 'cpi-logo';

function esc(s) {
  return String(s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c]);
}

export function subjectFor(report) {
  return `Security scan for ${report.domain}: grade ${report.grade} (${report.score}/100)`;
}

export function renderText(report) {
  const lines = [];
  lines.push('CYBER PROTECTION — Consulting Services');
  lines.push('');
  lines.push(`Website security scan — ${report.domain}`);
  lines.push(`Overall grade: ${report.grade}  (${report.score}/100)`);
  lines.push(
    `Checks: ${report.counts.pass} passed, ${report.counts.warn} to review, ${report.counts.fail} need action.`,
  );
  lines.push('');

  if (report.priorities.length === 0) {
    lines.push('No action items — every check passed. Nicely done.');
  } else {
    lines.push('Your next steps (most important first):');
    report.priorities.forEach((f, i) => {
      lines.push(`  ${i + 1}. [${f.severity.toUpperCase()}] ${f.title}: ${f.summary}`);
      lines.push(`     ${f.recommendation}`);
    });
  }

  lines.push('');
  lines.push('Full results:');
  for (const f of report.findings) {
    lines.push(`  - ${f.title} [${STATUS_LABEL[f.status]}]: ${f.summary}`);
  }
  lines.push('');
  lines.push(`Scanned at ${report.scannedAt}.`);
  lines.push('This automated scan is a starting point, not a full security audit.');
  return lines.join('\n');
}

export function renderHtml(report) {
  const colour = GRADE_COLOUR[report.grade] ?? CPI.info;
  const headingStyle = `font-family:${CPI.fontDisplay};font-weight:400;text-transform:uppercase;letter-spacing:0.02em;color:${CPI.navyDeep};margin:0 0 12px;font-size:19px;border-bottom:2px solid ${CPI.gold};padding-bottom:6px;display:inline-block`;

  const steps = report.priorities.length
    ? `<ol style="padding-left:20px;margin:0">${report.priorities
        .map(
          (f) => `<li style="margin-bottom:14px">
            <strong style="color:${CPI.navyDeep}">${esc(f.title)}</strong>
            <span style="color:#fff;background:${severityColour(f.severity)};border-radius:2px;padding:2px 8px;font-size:10px;margin-left:6px;text-transform:uppercase;letter-spacing:0.08em">${esc(
              f.severity.toUpperCase(),
            )}</span><br>
            <span style="color:${CPI.muted}">${esc(f.summary)}.</span><br>
            <span style="color:${CPI.ink}">${esc(f.recommendation)}</span>
          </li>`,
        )
        .join('')}</ol>`
    : `<p style="color:${CPI.pass}"><strong>No action items — every check passed.</strong></p>`;

  const rows = report.findings
    .map((f) => {
      const badge = { pass: CPI.pass, warn: CPI.warn, fail: CPI.fail, info: CPI.info }[f.status];
      return `<tr>
        <td style="padding:7px 10px;border-bottom:1px solid ${CPI.border};color:${CPI.navyDeep};font-weight:700">${esc(f.title)}</td>
        <td style="padding:7px 10px;border-bottom:1px solid ${CPI.border};color:${badge};font-weight:700">${esc(
          STATUS_LABEL[f.status],
        )}</td>
        <td style="padding:7px 10px;border-bottom:1px solid ${CPI.border};color:${CPI.muted}">${esc(f.summary)}</td>
      </tr>`;
    })
    .join('');

  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <link href="https://fonts.googleapis.com/css2?family=Oswald:wght@400;600&family=Open+Sans:wght@600;700&display=swap" rel="stylesheet"></head>
  <body style="margin:0;background:${CPI.paper};font-family:${CPI.fontBody};font-weight:600;color:${CPI.ink}">
  <div style="max-width:640px;margin:0 auto;padding:24px">
    <div style="background:${CPI.surface};border:1px solid ${CPI.border};border-radius:2px;overflow:hidden">
      <!-- Brand header (logo embedded as an inline CID attachment) -->
      <div style="padding:18px 24px;background:${CPI.navyDeep};border-bottom:2px solid ${CPI.gold}">
        <table role="presentation" cellpadding="0" cellspacing="0"><tr>
          <td style="padding-right:14px;vertical-align:middle"><img src="cid:${LOGO_CID}" width="44" height="44" alt="Cyber Protection" style="display:block;border:0"></td>
          <td style="vertical-align:middle">
            <div style="font-family:${CPI.fontBody};font-weight:700;color:#ffffff;font-size:16px;letter-spacing:0.14em;text-transform:uppercase">Cyber Protection</div>
            <div style="font-family:${CPI.fontBody};font-weight:700;color:${CPI.gold};font-size:9px;letter-spacing:0.26em;text-transform:uppercase;margin-top:5px">Consulting Services</div>
          </td>
        </tr></table>
      </div>
      <div style="padding:22px 24px 6px;border-bottom:1px solid ${CPI.border}">
        <p style="margin:0 0 4px;color:${CPI.navy};font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:0.18em">Website security scan</p>
        <h1 style="margin:0 0 16px;font-family:${CPI.fontDisplay};font-weight:400;font-size:30px;text-transform:uppercase;color:${CPI.navyDeep};letter-spacing:0.01em">${esc(report.domain)}</h1>
      </div>
      <!-- Grade -->
      <div style="padding:22px 24px">
        <table role="presentation" cellpadding="0" cellspacing="0"><tr>
          <td style="width:76px;height:76px;background:${colour};color:#ffffff;font-family:${CPI.fontDisplay};font-weight:400;font-size:40px;text-align:center;vertical-align:middle;border-radius:2px">${esc(
            report.grade,
          )}</td>
          <td style="padding-left:18px;vertical-align:middle">
            <div style="font-family:${CPI.fontDisplay};font-size:26px;color:${CPI.navy}">${report.score}/100</div>
            <div style="color:${CPI.muted};font-size:14px">${report.counts.pass} OK · ${report.counts.warn} to review · ${report.counts.fail} need action</div>
          </td>
        </tr></table>
      </div>
      <div style="padding:0 24px 10px"><h2 style="${headingStyle}">What to do next</h2>${steps}</div>
      <div style="padding:14px 24px 24px">
        <h2 style="${headingStyle}">All ${report.findings.length} checks</h2>
        <table style="width:100%;border-collapse:collapse;font-size:13px">${rows}</table>
      </div>
      <div style="padding:16px 24px;background:${CPI.paperAlt};color:${CPI.muted};font-size:12px">
        Scanned at ${esc(report.scannedAt)}. This automated scan is a starting point, not a full security audit.
      </div>
    </div>
    <div style="text-align:center;color:${CPI.muted};font-size:11px;margin-top:14px;letter-spacing:0.14em;text-transform:uppercase">Cyber Protection · Consulting Services</div>
  </div>
</body></html>`;
}

function severityColour(severity) {
  if (severity === 'critical' || severity === 'high') return CPI.fail;
  if (severity === 'medium') return CPI.warn;
  return CPI.navy;
}

export function renderEmail(report) {
  return {
    subject: subjectFor(report),
    text: renderText(report),
    html: renderHtml(report),
  };
}
