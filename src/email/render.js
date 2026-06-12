// Renders the audit report into the email we send the user: a plain-English
// summary, the grade, and a prioritised list of next steps. Pure functions so
// they can be unit-tested without a mail server.

const GRADE_COLOUR = {
  A: '#1a7f37', B: '#2da44e', C: '#bf8700', D: '#cf6d00', E: '#cf222e', F: '#a40e26',
};

const STATUS_LABEL = { pass: 'OK', warn: 'Review', fail: 'Action needed', info: 'Info' };

function esc(s) {
  return String(s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c]);
}

export function subjectFor(report) {
  return `Security scan for ${report.domain}: grade ${report.grade} (${report.score}/100)`;
}

export function renderText(report) {
  const lines = [];
  lines.push(`Domain security scan — ${report.domain}`);
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
  const colour = GRADE_COLOUR[report.grade] ?? '#57606a';

  const steps = report.priorities.length
    ? `<ol style="padding-left:20px;margin:0">${report.priorities
        .map(
          (f) => `<li style="margin-bottom:12px">
            <strong>${esc(f.title)}</strong>
            <span style="color:#fff;background:${colour};border-radius:10px;padding:1px 8px;font-size:11px;margin-left:6px">${esc(
              f.severity.toUpperCase(),
            )}</span><br>
            <span style="color:#57606a">${esc(f.summary)}.</span><br>
            <span>${esc(f.recommendation)}</span>
          </li>`,
        )
        .join('')}</ol>`
    : '<p style="color:#1a7f37"><strong>No action items — every check passed.</strong></p>';

  const rows = report.findings
    .map((f) => {
      const badge = { pass: '#1a7f37', warn: '#bf8700', fail: '#cf222e', info: '#57606a' }[f.status];
      return `<tr>
        <td style="padding:6px 10px;border-bottom:1px solid #eaeef2">${esc(f.title)}</td>
        <td style="padding:6px 10px;border-bottom:1px solid #eaeef2;color:${badge};font-weight:600">${esc(
          STATUS_LABEL[f.status],
        )}</td>
        <td style="padding:6px 10px;border-bottom:1px solid #eaeef2;color:#57606a">${esc(f.summary)}</td>
      </tr>`;
    })
    .join('');

  return `<!doctype html><html><body style="margin:0;background:#f6f8fa;font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#1f2328">
  <div style="max-width:640px;margin:0 auto;padding:24px">
    <div style="background:#fff;border:1px solid #d0d7de;border-radius:12px;overflow:hidden">
      <div style="padding:24px;border-bottom:1px solid #eaeef2">
        <p style="margin:0 0 4px;color:#57606a;font-size:13px">Domain security scan</p>
        <h1 style="margin:0;font-size:22px">${esc(report.domain)}</h1>
      </div>
      <div style="padding:24px;display:flex;align-items:center;gap:20px">
        <div style="width:72px;height:72px;border-radius:50%;background:${colour};color:#fff;display:flex;align-items:center;justify-content:center;font-size:34px;font-weight:700;text-align:center;line-height:72px">${esc(
          report.grade,
        )}</div>
        <div>
          <div style="font-size:24px;font-weight:700">${report.score}/100</div>
          <div style="color:#57606a;font-size:14px">${report.counts.pass} passed · ${report.counts.warn} to review · ${report.counts.fail} need action</div>
        </div>
      </div>
      <div style="padding:0 24px 8px"><h2 style="font-size:16px;margin:0 0 12px">Your next steps</h2>${steps}</div>
      <div style="padding:16px 24px 24px">
        <h2 style="font-size:16px;margin:0 0 12px">All ${report.findings.length} checks</h2>
        <table style="width:100%;border-collapse:collapse;font-size:13px">${rows}</table>
      </div>
      <div style="padding:16px 24px;background:#f6f8fa;color:#57606a;font-size:12px">
        Scanned at ${esc(report.scannedAt)}. This automated scan is a starting point, not a full security audit.
      </div>
    </div>
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
