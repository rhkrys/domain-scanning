const form = document.getElementById('scan-form');
const errorEl = document.getElementById('form-error');
const submitBtn = document.getElementById('submit');
const resultEl = document.getElementById('result');

const STATUS_LABEL = { pass: 'OK', warn: 'Review', fail: 'Action needed', info: 'Info' };

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  errorEl.hidden = true;

  const domain = document.getElementById('domain').value.trim();
  const email = document.getElementById('email').value.trim();
  if (!domain) return;

  submitBtn.disabled = true;
  submitBtn.textContent = 'Scanning…';

  try {
    const res = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domain, email }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Scan failed.');
    render(data);
  } catch (err) {
    errorEl.textContent = err.message;
    errorEl.hidden = false;
  } finally {
    submitBtn.disabled = false;
    submitBtn.textContent = 'Scan domain';
  }
});

function render({ report, mail }) {
  document.getElementById('result-domain').textContent = report.domain;
  document.getElementById('result-score').textContent = `${report.score}/100`;
  document.getElementById('result-counts').textContent =
    `${report.counts.pass} passed · ${report.counts.warn} to review · ${report.counts.fail} need action`;

  const grade = document.getElementById('grade');
  grade.textContent = report.grade;
  grade.className = `grade ${report.grade}`;

  const mailStatus = document.getElementById('mail-status');
  if (mail && mail.delivered) {
    mailStatus.textContent = '✓ Your next steps have been emailed to you.';
    mailStatus.hidden = false;
  } else if (mail && mail.mode === 'preview') {
    mailStatus.textContent = 'Email preview generated (SMTP not configured on this server).';
    mailStatus.hidden = false;
  } else if (mail && mail.mode === 'error') {
    mailStatus.textContent = 'We could not send the email, but your report is below.';
    mailStatus.hidden = false;
  } else {
    mailStatus.hidden = true;
  }

  // Next steps
  const steps = document.getElementById('next-steps');
  const noSteps = document.getElementById('no-steps');
  steps.innerHTML = '';
  if (report.priorities.length === 0) {
    noSteps.hidden = false;
  } else {
    noSteps.hidden = true;
    for (const f of report.priorities) {
      const li = document.createElement('li');
      li.innerHTML =
        `<strong>${escapeHtml(f.title)}</strong>` +
        `<span class="sev ${f.severity}">${f.severity.toUpperCase()}</span>` +
        `<span class="what"> — ${escapeHtml(f.summary)}.</span>` +
        `<span class="fix">${escapeHtml(f.recommendation)}</span>`;
      steps.appendChild(li);
    }
  }

  // All checks grouped by category
  const container = document.getElementById('findings');
  container.innerHTML = '';
  const byCategory = {};
  for (const f of report.findings) (byCategory[f.category] ??= []).push(f);
  for (const [category, items] of Object.entries(byCategory)) {
    const group = document.createElement('div');
    group.className = 'finding-group';
    group.innerHTML = `<h4>${escapeHtml(category)}</h4>`;
    for (const f of items) {
      const row = document.createElement('div');
      row.className = 'finding';
      row.innerHTML =
        `<span class="dot ${f.status}"></span>` +
        `<span class="title">${escapeHtml(f.title)}</span>` +
        `<span class="desc">${escapeHtml(STATUS_LABEL[f.status])} — ${escapeHtml(f.summary)}</span>`;
      group.appendChild(row);
    }
    container.appendChild(group);
  }

  resultEl.hidden = false;
  resultEl.scrollIntoView({ behavior: 'smooth' });
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"]/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c],
  );
}
