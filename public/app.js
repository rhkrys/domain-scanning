const form = document.getElementById('scan-form');
const errorEl = document.getElementById('form-error');
const domainErrorEl = document.getElementById('domain-error');
const emailErrorEl = document.getElementById('email-error');
const progressEl = document.getElementById('progress');
const submitBtn = document.getElementById('submit');
const resultEl = document.getElementById('result');

const STATUS_LABEL = { pass: 'OK', warn: 'Worth a look', fail: 'Needs fixing', info: 'Info' };

// When the site is deployed without the scan backend (static S3+CloudFront),
// config.js sets apiEnabled:false so we explain it's coming soon rather than
// calling an endpoint that isn't there.
const API_ENABLED = !(window.APP_CONFIG && window.APP_CONFIG.apiEnabled === false);
const comingSoonEl = document.getElementById('coming-soon');
if (!API_ENABLED && comingSoonEl) comingSoonEl.hidden = false;

function clearErrors() {
  for (const el of [errorEl, domainErrorEl, emailErrorEl]) {
    el.hidden = true;
    el.textContent = '';
  }
}

function showError(message, field) {
  const el = field === 'domain' ? domainErrorEl : field === 'email' ? emailErrorEl : errorEl;
  el.textContent = message;
  el.hidden = false;
  if (field) document.getElementById(field).focus();
}

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  clearErrors();

  const domain = document.getElementById('domain').value.trim();
  const email = document.getElementById('email').value.trim();
  if (!domain) {
    showError('Please enter your website address, e.g. example.com.', 'domain');
    return;
  }

  // Static deployment without the backend: explain, don't call a dead endpoint.
  if (!API_ENABLED) {
    if (comingSoonEl) comingSoonEl.hidden = false;
    showError('The live scanner isn’t switched on for this site yet — it’s coming soon. Please check back shortly.');
    return;
  }

  submitBtn.disabled = true;
  submitBtn.textContent = 'Checking…';
  progressEl.hidden = false;

  try {
    const res = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domain, email }),
    });
    const data = await res.json();
    if (!res.ok) {
      showError(data.error || 'Something went wrong. Please try again.', data.field);
      return;
    }
    render(data, domain);
  } catch {
    showError('We couldn’t reach the scanner. Check your connection and try again.');
  } finally {
    submitBtn.disabled = false;
    submitBtn.textContent = 'Check my website';
    progressEl.hidden = true;
  }
});

function render({ report, mail }, typedDomain) {
  document.getElementById('result-domain').textContent = report.domain;
  document.getElementById('result-score').textContent = `${report.score}/100`;
  document.getElementById('result-counts').textContent =
    `${report.counts.pass} OK · ${report.counts.warn} worth a look · ${report.counts.fail} need fixing`;

  // If we tidied up what they typed (pasted URL, www., etc.), say so.
  const cleanedNote = document.getElementById('cleaned-note');
  const typed = typedDomain.toLowerCase();
  if (typed !== report.domain && typed !== `www.${report.domain}`) {
    cleanedNote.textContent = `You entered “${typedDomain}” — we checked ${report.domain}.`;
    cleanedNote.hidden = false;
  } else if (typed === `www.${report.domain}`) {
    cleanedNote.textContent = `We checked ${report.domain} (the security settings live there, not on www).`;
    cleanedNote.hidden = false;
  } else {
    cleanedNote.hidden = true;
  }

  const grade = document.getElementById('grade');
  grade.textContent = report.grade;
  grade.className = `grade ${report.grade}`;

  const mailStatus = document.getElementById('mail-status');
  if (mail && mail.delivered) {
    mailStatus.textContent = '✓ We’ve emailed you this report with your to-do list.';
    mailStatus.hidden = false;
  } else if (mail && mail.mode === 'preview') {
    mailStatus.textContent = 'Email preview generated (email sending isn’t set up on this server yet).';
    mailStatus.hidden = false;
  } else if (mail && mail.mode === 'error') {
    mailStatus.textContent = 'We couldn’t send the email just now, but your full report is below.';
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
