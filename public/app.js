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

  // The email entered on the scan form is delivered during the scan, and its
  // confirmation matches the post-report "Email me the report" section exactly.
  const enteredEmail = document.getElementById('email').value.trim();
  const mailStatus = document.getElementById('mail-status');
  if (mail && mail.delivered) {
    mailStatus.textContent = enteredEmail
      ? `✓ Sent to ${enteredEmail}. Check your inbox.`
      : '✓ We’ve emailed you this report with your to-do list.';
    mailStatus.hidden = false;
  } else if (mail && mail.mode === 'preview') {
    mailStatus.textContent = 'Email preview generated (email sending isn’t set up on this server yet).';
    mailStatus.hidden = false;
  } else if (mail && mail.mode === 'error') {
    mailStatus.textContent = 'We couldn’t send that just now — please try again shortly.';
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

  // Second-chance CTA: email a copy + book a free Zoom review.
  setupCta(report.domain, mail, typedDomain);

  resultEl.hidden = false;
  ensureCalendly(); // now that the container is visible, size the widget correctly
  resultEl.scrollIntoView({ behavior: 'smooth' });
}

// Calendly's inline widget renders blank if initialised while its container is
// display:none, so we init it explicitly once the results are shown. The widget
// script loads async, so retry until it's available.
let calendlyInited = false;
function ensureCalendly() {
  if (calendlyInited) return;
  const el = document.getElementById('calendly-embed');
  if (!el) return;
  if (window.Calendly && typeof window.Calendly.initInlineWidget === 'function') {
    el.innerHTML = '';
    window.Calendly.initInlineWidget({ url: el.dataset.url, parentElement: el });
    calendlyInited = true;
  } else {
    setTimeout(ensureCalendly, 300);
  }
}

// Remembers the last scanned domain so the "email me the report" form can
// re-request delivery without the user retyping anything.
let lastScannedDomain = null;

function setupCta(domain, mail, typedDomain) {
  lastScannedDomain = domain;
  const lead = document.getElementById('cta-email-lead');
  const captureEmail = document.getElementById('capture-email');
  const captureStatus = document.getElementById('capture-status');
  captureStatus.hidden = true;

  if (mail && mail.delivered) {
    // They already got it — offer to send to another address.
    lead.textContent = 'Want this report sent to someone else too? Add their email.';
    captureEmail.value = '';
  } else {
    lead.textContent = 'Prefer it in writing? We’ll email you this report and your next steps.';
    // Pre-fill if they typed an email that failed to send.
    captureEmail.value = document.getElementById('email').value.trim();
  }
}

const captureForm = document.getElementById('capture-form');
if (captureForm) {
  captureForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const captureEmail = document.getElementById('capture-email');
    const captureStatus = document.getElementById('capture-status');
    const captureSubmit = document.getElementById('capture-submit');
    const email = captureEmail.value.trim();

    captureStatus.hidden = true;
    if (!email) {
      captureStatus.textContent = 'Please enter an email address.';
      captureStatus.className = 'capture-status err';
      captureStatus.hidden = false;
      return;
    }

    captureSubmit.disabled = true;
    captureSubmit.textContent = 'Sending…';
    try {
      const res = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain: lastScannedDomain, email }),
      });
      const data = await res.json();
      if (!res.ok) {
        captureStatus.textContent = data.error || 'We couldn’t send that just now — please try again.';
        captureStatus.className = 'capture-status err';
      } else if (data.mail && data.mail.delivered) {
        captureStatus.textContent = `✓ Sent to ${email}. Check your inbox.`;
        captureStatus.className = 'capture-status ok';
        captureEmail.value = '';
      } else {
        captureStatus.textContent = 'Scan finished, but the email couldn’t be sent. Please try again shortly.';
        captureStatus.className = 'capture-status err';
      }
    } catch {
      captureStatus.textContent = 'We couldn’t reach the scanner. Please try again.';
      captureStatus.className = 'capture-status err';
    } finally {
      captureStatus.hidden = false;
      captureSubmit.disabled = false;
      captureSubmit.textContent = 'Email me the report';
    }
  });
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"]/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c],
  );
}
