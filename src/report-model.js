// The scan result object. Everything the report email shows and everything the
// JSON endpoint returns comes from here, so the two can never disagree.
//
// buildReportModel(report) takes the audit report (findings plus raw facts)
// and returns plain data: flags, friendly names, exact DNS records, and the
// ready-to-show sentences for each section of "What to do".

import { sendersFromSpf, systemForDkimTarget } from './senders.js';

const SPF_INCLUDE_FOR_MAILBOX = {
  google: 'include:_spf.google.com',
  microsoft: 'include:spf.protection.outlook.com',
  zoho: 'include:zoho.com',
  ses: 'include:amazonses.com',
};

export function formatDate(iso) {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return null;
  return new Intl.DateTimeFormat('en-US', { month: 'long', day: 'numeric', year: 'numeric', timeZone: 'UTC' }).format(d);
}

export function joinList(items) {
  if (items.length <= 1) return items.join('');
  if (items.length === 2) return `${items[0]} and ${items[1]}`;
  return `${items.slice(0, -1).join(', ')}, and ${items[items.length - 1]}`;
}

function spfRecordOf(spf) {
  const ev = spf?.evidence ?? {};
  return ev.fixed ?? ev.record ?? (ev.records ? ev.records.join(' ') : null);
}

// ---- 1. Your website ----------------------------------------------------

function websiteSection(facts) {
  const w = facts?.website ?? { checked: false, leaks: [], wordpress: false, infrastructure: [] };
  const loadBalancers = w.infrastructure ?? [];
  let line;
  if (!w.checked) {
    line = 'We could not reach your website over HTTPS, so we could not check it.';
  } else if (w.leaks.length && w.wordpress) {
    line = 'If you are using WordPress, please run updates asap.';
  } else if (w.leaks.length) {
    line = `Your website is running ${joinList(w.leaks.map((l) => l.value))}.`;
  } else {
    line = 'Your website is not sharing version details with the public. Good.';
  }
  return {
    checked: w.checked,
    version_leaks: w.leaks,
    wordpress: w.wordpress,
    line,
    load_balancers: loadBalancers,
    load_balancer_line: loadBalancers.length ? `Your website is served through ${joinList(loadBalancers)}.` : null,
  };
}

// ---- 2. Your email ------------------------------------------------------

function spfStatus(spf) {
  const ev = spf?.evidence;
  if (!ev) return { status: 'missing', problem: 'Nothing lists the services allowed to send email as you.' };
  if (ev.records) return { status: 'incorrect', problem: `You have ${ev.records.length} SPF records. Only one is allowed.` };
  if (ev.problems?.length) return { status: 'incorrect', problem: 'Your SPF record has a typo, so inboxes ignore it.' };
  if (ev.all === '+all') return { status: 'incorrect', problem: 'Your SPF record lets anyone send email as you.' };
  if (ev.all !== '~all' && ev.all !== '-all') {
    return { status: 'incorrect', problem: 'Your SPF record does not end with ~all or -all, so it does not protect you.' };
  }
  if (ev.lookups > 10) {
    return { status: 'incorrect', problem: `Your SPF record needs ${ev.lookups} lookups. Inboxes stop reading after 10.` };
  }
  return { status: 'correct', problem: null };
}

function spfChange(spf, spfState, mailboxId) {
  if (spfState.status === 'correct') return { setting: 'SPF', change: false };
  const ev = spf?.evidence;
  const base = { setting: 'SPF', change: true, type: 'TXT', host: '@' };
  if (!ev) {
    const include = SPF_INCLUDE_FOR_MAILBOX[mailboxId];
    return {
      ...base,
      action: 'add',
      value: `v=spf1 ${include ?? 'include:<your email provider’s SPF domain>'} ~all`,
      note: 'Add an include for every other service that sends email as you.',
    };
  }
  if (ev.records) {
    const terms = [...new Set(ev.records.flatMap((r) => r.trim().split(/\s+/).slice(1)))]
      .filter((t) => !/^[+\-~?]?all$/i.test(t));
    return {
      ...base,
      action: 'change',
      value: ['v=spf1', ...terms, '~all'].join(' '),
      note: 'Keep this one record and delete the others.',
    };
  }
  if (ev.problems?.length) {
    return ev.fixed
      ? { ...base, action: 'change', value: ev.fixed, note: 'Edit your existing SPF record. Do not add a second one.' }
      : { ...base, action: 'change', value: null, note: 'Rewrite it using the SPF value from each service that sends as you.' };
  }
  if (ev.lookups > 10) {
    return {
      ...base,
      action: 'change',
      value: null,
      note: 'Remove includes for services you no longer use. If you need them all, ask your providers for a combined SPF value.',
    };
  }
  const record = ev.record.trim().split(/\s+/).filter((t) => !/^[+\-~?]?all$/i.test(t));
  return { ...base, action: 'change', value: [...record, '~all'].join(' '), note: 'Edit your existing SPF record.' };
}

function dmarcStatus(dmarc) {
  const ev = dmarc?.evidence;
  if (!ev) return { status: 'missing', problem: 'Nothing tells inboxes what to do with email that fakes your domain.' };
  if (ev.count > 1) return { status: 'incorrect', problem: 'You have more than one DMARC record. Only one is allowed.' };
  const p = (ev.tags?.p ?? '').toLowerCase();
  if (!['none', 'quarantine', 'reject'].includes(p)) {
    return { status: 'incorrect', problem: 'Your DMARC record has no valid p value, so it does not say what to do with fake email.' };
  }
  if (!ev.rua?.length) {
    return { status: 'incorrect', problem: 'Your DMARC record has no rua address, so nobody gets reports about fake email.' };
  }
  return { status: 'correct', problem: null };
}

function dmarcChange(dmarc, state, domain) {
  if (state.status === 'correct') return { setting: 'DMARC', change: false };
  const base = { setting: 'DMARC', change: true, type: 'TXT', host: '_dmarc' };
  const rua = `mailto:dmarc@${domain}`;
  const ev = dmarc?.evidence;
  if (!ev) {
    return {
      ...base,
      action: 'add',
      value: `v=DMARC1; p=none; rua=${rua}`,
      note: `Use a mailbox you read in place of dmarc@${domain} if you prefer.`,
      new_record: true,
    };
  }
  const tags = { ...ev.tags };
  delete tags.v;
  const p = (tags.p ?? '').toLowerCase();
  if (!['none', 'quarantine', 'reject'].includes(p)) tags.p = 'none';
  if (!ev.rua?.length) tags.rua = rua;
  const ordered = ['p', 'rua', ...Object.keys(tags).filter((k) => k !== 'p' && k !== 'rua')];
  const value = ['v=DMARC1', ...ordered.map((k) => `${k}=${tags[k]}`)].join('; ');
  return {
    ...base,
    action: 'change',
    value,
    note: ev.count > 1 ? 'Keep this one record and delete the others.' : 'Edit your existing DMARC record.',
    new_record: false,
  };
}

function dkimState(dkim, senders, sendsMail) {
  const found = dkim?.evidence?.selectors ?? [];
  const targets = dkim?.evidence?.targets ?? {};
  // Who holds each key we found: the CNAME target decides when there is one,
  // otherwise the selector name is our best guess.
  const signers = found.map((sel) => {
    const owner = systemForDkimTarget(targets[sel]);
    return { selector: sel, points_to: targets[sel] ?? null, sender: owner?.name ?? null, owner_id: owner?.id ?? null };
  });
  const keyBelongsTo = (sel, system) => {
    const signer = signers.find((x) => x.selector === sel);
    if (signer?.owner_id) return signer.owner_id === system.id;
    return system.selectors.includes(sel);
  };

  const spfIds = new Set(senders.map((s) => s.system?.id).filter(Boolean));
  const systems = senders
    .filter((s) => s.system)
    .map((s) => {
      const hit = found.filter((sel) => keyBelongsTo(sel, s.system));
      const status = hit.length ? 'found' : s.system.verifiable ? 'missing' : 'unconfirmed';
      return { name: s.name, status, selectors: hit, dashboard: s.system.dashboard };
    });
  // Keys whose CNAME names a system that SPF does not list.
  const otherSigners = [...new Set(signers.filter((x) => x.owner_id && !spfIds.has(x.owner_id)).map((x) => x.sender))];
  const missing = systems.filter((s) => s.status === 'missing');
  let status;
  let problem = null;
  if (systems.length) {
    status = missing.length ? 'missing' : 'correct';
    if (missing.length) problem = `No DKIM signature found for ${joinList(missing.map((s) => s.name))}.`;
  } else if (found.length || !sendsMail || senders.length === 0) {
    status = 'correct';
  } else {
    status = 'missing';
    problem = 'No DKIM signature found, so inboxes cannot tell your email really came from you.';
  }
  return {
    status,
    problem,
    found_selectors: found,
    systems,
    signers: signers.map(({ owner_id, ...rest }) => rest),
    other_signers: otherSigners,
  };
}

function emailSection(report) {
  const byId = Object.fromEntries(report.findings.map((f) => [f.id, f]));
  const spf = byId.spf;
  const dmarc = byId.dmarc;
  const senders = sendersFromSpf(spfRecordOf(spf));
  const sendingSystems = senders.map((s) => s.name);

  const spfState = spfStatus(spf);
  const dmarcStateV = dmarcStatus(dmarc);
  const dkim = dkimState(byId.dkim, senders, report.sendsMail !== false);
  const rua = dmarc?.evidence?.rua ?? [];
  const allCorrect = spfState.status === 'correct' && dmarcStateV.status === 'correct' && dkim.status === 'correct';

  const spfOut = {
    status: spfState.status,
    correct: spfState.status === 'correct',
    record: spf?.evidence?.record ?? null,
    lookups: spf?.evidence?.lookups ?? null,
    problem: spfState.problem,
  };
  const dmarcOut = {
    status: dmarcStateV.status,
    correct: dmarcStateV.status === 'correct',
    record: dmarc?.evidence?.record ?? null,
    policy: dmarc?.evidence?.tags?.p?.toLowerCase() ?? null,
    rua,
    problem: dmarcStateV.problem,
  };
  const dkimOut = { ...dkim, correct: dkim.status === 'correct' };

  const sendersLine = sendingSystems.length
    ? `You are sending mail or newsletters from ${joinList(sendingSystems)}. Is that correct?`
    : null;
  const unconfirmed = dkim.systems.filter((s) => s.status === 'unconfirmed');

  const changes = [
    spfChange(spf, spfState, report.emailSetup?.mailbox?.id),
    dmarcChange(dmarc, dmarcStateV, report.domain),
    dkim.status === 'correct'
      ? { setting: 'DKIM', change: false }
      : {
          setting: 'DKIM',
          change: true,
          steps: dkim.systems.filter((s) => s.status === 'missing').length
            ? dkim.systems
                .filter((s) => s.status === 'missing')
                .map((s) => `Turn on DKIM in ${s.name}. ${s.dashboard}`)
            : ['Turn on DKIM with your email provider. It gives you the record to add.'],
        },
  ];
  if (unconfirmed.length && changes[2].change) {
    changes[2].steps.push(
      ...unconfirmed.map((s) => `Check that DKIM is on in ${s.name}. We can't confirm it from outside. ${s.dashboard}`),
    );
  }

  const label = { SPF: 'SPF', DMARC: 'DMARC', DKIM: 'DKIM' };
  const correctLines = [];
  const attentionLines = [];
  for (const [name, st] of [['SPF', spfState], ['DMARC', dmarcStateV], ['DKIM', dkim]]) {
    if (st.status === 'correct') {
      correctLines.push(label[name]);
      if (name === 'SPF' && sendersLine) correctLines.push(sendersLine);
      if (name === 'DMARC' && rua.length) correctLines.push(`Reports go to ${joinList(rua)}.`);
      if (name === 'DKIM') {
        for (const s of unconfirmed) {
          correctLines.push(`DKIM for ${s.name} can't be confirmed from outside. Check your ${s.name} dashboard.`);
        }
      }
    } else {
      const what = st.status === 'missing' ? 'is missing' : 'has incorrect information';
      attentionLines.push(`${label[name]} ${what}. ${st.problem}`);
    }
  }

  const newDmarc = changes[1].change && changes[1].new_record;
  return {
    all_correct: allCorrect,
    sending_systems: sendingSystems,
    spf: spfOut,
    dmarc: dmarcOut,
    dkim: dkimOut,
    summary_line: allCorrect
      ? `Your emails are locked down and any errors go to ${joinList(rua)}. That's great! Who is reviewing DMARC notices for you?`
      : null,
    correct_lines: allCorrect ? [] : correctLines,
    attention_lines: allCorrect ? [] : attentionLines,
    dns_changes: allCorrect ? [] : changes,
    dmarc_advice: !allCorrect && newDmarc
      ? 'Start with p=none so nothing gets blocked while you learn who sends as you. After two weeks of reviewing reports, move to p=quarantine.'
      : null,
  };
}

// ---- 3. Your security certificate ---------------------------------------

function certificateSection(tlsFinding) {
  const ev = tlsFinding?.evidence ?? {};
  const valid = Boolean(ev.valid);
  const daysLeft = valid ? ev.daysLeft : null;
  const expiringSoon = valid && daysLeft != null && daysLeft <= 30;
  const expiresOn = valid ? formatDate(ev.expiresAt) : null;
  const lines = ['HTTPS can give your website a small boost in SEO when paired with content people want to read.'];
  if (valid) {
    lines.push(`Your SSL cert expires ${expiresOn}.`);
    if (expiringSoon) lines.push('That is soon. Renew it now.');
  } else {
    lines.push('Your website does not have a working SSL certificate. Browsers will warn visitors away.');
  }
  return {
    valid,
    hostname_match: ev.hostnameMatch ?? false,
    expires_at: valid ? ev.expiresAt : null,
    expires_on: expiresOn,
    days_left: daysLeft,
    expiring_soon: expiringSoon,
    lines,
  };
}

// ---- 4. Advanced settings -----------------------------------------------

function advancedSection(report) {
  const byId = Object.fromEntries(report.findings.map((f) => [f.id, f]));
  const headers = report.facts?.headers ?? null;
  const mta = byId['mta-sts']?.evidence ?? {};
  const items = [
    { name: 'MTA-STS', set: Boolean(mta.txt && mta.policy), description: 'request emails to use a secure connection.' },
    { name: 'BIMI', set: byId.bimi?.status === 'pass', description: 'for large established brands to add a logo next to their email name.' },
    { name: 'CAA records', set: byId.caa?.status === 'pass', description: 'locks the security certificates.' },
    { name: 'DNSSEC', set: byId.dnssec?.status === 'pass', description: 'locks your DNS settings.' },
  ];
  return {
    http_security: {
      intro:
        'The right settings protect your site. But settings that are too strict can stop parts of your website from working, such as videos, logins, forms, and other tools.',
      checked: Boolean(headers),
      in_place: headers?.present ?? [],
      missing: headers?.missing ?? [],
    },
    great_to_haves: {
      intro: 'These DNS settings are great to have but less common for smaller organizations.',
      items: items.map((i) => ({ ...i, status: i.set ? 'Set.' : 'Not set.' })),
    },
  };
}

// ---- Contract fields ------------------------------------------------------

const PLAIN = {
  spf: {
    pass: 'Your list of approved email senders is set up.',
    warn: 'Your list of approved email senders works but could be stricter.',
    fail: 'Your list of approved email senders is missing or broken.',
  },
  dmarc: {
    pass: 'Inboxes are told to block email that fakes your domain.',
    warn: 'Inboxes are told to watch, but not block, email that fakes your domain.',
    fail: 'Nothing tells inboxes what to do with email that fakes your domain.',
  },
  dkim: {
    pass: 'Your outgoing email carries a signature that proves it came from you.',
    warn: 'We could not find the signature that proves your email came from you.',
    fail: 'We could not find the signature that proves your email came from you.',
  },
  'mta-sts': {
    pass: 'Mail sent to you is asked to use a secure connection.',
    warn: 'Mail sent to you is not asked to use a secure connection.',
    info: 'Not needed, since this domain does not receive email.',
  },
  bimi: { pass: 'Your logo is set up to show next to your email in some inboxes.', info: 'No inbox logo is set up. This is optional.' },
  mx: { pass: 'Your domain is set up to receive email.', info: 'Your domain is set up not to receive email.' },
  nameservers: { pass: 'Your domain has backup servers for its settings.', warn: 'Your domain has no backup server for its settings.' },
  dnssec: { pass: 'Your domain settings are digitally signed.', warn: 'Your domain settings are not digitally signed.' },
  caa: { pass: 'Only the companies you chose can issue certificates for your site.', warn: 'Any company can issue a certificate for your site.' },
  tls: {
    pass: 'Your website has a working security certificate.',
    warn: 'Your website’s security certificate needs attention.',
    fail: 'Your website does not have a working security certificate.',
  },
  headers: {
    pass: 'Your website sends the settings that protect visitors.',
    warn: 'Your website is missing some settings that protect visitors.',
    fail: 'Your website is missing settings that protect visitors.',
  },
  php: {
    pass: 'No outdated website software is showing.',
    warn: 'Your website shows signs of software that may need updates.',
    fail: 'Your website runs software with a known security flaw.',
  },
};

function plainChecks(findings) {
  return findings.map((f) => ({
    name: f.title,
    status: f.status === 'info' ? 'pass' : f.status,
    plain_summary: PLAIN[f.id]?.[f.status] ?? f.summary,
  }));
}

function topFix(email, certificate, website) {
  if (email.spf.status === 'missing') return 'Add a record to your domain settings that lists every service allowed to send email for you.';
  if (email.spf.status === 'incorrect') return 'Fix the record in your domain settings that lists the services allowed to send email for you.';
  if (email.dmarc.status === 'missing') return 'Add a rule to your domain settings that tells inboxes what to do with email pretending to be from you.';
  if (email.dmarc.status === 'incorrect') return 'Fix the rule in your domain settings that tells inboxes what to do with fake email and where to send reports.';
  if (email.dkim.status !== 'correct') {
    const names = email.dkim.systems.filter((s) => s.status === 'missing').map((s) => s.name);
    return names.length
      ? `Turn on email signing in ${joinList(names)} so inboxes can tell your mail is really from you.`
      : 'Turn on email signing with your email provider so inboxes can tell your mail is really from you.';
  }
  if (!certificate.valid) return 'Install a working security certificate on your website so browsers stop warning visitors.';
  if (certificate.expiring_soon) return 'Renew your website’s security certificate now, before it runs out.';
  if (website.version_leaks.length) {
    return website.wordpress
      ? 'Run your WordPress updates now.'
      : 'Update your website software and stop it from showing its version number.';
  }
  return 'Nothing urgent to fix. Scan again after any change to your email or website settings.';
}

export function buildReportModel(report) {
  const byId = Object.fromEntries(report.findings.map((f) => [f.id, f]));
  const website = websiteSection(report.facts);
  const email = emailSection(report);
  const certificate = certificateSection(byId.tls);
  const advanced = advancedSection(report);
  const dmarcEv = byId.dmarc?.evidence;
  const pct = Number(dmarcEv?.tags?.pct ?? 100);
  const enforced = email.dmarc.status === 'correct' && ['quarantine', 'reject'].includes(email.dmarc.policy) && pct === 100;

  return {
    domain: report.domain,
    checked_at: report.scannedAt,
    checked_on: formatDate(report.scannedAt),
    grade: report.grade,
    score: report.score,
    can_be_faked: !enforced,
    likely_lands_in_inbox: email.spf.correct && email.dmarc.status !== 'missing' && email.dkim.correct,
    top_fix: topFix(email, certificate, website),
    checks: plainChecks(report.findings),
    website,
    email,
    certificate,
    advanced,
  };
}
