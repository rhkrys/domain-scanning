// Checks an email address typed into a form, and catches common provider
// typos. Shared by the scanner and the quiz Lambda.

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// Catch the most common mail-provider typos so a mistyped address doesn't
// silently swallow the report.
const EMAIL_DOMAIN_TYPOS = {
  'gmial.com': 'gmail.com',
  'gamil.com': 'gmail.com',
  'gmal.com': 'gmail.com',
  'gmai.com': 'gmail.com',
  'gmail.co': 'gmail.com',
  'gmail.con': 'gmail.com',
  'hotmial.com': 'hotmail.com',
  'hotmal.com': 'hotmail.com',
  'hotmail.co': 'hotmail.com',
  'outlok.com': 'outlook.com',
  'outloook.com': 'outlook.com',
  'yaho.com': 'yahoo.com',
  'yahooo.com': 'yahoo.com',
  'iclould.com': 'icloud.com',
  'icoud.com': 'icloud.com',
};

export function emailInputProblem(email) {
  const e = String(email).trim();
  if (!EMAIL_RE.test(e)) {
    return 'That email address doesn’t look right. Check it follows the format you@example.com.';
  }
  const domain = e.split('@')[1].toLowerCase();
  const suggestion = EMAIL_DOMAIN_TYPOS[domain];
  if (suggestion) {
    return `Did you mean @${suggestion}? "${domain}" looks like a typo — please double-check so your report reaches you.`;
  }
  return null;
}
