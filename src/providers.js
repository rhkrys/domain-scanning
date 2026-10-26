// Works out who runs a domain's email, so the report can link to that
// provider's own SPF, DKIM and DMARC setup guides.
//
// The mailbox provider comes from the MX records (who receives the mail).
// Services that only send as the domain (newsletters, receipts, password
// resets) never appear in MX, so we also read the SPF record's includes.
// Anything we do not recognise gets "check with your email provider".

export const PROVIDERS = [
  {
    id: 'google',
    name: 'Google Workspace',
    mx: [/(^|\.)google\.com$/, /(^|\.)googlemail\.com$/],
    spf: ['_spf.google.com', 'googlemail.com'],
    links: {
      spf: 'https://knowledge.workspace.google.com/admin/security/set-up-spf',
      dkim: 'https://knowledge.workspace.google.com/admin/security/set-up-dkim',
      dmarc: 'https://knowledge.workspace.google.com/admin/security/set-up-dmarc',
    },
  },
  {
    id: 'microsoft',
    name: 'Microsoft 365',
    mx: [/\.mail\.protection\.outlook\.com$/, /\.mx\.microsoft$/],
    spf: ['spf.protection.outlook.com'],
    links: {
      spf: 'https://learn.microsoft.com/en-us/defender-office-365/email-authentication-spf-configure',
      dkim: 'https://learn.microsoft.com/en-us/defender-office-365/email-authentication-dkim-configure',
      dmarc: 'https://learn.microsoft.com/en-us/defender-office-365/email-authentication-dmarc-configure',
    },
  },
  {
    id: 'zoho',
    name: 'Zoho Mail',
    mx: [/(^|\.)zoho(mail)?\.(com|eu|in|com\.au|jp|com\.cn|ca|sa|uk)$/],
    spf: ['zoho.com', 'zohomail.com', 'zoho.eu', 'zoho.in', 'zoho.com.au', 'zoho.jp', 'zoho.com.cn', 'zoho.ca', 'zoho.sa', 'zoho.uk'],
    links: {
      spf: 'https://www.zoho.com/mail/help/adminconsole/spf-configuration.html',
      dkim: 'https://www.zoho.com/mail/help/adminconsole/dkim-configuration.html',
      dmarc: 'https://www.zoho.com/mail/help/adminconsole/dmarc-policy.html',
    },
  },
  {
    id: 'ses',
    name: 'Amazon SES',
    mx: [/^inbound-smtp\.[a-z0-9-]+\.amazonaws\.com$/],
    spf: ['amazonses.com'],
    links: {
      spf: 'https://docs.aws.amazon.com/ses/latest/dg/send-email-authentication-spf.html',
      dkim: 'https://docs.aws.amazon.com/ses/latest/dg/send-email-authentication-dkim.html',
      dmarc: 'https://docs.aws.amazon.com/ses/latest/dg/send-email-authentication-dmarc.html',
    },
  },
  {
    id: 'sendgrid',
    name: 'Twilio SendGrid',
    mx: [],
    spf: ['sendgrid.net'],
    links: {
      spf: 'https://www.twilio.com/docs/sendgrid/ui/account-and-settings/how-to-set-up-domain-authentication',
      dkim: 'https://www.twilio.com/docs/sendgrid/ui/account-and-settings/how-to-set-up-domain-authentication',
      dmarc: 'https://www.twilio.com/docs/sendgrid/ui/sending-email/dmarc',
    },
  },
  {
    id: 'mailchimp',
    name: 'Mailchimp',
    mx: [],
    spf: ['servers.mcsv.net'],
    links: {
      spf: 'https://mailchimp.com/help/set-up-email-domain-authentication/',
      dkim: 'https://mailchimp.com/help/set-up-email-domain-authentication/',
      dmarc: 'https://mailchimp.com/help/set-up-email-domain-authentication/',
    },
  },
  {
    id: 'mandrill',
    name: 'Mailchimp Transactional (Mandrill)',
    mx: [],
    spf: ['mandrillapp.com'],
    links: {
      spf: 'https://mailchimp.com/developer/transactional/docs/authentication-delivery',
      dkim: 'https://mailchimp.com/developer/transactional/docs/authentication-delivery',
      dmarc: 'https://mailchimp.com/developer/transactional/docs/authentication-delivery',
    },
  },
];

function cleanHost(host) {
  return String(host ?? '').trim().toLowerCase().replace(/,+$/, '').replace(/\.$/, '');
}

// "include:_spf.google.com" and "include:spf.mandrillapp.com" both count:
// a match is the listed domain itself or any subdomain of it.
function spfIncludes(record) {
  if (typeof record !== 'string') return [];
  return record
    .split(/\s+/)
    .map((term) => term.match(/^[+~?-]?include:(.+)$/i)?.[1])
    .filter(Boolean)
    .map(cleanHost);
}

function matchesDomain(host, domains) {
  return domains.some((d) => host === d || host.endsWith(`.${d}`));
}

function publicView(p) {
  return { id: p.id, name: p.name, links: { ...p.links } };
}

// mxHosts: exchange names from the MX check. spfRecord: the SPF TXT string.
// Returns { mailbox, senders, known } where mailbox is the provider found in
// MX (or null), and senders are other known services found in SPF.
export function detectEmailProviders({ mxHosts = [], spfRecord = null } = {}) {
  const hosts = mxHosts.map(cleanHost).filter(Boolean);
  const mailbox = PROVIDERS.find((p) => hosts.some((h) => p.mx.some((re) => re.test(h)))) ?? null;

  const includes = spfIncludes(spfRecord);
  const senders = PROVIDERS.filter(
    (p) => p !== mailbox && includes.some((inc) => matchesDomain(inc, p.spf)),
  );

  return {
    mailbox: mailbox ? publicView(mailbox) : null,
    senders: senders.map(publicView),
    known: Boolean(mailbox) || senders.length > 0,
  };
}
