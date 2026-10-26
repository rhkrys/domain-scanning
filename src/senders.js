// Sending systems named in a domain's SPF record, with the DKIM selectors
// each one uses and where its owner turns DKIM on.
//
// spf: include (or redirect) domains that identify the system. A match is the
//      domain itself or any subdomain of it.
// selectors: DKIM names the system publishes. We test these on top of the
//      common list, so a Mailchimp sender gets k1/k2/k3 checked.
// dkimTargets: where the system's DKIM records point when they are CNAMEs
//      (k1._domainkey.you.com -> dkim.mcsv.net is Mailchimp). A CNAME is
//      stronger evidence than the selector name, which systems can share.
// verifiable: false when the system uses random or owner-chosen DKIM names
//      that no outside scan can guess. If we find nothing for these we say
//      "can't confirm from outside" instead of calling DKIM missing.

const GENERIC_DASHBOARD = (name) =>
  `In ${name}, open the account settings and look for email authentication or DKIM. It gives you the record to add.`;

export const SENDING_SYSTEMS = [
  {
    id: 'google',
    name: 'Google Workspace',
    spf: ['_spf.google.com', 'googlemail.com'],
    selectors: ['google'],
    dkimTargets: [],
    dashboard: 'In the Google Admin console, go to Apps, Google Workspace, Gmail, then Authenticate email.',
  },
  {
    id: 'microsoft',
    name: 'Microsoft 365',
    spf: ['spf.protection.outlook.com'],
    selectors: ['selector1', 'selector2'],
    dkimTargets: ['onmicrosoft.com', 'dkim.mail.microsoft'],
    dashboard:
      'In the Microsoft Defender portal, go to Email and collaboration, Policies and rules, Threat policies, Email authentication settings, then DKIM.',
  },
  {
    id: 'mailchimp',
    name: 'Mailchimp',
    spf: ['servers.mcsv.net'],
    selectors: ['k1', 'k2', 'k3'],
    dkimTargets: ['mcsv.net'],
    dashboard: 'In Mailchimp, go to Account and billing, Domains, then Authenticate next to your domain.',
  },
  {
    id: 'sendgrid',
    name: 'SendGrid',
    spf: ['sendgrid.net'],
    selectors: ['s1', 's2'],
    dkimTargets: ['sendgrid.net'],
    dashboard: 'In SendGrid, go to Settings, then Sender Authentication.',
  },
  {
    id: 'mailgun',
    name: 'Mailgun',
    spf: ['mailgun.org'],
    selectors: ['mx', 'k1', 'smtp'],
    dkimTargets: ['mailgun.org'],
    verifiable: false,
    dashboard: 'In Mailgun, open your sending domain and go to its DNS records page.',
  },
  {
    id: 'ses',
    name: 'Amazon SES',
    spf: ['amazonses.com'],
    selectors: [],
    dkimTargets: ['dkim.amazonses.com'],
    verifiable: false,
    dashboard: 'In the Amazon SES console, go to Identities, choose your domain, then the Authentication tab.',
  },
  {
    id: 'constantcontact',
    name: 'Constant Contact',
    spf: ['spf.constantcontact.com'],
    selectors: ['ctct1', 'ctct2'],
    dkimTargets: ['ccsend.com'],
  },
  {
    id: 'salesforce',
    name: 'Salesforce',
    spf: ['_spf.salesforce.com'],
    selectors: [],
    dkimTargets: ['salesforce.com'],
    verifiable: false,
    dashboard: 'In Salesforce Setup, search for DKIM Keys.',
  },
  {
    id: 'zendesk',
    name: 'Zendesk',
    spf: ['mail.zendesk.com'],
    selectors: ['zendesk1', 'zendesk2'],
    dkimTargets: ['zendesk.com'],
  },
  {
    id: 'mandrill',
    name: 'Mandrill',
    spf: ['spf.mandrillapp.com'],
    selectors: ['mandrill'],
    dkimTargets: ['mandrillapp.com'],
    dashboard: 'In Mandrill, go to Settings, Domains, then Sending domains.',
  },
  {
    id: 'hostinger',
    name: 'Hostinger',
    spf: ['_spf.mail.hostinger.com'],
    selectors: ['hostingermail1', 'hostingermail2', 'hostingermail3'],
    dkimTargets: ['hostinger.com'],
  },
  {
    id: 'godaddy',
    name: 'GoDaddy',
    spf: ['secureserver.net'],
    selectors: ['default'],
    dkimTargets: ['secureserver.net'],
    verifiable: false,
  },
  {
    id: 'resend',
    name: 'Resend',
    spf: ['spf.resend.com'],
    selectors: ['resend'],
    dkimTargets: ['resend.com'],
    dashboard: 'In Resend, go to Domains and open your domain.',
  },
  {
    id: 'klaviyo',
    name: 'Klaviyo',
    spf: ['spf.klaviyo.com'],
    selectors: ['kl', 'kl2'],
    dkimTargets: ['klaviyo.com'],
  },
  {
    id: 'shopify',
    name: 'Shopify',
    spf: ['shops.shopify.com'],
    selectors: [],
    dkimTargets: ['shopify.com', 'myshopify.com'],
    verifiable: false,
  },
  {
    id: 'squarespace',
    name: 'Squarespace',
    spf: ['spf.squarespace.com'],
    selectors: [],
    dkimTargets: ['squarespace.com'],
    verifiable: false,
  },
  {
    id: 'wix',
    name: 'Wix',
    spf: ['_spf.wix.com'],
    selectors: [],
    dkimTargets: ['wix.com'],
    verifiable: false,
  },
  {
    id: 'zoho',
    name: 'Zoho Mail',
    spf: ['zoho.com', 'zohomail.com', 'zoho.eu', 'zoho.in', 'zoho.com.au'],
    selectors: ['zoho', 'zmail'],
    dkimTargets: ['zoho.com'],
    verifiable: false,
    dashboard: 'In the Zoho Mail Admin Console, go to Domains, choose your domain, then Email configuration, DKIM.',
  },
].map((s) => ({ verifiable: true, dashboard: GENERIC_DASHBOARD(s.name), ...s }));

function matchesDomain(host, domains) {
  return domains.some((d) => host === d || host.endsWith(`.${d}`));
}

// Turns the SPF record into the list of places it allows mail from.
// Known includes become friendly names; unknown includes stay as the raw
// domain; ip4/ip6 show the address; a and mx get a plain label.
export function sendersFromSpf(record) {
  if (typeof record !== 'string') return [];
  const out = [];
  const seen = new Set();
  const add = (entry) => {
    const key = entry.id ?? `raw:${entry.name}`;
    if (seen.has(key)) return;
    seen.add(key);
    out.push(entry);
  };

  for (const raw of record.trim().split(/\s+/).slice(1)) {
    const term = raw.replace(/,+$/, '').replace(/^[+\-~?]/, '');
    let m;
    if ((m = term.match(/^(?:include:|redirect=)(.+)$/i))) {
      const host = m[1].toLowerCase().replace(/\.$/, '');
      const system = SENDING_SYSTEMS.find((s) => matchesDomain(host, s.spf));
      if (system) add({ id: system.id, name: system.name, source: host, system });
      else add({ id: null, name: host, source: host, system: null });
    } else if ((m = term.match(/^ip[46]:(.+)$/i))) {
      add({ id: null, name: m[1], source: term, system: null });
    } else if (/^mx(?:[:/]|$)/i.test(term)) {
      add({ id: 'mx', name: 'your own mail servers', source: term, system: null });
    } else if (/^a(?:[:/]|$)/i.test(term)) {
      add({ id: 'a', name: 'your website server', source: term, system: null });
    }
  }
  return out;
}

// The sending system a DKIM CNAME target belongs to, or null.
export function systemForDkimTarget(target) {
  const host = String(target ?? '').toLowerCase().replace(/\.$/, '');
  if (!host) return null;
  return SENDING_SYSTEMS.find((s) => matchesDomain(host, s.dkimTargets ?? [])) ?? null;
}

// DKIM selectors to test because of what SPF says the domain sends with.
export function selectorsForSenders(senders) {
  return [...new Set(senders.flatMap((s) => s.system?.selectors ?? []))];
}
