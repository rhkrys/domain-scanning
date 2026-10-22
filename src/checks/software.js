// Website software: does the site run PHP, and is it a patched version?
//
// Two critical PHP flaws (CVE-2026-109618 and CVE-2026-109619) were disclosed
// on 21 Oct 2026 and are being exploited. They affect PHP 5.4 and later and are
// fixed in 8.5.12, 8.4.27, 8.3.36 and 8.2.35.
//
// This check is passive. It reads the same home page response the security
// headers check already fetched and looks for signs of PHP. It never sends
// anything that tries to trigger the flaw.

// Lowest patched release for each supported branch.
export const PHP_FIXED = {
  '8.5': 12,
  '8.4': 27,
  '8.3': 36,
  '8.2': 35,
};
const FIXED_LIST = '8.5.12, 8.4.27, 8.3.36, or 8.2.35';

const COMPROMISE_CHECK =
  'After updating, check for a break-in going back to at least June 2026: unknown files, new admin users, ' +
  'web shells, and odd outbound connections.';

function headerText(value) {
  if (value == null) return '';
  return Array.isArray(value) ? value.join('; ') : String(value);
}

// Pulls "8.3.20" out of headers like "PHP/8.3.20" or
// "Apache/2.4.58 (Ubuntu) PHP/8.1.2-1ubuntu2.19".
export function parsePhpVersion(headers = {}) {
  const sources = [
    ['X-Powered-By', headerText(headers['x-powered-by'])],
    ['Server', headerText(headers.server)],
  ];
  for (const [header, s] of sources) {
    const m = s.match(/PHP\/(\d+)\.(\d+)(?:\.(\d+))?([^\s;,]*)/i);
    if (m) {
      return {
        // Which response header gave the version away, and its exact value.
        header,
        value: s,
        raw: `${m[1]}.${m[2]}${m[3] != null ? `.${m[3]}` : ''}${m[4] ?? ''}`,
        major: Number(m[1]),
        minor: Number(m[2]),
        patch: m[3] != null ? Number(m[3]) : null,
        // Linux distributions often fix old version numbers without changing them.
        distroBuild: /ubuntu|deb|el\d|fc\d|alpine/i.test(m[4] ?? ''),
      };
    }
  }
  return null;
}

// 'patched', 'unpatched', or 'unknown' (version too vague to tell).
export function phpPatchStatus(v) {
  if (!v) return 'unknown';
  const branch = `${v.major}.${v.minor}`;
  if (branch in PHP_FIXED) {
    if (v.patch == null) return 'unknown';
    return v.patch >= PHP_FIXED[branch] ? 'patched' : 'unpatched';
  }
  // Newer than every fixed branch.
  if (v.major > 8 || (v.major === 8 && v.minor > 5)) return 'patched';
  // 8.1 and older have no fix. They need an upgrade.
  return 'unpatched';
}

// Plain-language signs of PHP, from the response headers, cookies, final URL
// and home page HTML. Returns { signs: [...], platform: 'WordPress' | ... }.
export function detectPhp({ headers = {}, html = '', url = '' } = {}) {
  const signs = [];
  let platform = null;
  const h = (typeof html === 'string' ? html : '').toLowerCase();
  const poweredBy = headerText(headers['x-powered-by']);
  const server = headerText(headers.server);
  const cookies = headerText(headers['set-cookie']);
  const generator = headerText(headers['x-generator']);

  if (/php/i.test(poweredBy)) signs.push('your server says it is powered by PHP');
  else if (/php\//i.test(server)) signs.push('your server header names PHP');
  if (/\bPHPSESSID=/i.test(cookies)) signs.push('your site sets a PHP session cookie');
  try {
    if (url && /\.php$/i.test(new URL(url).pathname)) signs.push('your home page address ends in .php');
  } catch {
    // ignore an unreadable URL
  }

  if (
    /\/wp-content\/|\/wp-includes\//.test(h) ||
    /<meta[^>]+name=["']generator["'][^>]+wordpress/.test(h) ||
    headers['x-pingback'] ||
    /api\.w\.org/.test(headerText(headers.link))
  ) {
    platform = 'WordPress';
  } else if (
    /drupal/i.test(generator) ||
    headers['x-drupal-cache'] ||
    headers['x-drupal-dynamic-cache'] ||
    /<meta[^>]+name=["']generator["'][^>]+drupal/.test(h) ||
    /drupal-settings-json|drupal\.settings/.test(h)
  ) {
    platform = 'Drupal';
  } else if (/<meta[^>]+name=["']generator["'][^>]+joomla/.test(h) || /\/media\/jui\/|\/media\/system\/js\//.test(h)) {
    platform = 'Joomla';
  } else if (
    Object.keys(headers).some((k) => k.startsWith('x-magento')) ||
    /mage\/cookies|\/static\/version\d+\/frontend\/|"magento_/.test(h)
  ) {
    platform = 'Magento';
  }
  if (platform) signs.push(`your site looks like it is built on ${platform}, which runs on PHP`);

  return { signs, platform };
}

// "Your X-Powered-By header shows "PHP/8.3.20"." when the version is public.
function headerShows(version) {
  return version ? ` Your ${version.header} header shows "${version.value}".` : '';
}

// How to stop the response headers from naming the PHP version.
function hideVersion(version) {
  const apache = version?.header === 'Server' ? ' On Apache, also set ServerTokens Prod.' : '';
  return `Turn off the ${version?.header ?? 'X-Powered-By'} header that shows your PHP version: ` +
    `set expose_php = Off in php.ini, or ask your host to.${apache}`;
}

function joinList(items) {
  if (items.length <= 1) return items.join('');
  if (items.length === 2) return `${items[0]} and ${items[1]}`;
  return `${items.slice(0, -1).join(', ')}, and ${items[items.length - 1]}`;
}

const BASE = { id: 'php', category: 'Website Software', title: 'PHP (website software)' };

export function evaluateSoftware(page) {
  if (!page) {
    return {
      ...BASE,
      status: 'warn',
      severity: 'low',
      summary: 'Could not check your website software',
      detail: 'No HTTPS response was received from the site root, so we could not look for PHP.',
      recommendation:
        'Ask whoever manages your website if it runs PHP. If it does, update it today to ' +
        `${FIXED_LIST} or newer. ${COMPROMISE_CHECK}`,
    };
  }

  const headers = page.headers ?? {};
  const { signs, platform } = detectPhp({ headers, html: page.html, url: page.url });
  const version = parsePhpVersion(headers);
  if (version && !signs.some((s) => s.includes('PHP'))) signs.unshift('your server header names PHP');
  const behindCloudflare = Boolean(headers['cf-ray']);
  const cloudflareNote = behindCloudflare
    ? ' Your site is behind Cloudflare, which has added firewall rules for these flaws. That helps, but it is not a full fix.'
    : '';
  const evidence = {
    signs,
    platform,
    version: version?.raw ?? null,
    behindCloudflare,
    checkedUrl: page.url ?? null,
  };

  if (signs.length === 0) {
    return {
      ...BASE,
      status: 'pass',
      severity: 'info',
      summary: 'No signs of PHP on your home page',
      detail:
        'We found no signs of PHP in your home page response. This is a check of one public page, not your whole setup. ' +
        'If you use PHP anywhere else, like a members area or a separate shop, make sure it is updated.',
      evidence,
    };
  }

  const seen = `We saw these signs: ${joinList(signs)}.`;
  const status = phpPatchStatus(version);

  if (status === 'patched') {
    // Patched, but the public version still tells attackers what to target.
    return {
      ...BASE,
      status: 'warn',
      severity: 'low',
      summary: `PHP ${version.raw} is patched, but your ${version.header} header shows the version`,
      detail:
        `${seen}${headerShows(version)} PHP ${version.raw} includes the fix for the two critical PHP flaws. ` +
        'Showing the version helps attackers pick their target when the next flaw comes out.',
      recommendation: `${hideVersion(version)} This hides the version so attackers cannot read it.`,
      evidence,
    };
  }

  if (status === 'unpatched') {
    const oldBranch = !(`${version.major}.${version.minor}` in PHP_FIXED);
    const distro = version.distroBuild
      ? ' Your host may have patched this version without changing the number. Ask them to confirm.'
      : '';
    return {
      ...BASE,
      status: 'fail',
      severity: 'critical',
      summary: `PHP ${version.raw} is open to two critical flaws being exploited now`,
      detail:
        `${seen}${headerShows(version)} Your site reports PHP ${version.raw}. ` +
        (oldBranch
          ? 'This version has no fix. It needs an upgrade to a supported version.'
          : 'This version is missing the October 2026 fix.') +
        distro +
        cloudflareNote,
      recommendation:
        `Update PHP today to ${FIXED_LIST} or newer. If you cannot update today, take the site offline until you can. ` +
        `${COMPROMISE_CHECK} ${hideVersion(version)}`,
      evidence,
    };
  }

  // PHP is likely, but the version is hidden or too vague to judge.
  return {
    ...BASE,
    status: 'warn',
    severity: 'high',
    summary: platform
      ? `Your ${platform} site runs on PHP. Confirm it is patched`
      : 'Your site likely runs PHP. Confirm it is patched',
    detail:
      (version
        ? `${seen}${headerShows(version)} That does not include the exact release, so we cannot tell from outside if it is patched.`
        : `${seen} Your site does not show its PHP version, so we cannot tell from outside if it is patched. ` +
          'Hiding the version is good practice.') +
      cloudflareNote,
    recommendation:
      `Ask your host or web person today to confirm your PHP is ${FIXED_LIST} or newer. ` +
      COMPROMISE_CHECK +
      (version ? ` ${hideVersion(version)}` : ''),
    evidence,
  };
}

// loadPage resolves the home page fetched once by the audit (shared with the
// security headers check) or null when nothing answered.
export async function checkSoftware(domain, { loadPage } = {}) {
  if (typeof loadPage !== 'function') {
    const { fetchPage } = await import('./headers.js');
    loadPage = () => fetchPage(domain, 6000);
  }
  return evaluateSoftware(await loadPage());
}
