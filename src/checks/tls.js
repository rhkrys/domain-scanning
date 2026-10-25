// TLS certificate check. Connects on 443 and inspects the presented
// certificate: validity, expiry window and negotiated protocol version.

import tls from 'node:tls';

// trust: what the TLS handshake said about the certificate. authorized is
// false when no trusted authority vouches for it (self-signed, expired chain);
// hostnameMatch is false when it was issued for a different name.
export function evaluateCertificate(cert, protocol, now = new Date(), trust = {}) {
  const { authorized = true, authError = null, hostnameMatch = true } = trust;
  if (!cert || !cert.valid_to) {
    return {
      id: 'tls',
      category: 'Transport Security',
      title: 'TLS certificate',
      status: 'fail',
      severity: 'high',
      summary: 'No TLS certificate presented',
      detail: 'The server did not present a certificate on port 443.',
      recommendation: 'Install a valid TLS certificate so traffic to your site is encrypted.',
      evidence: { valid: false, expiresAt: null, daysLeft: null, hostnameMatch: false, authorized: false },
    };
  }

  const validTo = new Date(cert.valid_to);
  const validFrom = new Date(cert.valid_from);
  const daysLeft = Math.floor((validTo - now) / (1000 * 60 * 60 * 24));
  const legacyProtocol = protocol && /TLSv1(\.0|\.1)?$/.test(protocol);

  let status = 'pass';
  let severity = 'info';
  let summary = `Valid certificate (${daysLeft} days left)`;
  let recommendation;

  if (now < validFrom) {
    status = 'fail';
    severity = 'high';
    summary = 'Certificate is not yet valid';
    recommendation = 'The certificate start date is in the future; check the issuance and server clock.';
  } else if (daysLeft < 0) {
    status = 'fail';
    severity = 'critical';
    summary = 'Certificate has expired';
    recommendation = 'Renew the TLS certificate immediately; browsers are rejecting connections to your site.';
  } else if (!hostnameMatch) {
    status = 'fail';
    severity = 'high';
    summary = 'Certificate does not match this domain';
    recommendation = 'Install a certificate issued for this exact domain name so browsers trust it.';
  } else if (!authorized) {
    status = 'fail';
    severity = 'high';
    summary = 'Certificate is not trusted by browsers';
    recommendation = 'Replace it with a certificate from a trusted authority, such as a free Let\u2019s Encrypt certificate.';
  } else if (daysLeft < 14) {
    status = 'warn';
    severity = 'high';
    summary = `Certificate expires in ${daysLeft} days`;
    recommendation = 'Renew the TLS certificate now and enable auto-renewal to avoid an outage.';
  } else if (legacyProtocol) {
    status = 'warn';
    severity = 'medium';
    summary = `Negotiated legacy protocol (${protocol})`;
    recommendation = 'Disable TLS 1.0/1.1 and require TLS 1.2 or higher.';
  }

  return {
    id: 'tls',
    category: 'Transport Security',
    title: 'TLS certificate',
    status,
    severity,
    summary,
    detail: `Issued to ${cert.subject?.CN ?? 'unknown'} by ${
      cert.issuer?.O ?? cert.issuer?.CN ?? 'unknown'
    }; valid ${cert.valid_from} → ${cert.valid_to}; protocol ${protocol ?? 'unknown'}.`,
    recommendation,
    evidence: {
      daysLeft,
      protocol,
      expiresAt: Number.isNaN(validTo.getTime()) ? null : validTo.toISOString(),
      hostnameMatch,
      authorized,
      authError,
      // A working certificate: trusted, issued for this name, and in date.
      valid: authorized && hostnameMatch && now >= validFrom && daysLeft >= 0,
    },
  };
}

export async function checkTls(domain, { timeoutMs = 6000, connect = tls.connect } = {}) {
  return new Promise((resolve) => {
    const socket = connect(
      { host: domain, port: 443, servername: domain, timeout: timeoutMs, rejectUnauthorized: false },
      () => {
        const cert = socket.getPeerCertificate();
        const protocol = socket.getProtocol();
        const trust = {
          authorized: Boolean(socket.authorized),
          authError: socket.authorizationError ? String(socket.authorizationError) : null,
          hostnameMatch: cert?.subject ? tls.checkServerIdentity(domain, cert) === undefined : false,
        };
        socket.end();
        resolve(evaluateCertificate(cert, protocol, new Date(), trust));
      },
    );
    socket.on('timeout', () => {
      socket.destroy();
      resolve(unreachable('Connection timed out'));
    });
    socket.on('error', (err) => {
      resolve(unreachable(err.message));
    });
  });
}

function unreachable(reason) {
  return {
    id: 'tls',
    category: 'Transport Security',
    title: 'TLS certificate',
    status: 'warn',
    severity: 'medium',
    summary: 'Could not establish HTTPS connection',
    detail: `Unable to complete a TLS handshake on port 443 (${reason}).`,
    recommendation: 'Confirm the site serves HTTPS on port 443 with a valid certificate.',
    evidence: { valid: false, expiresAt: null, daysLeft: null, hostnameMatch: false, authorized: false },
  };
}
