// Sends the report email. Three transports, chosen by environment:
//   EMAIL_TRANSPORT=ses  -> Amazon SES via the SDK (uses the Lambda role; no
//                           stored secrets). This is the production path.
//   SMTP_* configured    -> any SMTP server via nodemailer.
//   neither              -> write an .html preview to disk (local dev).
//
// In every case we compose the MIME with nodemailer so the inline brand logo
// (CID attachment) renders identically across transports.

import nodemailer from 'nodemailer';
import fs from 'node:fs/promises';
import path from 'node:path';
import { renderEmail, LOGO_CID } from './render.js';

// Lambda's filesystem is read-only except /tmp, so allow the preview dir to be
// overridden. (In production EMAIL_TRANSPORT=ses, so this path isn't hit.)
const PREVIEW_DIR = process.env.PREVIEW_DIR || path.resolve('previews');
const LOGO_PATH = process.env.LOGO_PATH || path.resolve('public/logo-gold.png');

// Read the brand mark once and reuse it for every send.
let logoBuffer;
async function getLogo() {
  if (logoBuffer === undefined) {
    logoBuffer = await fs.readFile(LOGO_PATH).catch(() => null);
  }
  return logoBuffer;
}

function smtpConfigured() {
  return Boolean(process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS);
}

function sesConfigured() {
  return process.env.EMAIL_TRANSPORT === 'ses';
}

// Compose the full MIME message (headers + html + text + inline logo) without
// sending, so both the SES and SMTP paths share identical rendering.
async function composeMime({ from, to, subject, text, html, logo }) {
  const composer = nodemailer.createTransport({ streamTransport: true, buffer: true, newline: 'unix' });
  const info = await composer.sendMail({
    from, to, subject, text, html,
    attachments: logo ? [{ filename: 'logo-gold.png', content: logo, cid: LOGO_CID }] : [],
  });
  return info.message; // Buffer of raw RFC 822 MIME
}

let sesClient;
async function sendViaSes({ from, to, raw }) {
  const { SESv2Client, SendEmailCommand } = await import('@aws-sdk/client-sesv2');
  if (!sesClient) sesClient = new SESv2Client({});
  // Envelope sender: the bare address inside MAIL_FROM ("Name <addr>" -> addr).
  const fromAddress = /<([^>]+)>/.exec(from)?.[1] ?? from;
  const out = await sesClient.send(new SendEmailCommand({
    FromEmailAddress: fromAddress,
    Destination: { ToAddresses: [to] },
    Content: { Raw: { Data: raw } },
  }));
  return out.MessageId;
}

let smtpTransport;
function getSmtpTransport() {
  if (!smtpTransport) {
    smtpTransport = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: Number(process.env.SMTP_PORT ?? 587),
      secure: process.env.SMTP_SECURE === 'true',
      auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
    });
  }
  return smtpTransport;
}

export async function sendReport(to, report) {
  const email = renderEmail(report);
  const from = process.env.MAIL_FROM ?? 'Cyber Protection <scanner@localhost>';
  const logo = await getLogo();

  if (sesConfigured()) {
    const raw = await composeMime({ from, to, subject: email.subject, text: email.text, html: email.html, logo });
    const messageId = await sendViaSes({ from, to, raw });
    return { delivered: true, mode: 'ses', messageId };
  }

  if (smtpConfigured()) {
    const info = await getSmtpTransport().sendMail({
      from, to, subject: email.subject, text: email.text, html: email.html,
      attachments: logo ? [{ filename: 'logo-gold.png', content: logo, cid: LOGO_CID }] : [],
    });
    return { delivered: true, mode: 'smtp', messageId: info.messageId };
  }

  // Dev fallback: persist a preview the developer can open in a browser. The
  // cid: reference won't resolve in a browser, so inline the logo as a data URI.
  await fs.mkdir(PREVIEW_DIR, { recursive: true });
  let html = email.html;
  if (logo) {
    const dataUri = `data:image/png;base64,${logo.toString('base64')}`;
    html = html.replaceAll(`cid:${LOGO_CID}`, dataUri);
  }
  const file = path.join(PREVIEW_DIR, `${report.domain}-${Date.now()}.html`);
  await fs.writeFile(file, html, 'utf8');
  return { delivered: false, mode: 'preview', previewPath: file };
}
