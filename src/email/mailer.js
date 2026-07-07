// Sends the report email. When SMTP credentials are configured we send for
// real; otherwise we fall back to writing an .html preview to disk so the app
// is fully usable in development without any mail account.

import nodemailer from 'nodemailer';
import fs from 'node:fs/promises';
import path from 'node:path';
import { renderEmail, LOGO_CID } from './render.js';

const PREVIEW_DIR = path.resolve('previews');
const LOGO_PATH = path.resolve('public/logo-gold.png');

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

let transport;
function getTransport() {
  if (!transport) {
    transport = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: Number(process.env.SMTP_PORT ?? 587),
      secure: process.env.SMTP_SECURE === 'true',
      auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
    });
  }
  return transport;
}

export async function sendReport(to, report) {
  const email = renderEmail(report);
  const from = process.env.MAIL_FROM ?? 'Cyber Protection <scanner@localhost>';
  const logo = await getLogo();

  if (smtpConfigured()) {
    const info = await getTransport().sendMail({
      from,
      to,
      subject: email.subject,
      text: email.text,
      html: email.html,
      // Embed the logo inline so it renders without external image hosting.
      attachments: logo
        ? [{ filename: 'logo-gold.png', content: logo, cid: LOGO_CID }]
        : [],
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
