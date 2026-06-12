// Sends the report email. When SMTP credentials are configured we send for
// real; otherwise we fall back to writing an .html preview to disk so the app
// is fully usable in development without any mail account.

import nodemailer from 'nodemailer';
import fs from 'node:fs/promises';
import path from 'node:path';
import { renderEmail } from './render.js';

const PREVIEW_DIR = path.resolve('previews');

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
  const from = process.env.MAIL_FROM ?? 'Domain Scanner <scanner@localhost>';

  if (smtpConfigured()) {
    const info = await getTransport().sendMail({
      from,
      to,
      subject: email.subject,
      text: email.text,
      html: email.html,
    });
    return { delivered: true, mode: 'smtp', messageId: info.messageId };
  }

  // Dev fallback: persist a preview the developer can open in a browser.
  await fs.mkdir(PREVIEW_DIR, { recursive: true });
  const file = path.join(
    PREVIEW_DIR,
    `${report.domain}-${Date.now()}.html`,
  );
  await fs.writeFile(file, email.html, 'utf8');
  return { delivered: false, mode: 'preview', previewPath: file };
}
