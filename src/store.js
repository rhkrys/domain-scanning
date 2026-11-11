// Where scans are saved so report links work and reports can be re-sent
// without scanning again. DynamoDB in production (SCANS_TABLE), memory in
// local dev and tests.
//
// A record holds only: scan_id, domain, checked_at, result_json, source,
// email (if given), newsletter_opt_in, consent_at (if opted in), the rendered
// email (subject, text, html), and expires_at for automatic deletion.

import crypto from 'node:crypto';

export const SCAN_ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

// Matches the privacy policy: 12 months when an email was given, 90 days if not.
const DAY_S = 24 * 60 * 60;
export const RETENTION_DAYS = { withEmail: 365, anonymous: 90 };

export function newScanId() {
  return crypto.randomUUID();
}

export function buildScanRecord({ scanId, report, source, email = null, newsletterOptIn = false, consentAt = null, rendered }) {
  const optIn = newsletterOptIn === true && Boolean(email);
  const days = email ? RETENTION_DAYS.withEmail : RETENTION_DAYS.anonymous;
  const checkedAt = report.scannedAt;
  const record = {
    scan_id: scanId,
    domain: report.domain,
    checked_at: checkedAt,
    result_json: JSON.stringify(report),
    source,
    newsletter_opt_in: optIn,
    email_subject: rendered.subject,
    email_text: rendered.text,
    email_html: rendered.html,
    expires_at: Math.floor(new Date(checkedAt).getTime() / 1000) + days * DAY_S,
  };
  if (email) record.email = email;
  if (optIn) record.consent_at = consentAt ?? new Date().toISOString();
  return record;
}

export function createMemoryStore() {
  const items = new Map();
  return {
    async save(record) {
      items.set(record.scan_id, structuredClone(record));
    },
    async get(scanId) {
      const item = items.get(scanId);
      return item ? structuredClone(item) : null;
    },
  };
}

// DynamoDB attribute types for the fields above.
function toItem(record) {
  const item = {};
  for (const [k, v] of Object.entries(record)) {
    if (typeof v === 'boolean') item[k] = { BOOL: v };
    else if (typeof v === 'number') item[k] = { N: String(v) };
    else item[k] = { S: String(v) };
  }
  return item;
}

function fromItem(item) {
  const out = {};
  for (const [k, v] of Object.entries(item)) {
    if ('BOOL' in v) out[k] = v.BOOL;
    else if ('N' in v) out[k] = Number(v.N);
    else out[k] = v.S;
  }
  return out;
}

export function createDynamoStore({ table, client }) {
  return {
    async save(record) {
      const { PutItemCommand } = await import('@aws-sdk/client-dynamodb');
      await client.send(new PutItemCommand({ TableName: table, Item: toItem(record) }));
    },
    async get(scanId) {
      const { GetItemCommand } = await import('@aws-sdk/client-dynamodb');
      const out = await client.send(new GetItemCommand({ TableName: table, Key: { scan_id: { S: scanId } } }));
      return out.Item ? fromItem(out.Item) : null;
    },
  };
}

export async function createStore(config) {
  if (!config.scansTable) return createMemoryStore();
  const { DynamoDBClient } = await import('@aws-sdk/client-dynamodb');
  return createDynamoStore({ table: config.scansTable, client: new DynamoDBClient({}) });
}
