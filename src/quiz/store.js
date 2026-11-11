// Where quiz submissions are saved: the quiz Lambda's own DynamoDB table
// (QUIZ_TABLE), memory in local dev and tests.
//
// A record holds only: submission_id, quiz, taken_at, result_json (the
// answers and the scored result), email, newsletter_opt_in, consent_at (if
// opted in), the rendered email, and expires_at. An email is always given, so
// records are kept 12 months, as the privacy policy says for scans with one.

const DAY_S = 24 * 60 * 60;
export const RETENTION_DAYS = 365;

export function buildSubmissionRecord({ id, quiz, result, takenAt, email, newsletterOptIn = false, rendered }) {
  const optIn = newsletterOptIn === true;
  const record = {
    submission_id: id,
    quiz,
    taken_at: takenAt,
    result_json: JSON.stringify(result),
    email,
    newsletter_opt_in: optIn,
    email_subject: rendered.subject,
    email_text: rendered.text,
    email_html: rendered.html,
    expires_at: Math.floor(new Date(takenAt).getTime() / 1000) + RETENTION_DAYS * DAY_S,
  };
  if (optIn) record.consent_at = takenAt;
  return record;
}

export function createMemoryQuizStore() {
  const items = new Map();
  return {
    items,
    async save(record) {
      items.set(record.submission_id, structuredClone(record));
    },
  };
}

function toItem(record) {
  const item = {};
  for (const [k, v] of Object.entries(record)) {
    if (typeof v === 'boolean') item[k] = { BOOL: v };
    else if (typeof v === 'number') item[k] = { N: String(v) };
    else item[k] = { S: String(v) };
  }
  return item;
}

export function createDynamoQuizStore({ table, client }) {
  return {
    async save(record) {
      const { PutItemCommand } = await import('@aws-sdk/client-dynamodb');
      await client.send(new PutItemCommand({ TableName: table, Item: toItem(record) }));
    },
  };
}

export async function createQuizStore(config) {
  if (!config.quizTable) return createMemoryQuizStore();
  const { DynamoDBClient } = await import('@aws-sdk/client-dynamodb');
  return createDynamoQuizStore({ table: config.quizTable, client: new DynamoDBClient({}) });
}
