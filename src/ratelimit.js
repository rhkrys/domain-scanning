// Per-IP rate limit for the JSON API: N scans per IP per hour.
//
// The IP itself is never stored. We keep a salted SHA-256 of it plus the hour,
// with a count, and DynamoDB deletes the row on its own after the hour (TTL).
// Without a table (local dev, tests) the same rule runs in memory.

import crypto from 'node:crypto';

const HOUR_MS = 60 * 60 * 1000;

export function hashIp(ip, salt) {
  return crypto.createHash('sha256').update(`${salt}|${ip}`).digest('hex');
}

export function createMemoryLimiter({ max = 10, windowMs = HOUR_MS, now = () => Date.now() } = {}) {
  const hits = new Map();
  return {
    async hit(ip) {
      const t = now();
      const list = (hits.get(ip) ?? []).filter((x) => t - x < windowMs);
      list.push(t);
      hits.set(ip, list);
      return { limited: list.length > max, count: list.length };
    },
  };
}

export function createDynamoLimiter({ table, salt, max = 10, client, now = () => Date.now() }) {
  return {
    async hit(ip) {
      const { UpdateItemCommand } = await import('@aws-sdk/client-dynamodb');
      const t = now();
      const hour = Math.floor(t / HOUR_MS);
      const out = await client.send(
        new UpdateItemCommand({
          TableName: table,
          Key: { key: { S: `${hashIp(ip, salt)}:${hour}` } },
          UpdateExpression: 'ADD #c :one SET expires_at = if_not_exists(expires_at, :exp)',
          ExpressionAttributeNames: { '#c': 'count' },
          ExpressionAttributeValues: {
            ':one': { N: '1' },
            ':exp': { N: String(Math.floor(((hour + 2) * HOUR_MS) / 1000)) },
          },
          ReturnValues: 'UPDATED_NEW',
        }),
      );
      const count = Number(out.Attributes?.count?.N ?? 1);
      return { limited: count > max, count };
    },
  };
}

// Picks DynamoDB when a table and salt are configured, memory otherwise.
export async function createApiLimiter(config) {
  if (config.rateTable && config.rateSalt) {
    const { DynamoDBClient } = await import('@aws-sdk/client-dynamodb');
    return createDynamoLimiter({
      table: config.rateTable,
      salt: config.rateSalt,
      max: config.apiScansPerHour,
      client: new DynamoDBClient({}),
    });
  }
  return createMemoryLimiter({ max: config.apiScansPerHour });
}
