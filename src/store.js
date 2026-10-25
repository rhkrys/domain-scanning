// Where scans are saved so report links work and reports can be re-sent.
// This in-memory store is used for local dev and tests.

import crypto from 'node:crypto';

export const SCAN_ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

export function newScanId() {
  return crypto.randomUUID();
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
