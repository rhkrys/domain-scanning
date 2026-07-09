// A scripted resolver for tests: feed it a map of "name|TYPE" -> records.
export class FakeResolver {
  constructor(table = {}) {
    this.table = table;
  }

  async query(name, type) {
    const key = `${name}|${type}`;
    const entry = this.table[key];
    if (!entry) return { status: 0, ad: false, records: [] };
    if (Array.isArray(entry)) {
      return { status: 0, ad: false, records: entry.map((data) => ({ type, data })) };
    }
    return {
      status: entry.status ?? 0,
      ad: entry.ad ?? false,
      records: (entry.records ?? []).map((data) => ({ type, data })),
    };
  }

  async txt(name) {
    return (await this.query(name, 'TXT')).records.map((r) => r.data);
  }
}
