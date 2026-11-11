// Settings that change per environment, read from environment variables so
// nothing (allowed origins, table names, salts) is hardcoded in the code.

export function loadConfig(env = process.env) {
  return {
    // Origins allowed to call /api/v1/* from a browser, comma separated,
    // for example "https://chatgpt.com,https://www.techinpeace.com".
    allowedOrigins: String(env.ALLOWED_ORIGINS ?? '')
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean),
    // Where report links point.
    publicBaseUrl: String(env.PUBLIC_BASE_URL ?? 'https://www.techinpeace.com').replace(/\/+$/, ''),
    // DynamoDB tables. Without them the app keeps data in memory (local dev, tests).
    scansTable: env.SCANS_TABLE || null,
    rateTable: env.RATE_TABLE || null,
    // Secret mixed into the IP hash so stored rate-limit keys cannot be reversed.
    rateSalt: env.RATE_SALT || null,
    apiScansPerHour: Number(env.API_SCANS_PER_HOUR ?? 10),
  };
}
