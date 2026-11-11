// Settings for the quiz Lambda, read from environment variables.

export function loadQuizConfig(env = process.env) {
  return {
    // Browser origins allowed to call the quiz API from another site, comma
    // separated. The site's own pages are same-origin and need nothing here.
    allowedOrigins: String(env.ALLOWED_ORIGINS ?? '')
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean),
    // DynamoDB tables. Without them the app keeps data in memory (local dev, tests).
    quizTable: env.QUIZ_TABLE || null,
    rateTable: env.RATE_TABLE || null,
    // Secret mixed into the IP hash so stored rate-limit keys cannot be reversed.
    rateSalt: env.RATE_SALT || null,
    reportsPerHour: Number(env.QUIZ_REPORTS_PER_HOUR ?? 5),
    // Optional address that gets a copy of every quiz report.
    notifyTo: env.QUIZ_NOTIFY_TO || null,
  };
}
