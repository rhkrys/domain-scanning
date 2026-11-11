// The quiz Lambda's web app. One route serves every quiz in quizzes/index.js:
//   POST /api/quiz/:slug/report   scores the answers, emails the report to
//                                 the person who took the quiz, sends an
//                                 optional copy to config.notifyTo, and saves
//                                 the submission. Rate limited per IP per hour.
//   GET  /api/quiz/healthz
//
// The server always scores the answers itself; a score sent by the browser
// is ignored. Dependencies are injectable so tests never touch AWS.

import express from 'express';
import { QUIZZES } from './quizzes/index.js';
import { loadQuizConfig } from './config.js';
import { createQuizStore, buildSubmissionRecord } from './store.js';
import { createMemoryLimiter, createDynamoLimiter } from '../ratelimit.js';
import { emailInputProblem } from '../email/address.js';
import { sendRendered } from '../email/mailer.js';
import crypto from 'node:crypto';

async function createQuizLimiter(config) {
  if (config.rateTable && config.rateSalt) {
    const { DynamoDBClient } = await import('@aws-sdk/client-dynamodb');
    return createDynamoLimiter({ table: config.rateTable, salt: config.rateSalt, max: config.reportsPerHour, client: new DynamoDBClient({}) });
  }
  return createMemoryLimiter({ max: config.reportsPerHour });
}

function clientIp(req) {
  return req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip;
}

export function createQuizApp({
  quizzes = QUIZZES,
  sendEmail = sendRendered,
  config = loadQuizConfig(),
  limiter,
  store,
  now = () => new Date(),
} = {}) {
  const limiterReady = limiter ? Promise.resolve(limiter) : createQuizLimiter(config);
  const storeReady = store ? Promise.resolve(store) : createQuizStore(config);
  const app = express();

  app.use('/api/quiz', (req, res, next) => {
    const origin = req.headers.origin;
    if (origin && config.allowedOrigins.includes(origin)) {
      res.set('Access-Control-Allow-Origin', origin);
      res.set('Vary', 'Origin');
      res.set('Access-Control-Allow-Methods', 'POST, OPTIONS');
      res.set('Access-Control-Allow-Headers', 'Content-Type');
      res.set('Access-Control-Max-Age', '600');
    }
    if (req.method === 'OPTIONS') return res.sendStatus(204);
    next();
  });
  app.use(express.json({ limit: '8kb' }));

  app.get('/api/quiz/healthz', (_req, res) => res.json({ ok: true, quizzes: Object.keys(quizzes) }));

  app.post('/api/quiz/:slug/report', async (req, res) => {
    const quiz = Object.hasOwn(quizzes, req.params.slug) ? quizzes[req.params.slug] : null;
    if (!quiz) return res.status(404).json({ error: 'That quiz was not found.' });

    try {
      const l = await limiterReady;
      if ((await l.hit(clientIp(req))).limited) {
        return res.status(429).json({ error: 'Too many reports from this address. Please try again in an hour.' });
      }
    } catch (err) {
      // Never block a report because the counter is unavailable.
      console.error('Rate limiter failed:', err.message);
    }

    const body = req.body ?? {};
    const email = typeof body.email === 'string' ? body.email.trim() : '';
    const emailProblem = email ? emailInputProblem(email) : 'Enter your email address so we can send your report.';
    if (emailProblem) return res.status(400).json({ error: emailProblem, field: 'email' });
    const input = quiz.validate(body);
    if (input.error) return res.status(400).json({ error: input.error, field: input.field });

    const result = quiz.score(input.value);
    const takenAt = now().toISOString();
    const rendered = quiz.render(result, takenAt);

    let emailed = false;
    try {
      emailed = Boolean((await sendEmail(email, rendered, `quiz-${quiz.slug}`))?.delivered);
    } catch (err) {
      console.error(`Quiz ${quiz.slug} report email failed:`, err.message);
    }
    if (config.notifyTo) {
      const copy = { ...rendered, subject: `${quiz.title}: ${email} ${quiz.summary(result)}` };
      await sendEmail(config.notifyTo, copy, `quiz-${quiz.slug}-copy`).catch((err) => console.error('Quiz copy email failed:', err.message));
    }

    try {
      const record = buildSubmissionRecord({ id: crypto.randomUUID(), quiz: quiz.slug, result, takenAt, email, newsletterOptIn: body.newsletter_opt_in === true, rendered });
      await (await storeReady).save(record);
    } catch (err) {
      // A storage problem must not cost the visitor their report.
      console.error('Saving quiz submission failed:', err.message);
    }

    res.json({ ...result, report_emailed: emailed });
  });

  return app;
}
