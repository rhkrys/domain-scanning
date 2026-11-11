// The WISP readiness quiz for tax preparers, in the shape every quiz uses:
//   slug      the name in the URL: /api/quiz/<slug>/report
//   validate  checks the request body, returns { value } or { error, field }
//   score     turns valid answers into the result object
//   render    turns the result into the email: { subject, text, html }
//   summary   one line for the copy sent to Tech in Peace
//   page      where the quiz lives on the site (used in tests and docs)

import { validateQuizInput, scoreQuiz } from './scoring.js';
import { renderWispEmail } from './email.js';

export default {
  slug: 'wisp',
  title: 'WISP readiness quiz',
  page: '/wisp/quiz',
  validate: validateQuizInput,
  score: scoreQuiz,
  render: renderWispEmail,
  summary: (result) => `scored ${result.score} of ${result.max_score}, ${result.band_label}`,
};
