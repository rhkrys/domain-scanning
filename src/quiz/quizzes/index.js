// Every quiz the quiz Lambda serves. To add one: make a folder next to wisp/
// with the same index.js shape, then add it here.

import wisp from './wisp/index.js';

export const QUIZZES = Object.fromEntries([wisp].map((q) => [q.slug, q]));
