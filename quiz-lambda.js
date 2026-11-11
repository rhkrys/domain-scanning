// AWS Lambda entry point for the quiz API, separate from the scanner's
// lambda.js. CloudFront sends /api/quiz/* here; everything else under /api/*
// still goes to the scanner.

import serverlessHttp from 'serverless-http';
import { createQuizApp } from './src/quiz/app.js';

export const handler = serverlessHttp(createQuizApp());
