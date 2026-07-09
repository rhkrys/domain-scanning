// AWS Lambda entry point for the scanner's API.
//
// In the S3 + CloudFront deployment the static page is served from S3 and only
// /api/* is routed to this Lambda (via a Function URL origin). We wrap the same
// Express app the local server uses, so there is a single source of truth for
// the audit and email logic.

import serverlessHttp from 'serverless-http';
import { createApp } from './server.js';

// Rate-limit state is per warm container here (best-effort in Lambda). CloudFront
// forwards the viewer IP in X-Forwarded-For, which the app already reads.
export const handler = serverlessHttp(createApp());
