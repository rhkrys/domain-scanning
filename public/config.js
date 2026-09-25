// Frontend feature flags. The full app (local server / Lambda backend) leaves
// apiEnabled true. The static-only S3+CloudFront deployment overrides this file
// with apiEnabled:false, so the page explains the scanner is coming soon instead
// of calling a /api/scan backend that isn't wired up on that host yet.
window.APP_CONFIG = { apiEnabled: true };
