import fs from 'node:fs';
import path from 'node:path';
import { SentinelConfig, EndpointDefinition } from './types.js';

export const DEFAULT_CONFIG: SentinelConfig = {
  baseUrl: process.env.BASE_URL || 'http://localhost:3000',
  endpoints: [
    { path: '/api/health', method: 'GET', authRequired: false, expectedSuccessStatus: 200 },
    { path: '/api/users', method: 'GET', authRequired: true, requiredRole: 'user' },
    { path: '/api/users', method: 'POST', authRequired: true, requiredRole: 'user', sampleBody: { name: 'Test User', email: 'test@example.com' } },
    { path: '/api/admin/metrics', method: 'GET', authRequired: true, requiredRole: 'admin' },
  ],
  auth: {
    userToken: process.env.SENTINEL_USER_TOKEN || 'user-test-token',
    adminToken: process.env.SENTINEL_ADMIN_TOKEN || 'admin-test-token',
    authHeader: 'Authorization',
    tokenPrefix: 'Bearer ',
  },
  stress: {
    durationSec: 15,
    rampUpStages: [
      { durationSec: 3, targetVUs: 10 },
      { durationSec: 5, targetVUs: 30 },
      { durationSec: 5, targetVUs: 70 },
      { durationSec: 2, targetVUs: 10 },
    ],
    maxVUs: 100,
    requestTimeoutMs: 5000,
    thresholds: {
      p95LatencyMs: 300,
      p99LatencyMs: 600,
      maxErrorRatePercent: 2.0,
    },
  },
  outputDir: './sentinel-reports',
};

export function loadConfig(customConfigPath?: string, cliOverrides?: Partial<SentinelConfig>): SentinelConfig {
  let resolvedConfig: SentinelConfig = { ...DEFAULT_CONFIG };

  const possiblePaths = [
    customConfigPath,
    path.resolve(process.cwd(), 'sentinel.config.json'),
    path.resolve(process.cwd(), '.sentinelrc.json'),
  ].filter(Boolean) as string[];

  for (const p of possiblePaths) {
    if (fs.existsSync(p)) {
      try {
        const raw = fs.readFileSync(p, 'utf-8');
        const parsed = JSON.parse(raw);
        resolvedConfig = {
          ...resolvedConfig,
          ...parsed,
          auth: { ...resolvedConfig.auth, ...(parsed.auth || {}) },
          stress: { ...resolvedConfig.stress, ...(parsed.stress || {}) },
        };
        break;
      } catch (err) {
        console.warn(`[Sentinel-QA] Warning: Could not parse config file at ${p}:`, (err as Error).message);
      }
    }
  }

  // CLI overrides
  if (cliOverrides?.baseUrl) {
    resolvedConfig.baseUrl = cliOverrides.baseUrl;
  }
  if (cliOverrides?.outputDir) {
    resolvedConfig.outputDir = cliOverrides.outputDir;
  }
  if (cliOverrides?.endpoints && cliOverrides.endpoints.length > 0) {
    resolvedConfig.endpoints = cliOverrides.endpoints;
  }

  // Clean trailing slashes on baseUrl
  resolvedConfig.baseUrl = resolvedConfig.baseUrl.replace(/\/+$/, '');

  return resolvedConfig;
}

export function generateSampleConfigJson(): string {
  return JSON.stringify(DEFAULT_CONFIG, null, 2);
}
