export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';

export interface EndpointDefinition {
  path: string;
  method: HttpMethod;
  description?: string;
  authRequired?: boolean;
  requiredRole?: 'user' | 'admin' | string;
  sampleBody?: Record<string, unknown>;
  sampleHeaders?: Record<string, string>;
  expectedSuccessStatus?: number;
}

export interface SentinelConfig {
  baseUrl: string;
  endpoints: EndpointDefinition[];
  auth?: {
    userToken?: string;
    adminToken?: string;
    authHeader?: string; // Default: 'Authorization'
    tokenPrefix?: string; // Default: 'Bearer '
  };
  stress?: {
    durationSec?: number; // total duration
    rampUpStages?: Array<{ durationSec: number; targetVUs: number }>;
    maxVUs?: number;
    requestTimeoutMs?: number;
    thresholds?: {
      p95LatencyMs?: number;
      p99LatencyMs?: number;
      maxErrorRatePercent?: number;
    };
  };
  outputDir?: string;
}

export type AuditSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export interface AuditCheckResult {
  id: string;
  category: 'SECURITY_HEADERS' | 'PAYLOAD_VALIDATION' | 'RBAC_AUTH' | 'LEAK_PREVENTION';
  endpoint: string;
  method: HttpMethod;
  severity: AuditSeverity;
  title: string;
  description: string;
  passed: boolean;
  httpStatus?: number;
  expectedStatus?: string;
  evidence?: string;
  reproduceCurl?: string;
  remediationAdvice: string;
}

export interface LatencyStats {
  min: number;
  max: number;
  mean: number;
  p50: number;
  p90: number;
  p95: number;
  p99: number;
}

export interface StressStageResult {
  vus: number;
  durationSec: number;
  totalRequests: number;
  successfulRequests: number;
  failedRequests: number;
  rateLimitedRequests: number;
  rps: number;
  latencies: LatencyStats;
}

export interface StressTestSummary {
  endpoint: string;
  totalRequests: number;
  overallRps: number;
  overallLatencies: LatencyStats;
  stages: StressStageResult[];
  errorRatePercent: number;
  rateLimitEnforced: boolean;
  saturationKneeVUs?: number;
}

export interface DiagnosticItem {
  id: string;
  category: 'SECURITY' | 'PERFORMANCE_BOTTLENECK' | 'RESILIENCE';
  severity: AuditSeverity;
  title: string;
  impact: string;
  rootCause: string;
  remediationCode: string;
}

export interface FullAuditReport {
  timestamp: string;
  baseUrl: string;
  securityScore: number; // 0 to 100
  auditResults: AuditCheckResult[];
  stressResults?: StressTestSummary[];
  diagnostics: DiagnosticItem[];
  remediationCount: number;
}
