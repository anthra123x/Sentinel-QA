import { AuditCheckResult, SentinelConfig, EndpointDefinition } from '../types.js';
import { generateCurlCommand } from './curl-generator.js';
import { detectInformationLeak } from './leak-auditor.js';

export async function auditRbacAndAuth(
  config: SentinelConfig,
  endpoint: EndpointDefinition
): Promise<AuditCheckResult[]> {
  const results: AuditCheckResult[] = [];
  const fullUrl = `${config.baseUrl}${endpoint.path}`;

  if (!endpoint.authRequired) {
    return results;
  }

  const headerName = config.auth?.authHeader || 'Authorization';
  const prefix = config.auth?.tokenPrefix || 'Bearer ';
  const userToken = config.auth?.userToken;
  const adminToken = config.auth?.adminToken;

  // 1. Unauthenticated Request (Missing token)
  try {
    const resp = await fetch(fullUrl, {
      method: endpoint.method,
      headers: {
        'Content-Type': 'application/json',
      },
      body: ['POST', 'PUT', 'PATCH'].includes(endpoint.method) ? JSON.stringify(endpoint.sampleBody || {}) : undefined,
    });

    const bodyText = await resp.text();
    const leak = detectInformationLeak(bodyText);

    // Defensively, a protected route MUST return 401 Unauthorized
    const isUnauthorized = resp.status === 401;
    const passed = isUnauthorized && !leak.hasLeak;

    results.push({
      id: `AUTH-ANONYMOUS-${endpoint.path}`,
      category: 'RBAC_AUTH',
      endpoint: endpoint.path,
      method: endpoint.method,
      severity: 'CRITICAL',
      title: 'Unauthenticated Access Protection (Missing Auth)',
      description: 'Verifies that calls without authentication credentials strictly yield HTTP 401 Unauthorized.',
      passed,
      httpStatus: resp.status,
      expectedStatus: 'HTTP 401 (Unauthorized)',
      evidence: `Status received: ${resp.status}.${leak.hasLeak ? ` LEAK: ${leak.snippet}` : ''}`,
      reproduceCurl: generateCurlCommand({
        url: fullUrl,
        method: endpoint.method,
      }),
      remediationAdvice: 'Add authentication guard/middleware to reject anonymous requests with HTTP 401.',
    });
  } catch (err) {
    results.push({
      id: `AUTH-ANONYMOUS-ERR-${endpoint.path}`,
      category: 'RBAC_AUTH',
      endpoint: endpoint.path,
      method: endpoint.method,
      severity: 'HIGH',
      title: 'Unauthenticated Request Execution Error',
      description: 'Request execution error when probing unauthenticated access.',
      passed: false,
      evidence: `Error: ${(err as Error).message}`,
      remediationAdvice: 'Verify endpoint connectivity.',
    });
  }

  // 2. Invalid / Corrupted Token
  try {
    const resp = await fetch(fullUrl, {
      method: endpoint.method,
      headers: {
        'Content-Type': 'application/json',
        [headerName]: `${prefix}corrupted.token.payload`,
      },
      body: ['POST', 'PUT', 'PATCH'].includes(endpoint.method) ? JSON.stringify(endpoint.sampleBody || {}) : undefined,
    });

    const bodyText = await resp.text();
    const leak = detectInformationLeak(bodyText);

    const isUnauthorized = resp.status === 401;
    const passed = isUnauthorized && !leak.hasLeak;

    results.push({
      id: `AUTH-INVALID-TOKEN-${endpoint.path}`,
      category: 'RBAC_AUTH',
      endpoint: endpoint.path,
      method: endpoint.method,
      severity: 'HIGH',
      title: 'Corrupted / Tampered Token Handling',
      description: 'Verifies that forged or expired tokens are rejected with HTTP 401 without stack trace exposure.',
      passed,
      httpStatus: resp.status,
      expectedStatus: 'HTTP 401 (Unauthorized)',
      evidence: `Status received: ${resp.status}.${leak.hasLeak ? ` LEAK: ${leak.snippet}` : ''}`,
      reproduceCurl: generateCurlCommand({
        url: fullUrl,
        method: endpoint.method,
        headers: { [headerName]: `${prefix}corrupted.token.payload` },
      }),
      remediationAdvice: 'Catch JWT verification exceptions and return clean HTTP 401 responses.',
    });
  } catch (err) {
    // Ignored
  }

  // 3. Insufficient Role (RBAC) - User token accessing Admin endpoint
  if (endpoint.requiredRole === 'admin') {
    try {
      const resp = await fetch(fullUrl, {
        method: endpoint.method,
        headers: {
          'Content-Type': 'application/json',
          ...(userToken ? { [headerName]: `${prefix}${userToken}` } : {}),
        },
        body: ['POST', 'PUT', 'PATCH'].includes(endpoint.method) ? JSON.stringify(endpoint.sampleBody || {}) : undefined,
      });

      const bodyText = await resp.text();
      const leak = detectInformationLeak(bodyText);

      // A user without admin role MUST receive HTTP 403 Forbidden
      const isForbidden = resp.status === 403;
      const passed = isForbidden && !leak.hasLeak;

      results.push({
        id: `RBAC-PRIVILEGE-${endpoint.path}`,
        category: 'RBAC_AUTH',
        endpoint: endpoint.path,
        method: endpoint.method,
        severity: 'CRITICAL',
        title: 'Role-Based Access Control (RBAC) Enforcement',
        description: 'Verifies that a standard user token cannot access restricted administrative routes (must return 403).',
        passed,
        httpStatus: resp.status,
        expectedStatus: 'HTTP 403 (Forbidden)',
        evidence: `Status received: ${resp.status}.${resp.status === 200 ? ' PRIVILEGE ESCALATION VULNERABILITY!' : ''}`,
        reproduceCurl: generateCurlCommand({
          url: fullUrl,
          method: endpoint.method,
          headers: userToken ? { [headerName]: `${prefix}${userToken}` } : undefined,
        }),
        remediationAdvice: 'Add role verification guard (e.g., requireRole("admin")) and reject non-privileged accounts with HTTP 403.',
      });
    } catch (err) {
      // Ignored
    }
  }

  return results;
}
