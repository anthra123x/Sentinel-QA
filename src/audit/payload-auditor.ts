import { AuditCheckResult, SentinelConfig, EndpointDefinition } from '../types.js';
import { generateCurlCommand } from './curl-generator.js';
import { detectInformationLeak } from './leak-auditor.js';

export async function auditPayloads(
  config: SentinelConfig,
  endpoint: EndpointDefinition
): Promise<AuditCheckResult[]> {
  const results: AuditCheckResult[] = [];
  const fullUrl = `${config.baseUrl}${endpoint.path}`;

  // Only test payload validation on POST, PUT, PATCH methods (or GET with query params)
  const isBodyMethod = ['POST', 'PUT', 'PATCH'].includes(endpoint.method);

  const authHeaders: Record<string, string> = {};
  if (endpoint.authRequired && config.auth?.userToken) {
    const headerName = config.auth.authHeader || 'Authorization';
    const prefix = config.auth.tokenPrefix || 'Bearer ';
    authHeaders[headerName] = `${prefix}${config.auth.userToken}`;
  }

  if (isBodyMethod) {
    // 1. Malformed JSON Test
    try {
      const malformedJson = '{"title": "test", "corrupted": ';
      const resp = await fetch(fullUrl, {
        method: endpoint.method,
        headers: {
          'Content-Type': 'application/json',
          ...authHeaders,
        },
        body: malformedJson,
      });

      const bodyText = await resp.text();
      const leak = detectInformationLeak(bodyText);

      // Expected: 400 Bad Request or 422 Unprocessable Entity
      const passedStatus = resp.status === 400 || resp.status === 422;
      const passed = passedStatus && !leak.hasLeak;

      results.push({
        id: `PLD-MALFORMED-${endpoint.path}`,
        category: 'PAYLOAD_VALIDATION',
        endpoint: endpoint.path,
        method: endpoint.method,
        severity: 'HIGH',
        title: 'Malformed JSON Handling',
        description: 'Verifies defensive rejection (400/422) without internal 500 crash or stack trace exposure.',
        passed,
        httpStatus: resp.status,
        expectedStatus: 'HTTP 400 or 422 (No stack traces)',
        evidence: `Received HTTP ${resp.status}.${leak.hasLeak ? ` LEAK DETECTED: ${leak.snippet}` : ''}`,
        reproduceCurl: generateCurlCommand({
          url: fullUrl,
          method: endpoint.method,
          headers: { 'Content-Type': 'application/json', ...authHeaders },
          rawBody: malformedJson,
        }),
        remediationAdvice: 'Add defensive JSON parsing middleware with a custom error handler returning HTTP 400 JSON response.',
      });
    } catch (err) {
      results.push({
        id: `PLD-MALFORMED-ERR-${endpoint.path}`,
        category: 'PAYLOAD_VALIDATION',
        endpoint: endpoint.path,
        method: endpoint.method,
        severity: 'HIGH',
        title: 'Malformed JSON Request Failure',
        description: 'Server failed to handle malformed JSON stream.',
        passed: false,
        evidence: `Request failed: ${(err as Error).message}`,
        remediationAdvice: 'Ensure server catches JSON parsing exceptions gracefully.',
      });
    }

    // 2. Oversized Payload Test (Body Bomb / DoS protection)
    try {
      const largePayload = JSON.stringify({
        data: 'A'.repeat(1024 * 600), // ~600KB payload
      });

      const resp = await fetch(fullUrl, {
        method: endpoint.method,
        headers: {
          'Content-Type': 'application/json',
          ...authHeaders,
        },
        body: largePayload,
      });

      const bodyText = await resp.text();
      const leak = detectInformationLeak(bodyText);

      // Defensively protected servers should return 413 Payload Too Large or 400
      const isProtected = resp.status === 413 || resp.status === 400 || resp.status === 422;
      const passed = isProtected && !leak.hasLeak;

      results.push({
        id: `PLD-OVERSIZED-${endpoint.path}`,
        category: 'PAYLOAD_VALIDATION',
        endpoint: endpoint.path,
        method: endpoint.method,
        severity: 'HIGH',
        title: 'Oversized Payload Protection (Limit Enforcement)',
        description: 'Verifies limits on request body sizes to prevent memory exhaustion and buffer overflows.',
        passed,
        httpStatus: resp.status,
        expectedStatus: 'HTTP 413 (Payload Too Large) or 400',
        evidence: `Received HTTP ${resp.status}.${leak.hasLeak ? ` LEAK: ${leak.snippet}` : ''}`,
        reproduceCurl: generateCurlCommand({
          url: fullUrl,
          method: endpoint.method,
          headers: { 'Content-Type': 'application/json', ...authHeaders },
          rawBody: '{"data":"[600KB padding]"}',
        }),
        remediationAdvice: 'Configure explicit payload limits (e.g., express.json({ limit: "100kb" })).',
      });
    } catch (err) {
      // If server dropped connection or timed out due to size, note it
      results.push({
        id: `PLD-OVERSIZED-ERR-${endpoint.path}`,
        category: 'PAYLOAD_VALIDATION',
        endpoint: endpoint.path,
        method: endpoint.method,
        severity: 'MEDIUM',
        title: 'Oversized Payload Network Handling',
        description: 'Verifies connection behavior under heavy body payload.',
        passed: false,
        evidence: `Connection error on large payload: ${(err as Error).message}`,
        remediationAdvice: 'Enforce body-size limits at the reverse proxy or application layer.',
      });
    }

    // 3. SQLi / Injection Probe in Body
    try {
      const injectionPayload = JSON.stringify({
        ...(endpoint.sampleBody || {}),
        search: "' OR '1'='1' --",
        filter: "'; DROP TABLE test; --",
        username: "admin' --",
      });

      const resp = await fetch(fullUrl, {
        method: endpoint.method,
        headers: {
          'Content-Type': 'application/json',
          ...authHeaders,
        },
        body: injectionPayload,
      });

      const bodyText = await resp.text();
      const leak = detectInformationLeak(bodyText);

      // Server should not throw a 500 with SQL errors or expose database details
      const safeHandling = resp.status !== 500 && !leak.hasLeak;

      results.push({
        id: `PLD-SQLI-${endpoint.path}`,
        category: 'PAYLOAD_VALIDATION',
        endpoint: endpoint.path,
        method: endpoint.method,
        severity: 'CRITICAL',
        title: 'SQL / Injection Probe Defense',
        description: 'Verifies that hostile SQL probe characters are safely parameterized or validated without DB errors.',
        passed: safeHandling,
        httpStatus: resp.status,
        expectedStatus: 'Handled safely (No SQL syntax/DB driver leaks)',
        evidence: leak.hasLeak ? `CRITICAL LEAK: ${leak.snippet}` : `Status ${resp.status}. No DB error leaked.`,
        reproduceCurl: generateCurlCommand({
          url: fullUrl,
          method: endpoint.method,
          headers: { 'Content-Type': 'application/json', ...authHeaders },
          rawBody: injectionPayload,
        }),
        remediationAdvice: 'Use parameterized queries / ORM prepared statements and sanitize / validate input with schema validators (Zod, Joi, class-validator).',
      });
    } catch (err) {
      // Ignored
    }

    // 4. Schema Boundary / Type Mismatch Test
    try {
      const typeMismatchPayload = JSON.stringify({
        ...(endpoint.sampleBody || {}),
        id: { $ne: null }, // NoSQL query injection pattern or object where primitive expected
        email: 9999999,    // Number where email expected
        items: 'not-an-array', // String where array expected
      });

      const resp = await fetch(fullUrl, {
        method: endpoint.method,
        headers: {
          'Content-Type': 'application/json',
          ...authHeaders,
        },
        body: typeMismatchPayload,
      });

      const bodyText = await resp.text();
      const leak = detectInformationLeak(bodyText);

      // Should return 400 or 422 with structured validation error, never an unhandled 500 crash
      const passed = (resp.status === 400 || resp.status === 422) && !leak.hasLeak;

      results.push({
        id: `PLD-TYPE-VALIDATION-${endpoint.path}`,
        category: 'PAYLOAD_VALIDATION',
        endpoint: endpoint.path,
        method: endpoint.method,
        severity: 'MEDIUM',
        title: 'Input Type & Schema Boundary Validation',
        description: 'Verifies schema enforcement when unexpected types or NoSQL operators are injected.',
        passed,
        httpStatus: resp.status,
        expectedStatus: 'HTTP 400 or 422 validation response',
        evidence: `Received HTTP ${resp.status}.${leak.hasLeak ? ` LEAK: ${leak.snippet}` : ''}`,
        reproduceCurl: generateCurlCommand({
          url: fullUrl,
          method: endpoint.method,
          headers: { 'Content-Type': 'application/json', ...authHeaders },
          rawBody: typeMismatchPayload,
        }),
        remediationAdvice: 'Enforce strict DTO validation schemas (e.g. Zod/Joi) and reject unvalidated properties.',
      });
    } catch (err) {
      // Ignored
    }
  }

  return results;
}
