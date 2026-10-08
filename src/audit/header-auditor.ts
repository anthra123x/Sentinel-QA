import { AuditCheckResult, SentinelConfig, EndpointDefinition } from '../types.js';
import { generateCurlCommand } from './curl-generator.js';

export async function auditSecurityHeaders(
  config: SentinelConfig,
  endpoint: EndpointDefinition
): Promise<AuditCheckResult[]> {
  const results: AuditCheckResult[] = [];
  const fullUrl = `${config.baseUrl}${endpoint.path}`;

  try {
    const response = await fetch(fullUrl, {
      method: endpoint.method === 'GET' ? 'GET' : 'HEAD',
      headers: {
        'User-Agent': 'Sentinel-QA-Auditor/1.0',
        Origin: 'https://attacker-origin.example.com',
      },
    });

    const headers = response.headers;

    // 1. Check X-Content-Type-Options
    const nosniff = headers.get('x-content-type-options');
    results.push({
      id: `HDR-NOSNIFF-${endpoint.path}`,
      category: 'SECURITY_HEADERS',
      endpoint: endpoint.path,
      method: endpoint.method,
      severity: 'HIGH',
      title: 'MIME-sniffing Protection (X-Content-Type-Options)',
      description: 'Prevents MIME-type confusion attacks by forcing browsers to honor declared content types.',
      passed: nosniff?.toLowerCase() === 'nosniff',
      httpStatus: response.status,
      expectedStatus: 'Header x-content-type-options: nosniff',
      evidence: nosniff ? `Found: ${nosniff}` : 'Header is missing',
      reproduceCurl: generateCurlCommand({ url: fullUrl, method: 'GET' }),
      remediationAdvice: 'Add response header: "X-Content-Type-Options: nosniff" (e.g. helmet() in Express).',
    });

    // 2. Check X-Frame-Options or CSP frame-ancestors (Clickjacking)
    const frameOptions = headers.get('x-frame-options');
    const csp = headers.get('content-security-policy');
    const hasFrameProtection =
      (frameOptions && ['deny', 'sameorigin'].includes(frameOptions.toLowerCase())) ||
      (csp && csp.includes('frame-ancestors'));

    results.push({
      id: `HDR-FRAME-${endpoint.path}`,
      category: 'SECURITY_HEADERS',
      endpoint: endpoint.path,
      method: endpoint.method,
      severity: 'HIGH',
      title: 'Anti-Clickjacking (X-Frame-Options / CSP frame-ancestors)',
      description: 'Prevents framing of responses inside malicious iframes to protect against UI redressing.',
      passed: !!hasFrameProtection,
      httpStatus: response.status,
      evidence: frameOptions ? `X-Frame-Options: ${frameOptions}` : (csp?.includes('frame-ancestors') ? 'CSP frame-ancestors present' : 'Missing frame protection'),
      reproduceCurl: generateCurlCommand({ url: fullUrl, method: 'GET' }),
      remediationAdvice: 'Set "X-Frame-Options: DENY" or CSP "frame-ancestors \'none\'".',
    });

    // 3. Check X-Powered-By leakage
    const poweredBy = headers.get('x-powered-by');
    results.push({
      id: `HDR-POWERED-BY-${endpoint.path}`,
      category: 'SECURITY_HEADERS',
      endpoint: endpoint.path,
      method: endpoint.method,
      severity: 'LOW',
      title: 'Server Fingerprint Disclosure (X-Powered-By)',
      description: 'Disclosing technology stack (e.g. Express, PHP) helps attackers target specific CVEs.',
      passed: !poweredBy,
      httpStatus: response.status,
      evidence: poweredBy ? `Exposed: ${poweredBy}` : 'Header properly stripped',
      reproduceCurl: generateCurlCommand({ url: fullUrl, method: 'GET' }),
      remediationAdvice: 'Remove header: app.disable("x-powered-by") or helmet.hidePoweredBy().',
    });

    // 4. Check Content-Security-Policy (CSP)
    results.push({
      id: `HDR-CSP-${endpoint.path}`,
      category: 'SECURITY_HEADERS',
      endpoint: endpoint.path,
      method: endpoint.method,
      severity: 'MEDIUM',
      title: 'Content-Security-Policy (CSP)',
      description: 'Restricts sources of executable scripts, stylesheets, and objects.',
      passed: !!csp,
      httpStatus: response.status,
      evidence: csp ? `Present: ${csp.slice(0, 80)}...` : 'CSP header is missing',
      reproduceCurl: generateCurlCommand({ url: fullUrl, method: 'GET' }),
      remediationAdvice: 'Configure Content-Security-Policy header with strict default-src directives.',
    });

    // 5. Check Strict CORS check (Arbitrary Origin reflection)
    const allowOrigin = headers.get('access-control-allow-origin');
    const allowCredentials = headers.get('access-control-allow-credentials');
    const isOverlyPermissiveCors =
      allowOrigin === 'https://attacker-origin.example.com' ||
      (allowOrigin === '*' && allowCredentials === 'true');

    results.push({
      id: `HDR-CORS-${endpoint.path}`,
      category: 'SECURITY_HEADERS',
      endpoint: endpoint.path,
      method: endpoint.method,
      severity: 'HIGH',
      title: 'CORS Configuration & Origin Validation',
      description: 'Verifies that server does not reflect untrusted Origins or allow wildcard with credentials.',
      passed: !isOverlyPermissiveCors,
      httpStatus: response.status,
      evidence: allowOrigin ? `Access-Control-Allow-Origin: ${allowOrigin}` : 'No permissive CORS header',
      reproduceCurl: generateCurlCommand({
        url: fullUrl,
        method: 'GET',
        headers: { Origin: 'https://attacker-origin.example.com' },
      }),
      remediationAdvice: 'Configure explicit CORS origin whitelist instead of reflecting origin or using wildcard with credentials.',
    });

  } catch (err) {
    results.push({
      id: `HDR-CONN-ERR-${endpoint.path}`,
      category: 'SECURITY_HEADERS',
      endpoint: endpoint.path,
      method: endpoint.method,
      severity: 'CRITICAL',
      title: 'Connection Availability',
      description: 'Endpoint must be reachable to evaluate security headers.',
      passed: false,
      evidence: `Connection error: ${(err as Error).message}`,
      reproduceCurl: generateCurlCommand({ url: fullUrl, method: 'GET' }),
      remediationAdvice: 'Ensure target backend server is running and accessible at baseUrl.',
    });
  }

  return results;
}
