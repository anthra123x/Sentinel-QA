import { AuditCheckResult, StressTestSummary, DiagnosticItem } from '../types.js';

export function analyzeBottlenecksAndRisks(
  auditResults: AuditCheckResult[],
  stressResults?: StressTestSummary[]
): DiagnosticItem[] {
  const diagnostics: DiagnosticItem[] = [];

  // --- 1. Audit Security Analysis ---
  const failedHeaders = auditResults.filter(r => !r.passed && r.category === 'SECURITY_HEADERS');
  if (failedHeaders.length > 0) {
    diagnostics.push({
      id: 'DIAG-MISSING-SECURITY-HEADERS',
      category: 'SECURITY',
      severity: 'HIGH',
      title: 'Missing Core Defense HTTP Security Headers',
      impact: 'Browsers are susceptible to Clickjacking (lack of X-Frame-Options/CSP), MIME sniffing attacks, and technology profiling via X-Powered-By.',
      rootCause: 'HTTP response pipeline lacks security header middleware.',
      remediationCode: `// TypeScript / Node.js (Express / Fastify):
import helmet from 'helmet';

// Mount helmet at top of middleware chain:
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      objectSrc: ["'none'"],
      upgradeInsecureRequests: [],
    },
  },
  frameguard: { action: 'deny' },
  noSniff: true,
  hidePoweredBy: true,
}));`,
    });
  }

  // Check Stack Trace Leaks
  const leakFindings = auditResults.filter(r => !r.passed && r.evidence?.includes('LEAK'));
  if (leakFindings.length > 0) {
    diagnostics.push({
      id: 'DIAG-STACK-TRACE-LEAK',
      category: 'SECURITY',
      severity: 'CRITICAL',
      title: 'Internal Stack Trace & Path Disclosure in Error Responses',
      impact: 'Attackers gain insight into internal file structures, dependencies, versions, and potential CVEs in runtime packages.',
      rootCause: 'Default or unhandled exception handler outputs "err.stack" directly into response JSON or HTML.',
      remediationCode: `// Centralized Production Error Handler Middleware:
app.use((err: Error, req: Request, res: Response, next: NextFunction) => {
  const isProduction = process.env.NODE_ENV === 'production';
  
  // Log full stack internally only
  console.error('[Internal Error Log]', { message: err.message, stack: err.stack });

  res.status(500).json({
    status: 'error',
    message: isProduction ? 'Internal Server Error' : err.message,
    // NEVER expose stack trace to clients
  });
});`,
    });
  }

  // Check Body Limit / Malformed JSON
  const bodyIssues = auditResults.filter(r => !r.passed && (r.id.includes('PLD-OVERSIZED') || r.id.includes('PLD-MALFORMED')));
  if (bodyIssues.length > 0) {
    diagnostics.push({
      id: 'DIAG-PAYLOAD-LIMITS',
      category: 'RESILIENCE',
      severity: 'HIGH',
      title: 'Unbounded Request Body Size & Unsafe JSON Parser',
      impact: 'Application is vulnerable to Denial of Service (DoS) memory exhaustion via JSON body bombs.',
      rootCause: 'Body parser accepts unbounded payload streams or crashes on malformed JSON chunks.',
      remediationCode: `// Enforce tight body limits and handle parsing errors:
app.use(express.json({ limit: '100kb' }));

app.use((err: any, req: Request, res: Response, next: NextFunction) => {
  if (err instanceof SyntaxError && 'status' in err && err.status === 400) {
    return res.status(400).json({ error: 'Malformed JSON payload' });
  }
  if (err.type === 'entity.too.large') {
    return res.status(413).json({ error: 'Payload too large (max 100kb)' });
  }
  next(err);
});`,
    });
  }

  // Check RBAC Failures
  const rbacIssues = auditResults.filter(r => !r.passed && r.category === 'RBAC_AUTH');
  if (rbacIssues.length > 0) {
    diagnostics.push({
      id: 'DIAG-RBAC-AUTH-BYPASS',
      category: 'SECURITY',
      severity: 'CRITICAL',
      title: 'Broken Authentication or Privilege Escalation Boundary',
      impact: 'Unauthenticated clients or non-privileged users can execute sensitive business logic or access restricted endpoints.',
      rootCause: 'Endpoints are missing authentication middleware or lack role authorization guards.',
      remediationCode: `// Require Authentication & Role Guard:
export function requireRole(requiredRole: 'user' | 'admin') {
  return (req: Request, res: Response, next: NextFunction) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Unauthorized: Missing or invalid token' });
    }

    const token = authHeader.split(' ')[1];
    const user = verifyToken(token); // Verify signature & claims

    if (!user) {
      return res.status(401).json({ error: 'Unauthorized: Invalid token' });
    }

    if (requiredRole === 'admin' && user.role !== 'admin') {
      return res.status(403).json({ error: 'Forbidden: Insufficient privileges' });
    }

    req.user = user;
    next();
  };
}`,
    });
  }

  // --- 2. Stress Test & Bottleneck Analysis ---
  if (stressResults && stressResults.length > 0) {
    for (const stress of stressResults) {
      // Check 1: Missing Rate Limiting
      if (!stress.rateLimitEnforced && stress.totalRequests > 50) {
        diagnostics.push({
          id: `DIAG-NO-RATE-LIMIT-${stress.endpoint.replace(/\s+/g, '_')}`,
          category: 'RESILIENCE',
          severity: 'HIGH',
          title: `Absence of Rate Limiting on ${stress.endpoint}`,
          impact: `Endpoint handled ${stress.totalRequests} requests without triggering 429 Too Many Requests, leaving backend open to brute-force and resource starvation.`,
          rootCause: 'No rate limiting middleware or reverse-proxy throttling configured.',
          remediationCode: `import rateLimit from 'express-rate-limit';

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per window
  standardHeaders: true, // Return RateLimit-* headers
  legacyHeaders: false,
  message: { error: 'Too many requests, please try again later.' },
  statusCode: 429,
});

app.use('/api/', apiLimiter);`,
        });
      }

      // Check 2: Saturation Knee / N+1 Query / DB Lock indication
      if (stress.saturationKneeVUs || stress.overallLatencies.p99 > 500) {
        diagnostics.push({
          id: `DIAG-BOTTLENECK-SATURATION-${stress.endpoint.replace(/\s+/g, '_')}`,
          category: 'PERFORMANCE_BOTTLENECK',
          severity: 'HIGH',
          title: `Latency Degradation & Saturation Knee on ${stress.endpoint}`,
          impact: `P99 latency spiked to ${stress.overallLatencies.p99}ms under load. Throughput choked near ~${stress.saturationKneeVUs || 'peak'} concurrent users.`,
          rootCause: 'Likely unindexed database queries, synchronous CPU blocking in event loop, or connection pool contention (N+1 query problem).',
          remediationCode: `// 1. Add SQL indexes on queried foreign keys / filter columns:
// CREATE INDEX idx_users_email ON users(email);
// CREATE INDEX idx_orders_user_id ON orders(user_id);

// 2. Resolve N+1 query loops using DataLoader or JOIN:
// Instead of:
// const users = await db.users.findMany();
// for (const u of users) { u.posts = await db.posts.findMany({ where: { userId: u.id } }); }
// Use batch include:
const users = await db.users.findMany({
  include: { posts: true },
});

// 3. Configure Database Connection Pool:
// maxConnections: 20, idleTimeoutMillis: 30000`,
        });
      }

      // Check 3: High Error Rate under concurrency
      if (stress.errorRatePercent > 2.0) {
        diagnostics.push({
          id: `DIAG-CONCURRENCY-ERRORS-${stress.endpoint.replace(/\s+/g, '_')}`,
          category: 'RESILIENCE',
          severity: 'CRITICAL',
          title: `Excessive Error Rate (${stress.errorRatePercent}%) Under Load on ${stress.endpoint}`,
          impact: 'Server connections were dropped or returned 5xx errors during high concurrency peaks.',
          rootCause: 'Socket exhaustion, unhandled promise rejections, or database pool timeouts.',
          remediationCode: `// Tune Node.js & DB pool resilience:
// In entrypoint:
process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});

// Configure Keep-Alive timeout on HTTP server:
const server = app.listen(PORT);
server.keepAliveTimeout = 65000;
server.headersTimeout = 66000;`,
        });
      }
    }
  }

  return diagnostics;
}
