import http from 'node:http';

const PORT = parseInt(process.env.PORT || '3001', 10);
const IS_HARDENED = process.env.HARDENED === 'true' || process.argv.includes('--hardened');

// In-memory rate limiter for demo
const requestCounts = new Map<string, { count: number; resetTime: number }>();

function checkRateLimit(ip: string, limit = 50, windowMs = 5000): boolean {
  const now = Date.now();
  const record = requestCounts.get(ip);
  if (!record || now > record.resetTime) {
    requestCounts.set(ip, { count: 1, resetTime: now + windowMs });
    return true;
  }
  if (record.count >= limit) {
    return false;
  }
  record.count++;
  return true;
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);
  const clientIp = req.socket.remoteAddress || '127.0.0.1';

  // --- HARDENED HEADERS ---
  if (IS_HARDENED) {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Content-Security-Policy', "default-src 'self'");
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    // Note: Do NOT set X-Powered-By
  } else {
    // VULNERABLE: Leaks technology stack, misses defense headers
    res.setHeader('X-Powered-By', 'Express/4.17.1');
    res.setHeader('Access-Control-Allow-Origin', '*');
  }

  // --- RATE LIMITING ---
  if (IS_HARDENED && !checkRateLimit(clientIp, 60, 5000)) {
    res.writeHead(429, {
      'Content-Type': 'application/json',
      'Retry-After': '5',
      'X-RateLimit-Limit': '60',
      'X-RateLimit-Remaining': '0',
    });
    return res.end(JSON.stringify({ error: 'Too Many Requests: Rate limit exceeded. Try again in 5s.' }));
  }

  // --- BODY COLLECTION & SIZE LIMIT ---
  let bodyBuffer = '';
  let bodyTooLarge = false;
  const MAX_BYTES = IS_HARDENED ? 100 * 1024 : 10 * 1024 * 1024; // 100KB vs 10MB

  req.on('data', (chunk) => {
    bodyBuffer += chunk;
    if (bodyBuffer.length > MAX_BYTES) {
      bodyTooLarge = true;
      req.destroy(); // stop receiving
    }
  });

  req.on('end', () => {
    if (bodyTooLarge) {
      res.writeHead(413, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'Payload Too Large: maximum allowed body size is 100KB' }));
    }

    try {
      handleRequest(url, req, res, bodyBuffer);
    } catch (err: any) {
      if (IS_HARDENED) {
        // Defensive sanitized 500
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: 'error', message: 'Internal Server Error' }));
      } else {
        // VULNERABLE: Leaking stack trace to client
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          error: err.message,
          stack: err.stack,
          serverPath: '/home/omicron/app/server.ts',
        }));
      }
    }
  });
});

function handleRequest(url: URL, req: http.IncomingMessage, res: http.ServerResponse, rawBody: string) {
  const method = req.method || 'GET';
  const pathname = url.pathname;
  const authHeader = req.headers['authorization'];

  // Route 1: Healthcheck
  if (pathname === '/api/health' && method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ status: 'healthy', hardened: IS_HARDENED, timestamp: new Date().toISOString() }));
  }

  // Route 2: /api/users (GET & POST)
  if (pathname === '/api/users') {
    // Check Authentication
    if (IS_HARDENED) {
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: 'Unauthorized: Missing or invalid token' }));
      }
    } else {
      // VULNERABLE: Allows unauthenticated access
    }

    if (method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify([
        { id: 1, name: 'Alice Smith', email: 'alice@example.com' },
        { id: 2, name: 'Bob Jones', email: 'bob@example.com' },
      ]));
    }

    if (method === 'POST') {
      let parsed: any;
      try {
        parsed = rawBody ? JSON.parse(rawBody) : {};
      } catch (e: any) {
        if (IS_HARDENED) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ error: 'Malformed JSON payload' }));
        } else {
          // VULNERABLE: Uncaught or raw stack trace
          throw new SyntaxError(`Unexpected token in JSON at position 12 in /var/www/api/users.ts: \n at JSON.parse (<anonymous>)\n at handleRequest (/home/omicron/app/server.ts:85:20)`);
        }
      }

      // Schema boundary validation
      if (IS_HARDENED) {
        if (!parsed.name || typeof parsed.name !== 'string') {
          res.writeHead(422, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ error: 'Validation failed: field "name" must be a non-empty string' }));
        }
      }

      res.writeHead(201, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ id: 3, name: parsed.name, created: true }));
    }
  }

  // Route 3: /api/admin/metrics (Privileged)
  if (pathname === '/api/admin/metrics') {
    if (IS_HARDENED) {
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: 'Unauthorized' }));
      }
      const token = authHeader.replace('Bearer ', '').trim();
      if (token !== 'admin-secret-token') {
        res.writeHead(403, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: 'Forbidden: Admin role required' }));
      }
    } else {
      // VULNERABLE: No role check, anyone with user token or anonymous can see admin metrics!
    }

    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ memoryUsage: '45MB', totalUsers: 1420, systemUptime: '99.9%' }));
  }

  // Route 4: /api/simulate-crash (For testing 500 error leak)
  if (pathname === '/api/simulate-crash') {
    throw new Error('Database connection pool timeout at query: SELECT * FROM secrets WHERE id=1');
  }

  // Not Found
  res.writeHead(404, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ error: 'Not found' }));
}

server.listen(PORT, () => {
  console.log(`[Demo Server] Running on http://localhost:${PORT}`);
  console.log(`[Demo Server] Mode: ${IS_HARDENED ? '🛡️  HARDENED (Defensive Mode)' : '⚠️  VULNERABLE (Default Flawed Mode)'}`);
});
