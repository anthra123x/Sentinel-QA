export interface LeakDetectionResult {
  hasLeak: boolean;
  leakType?: 'STACK_TRACE' | 'FILE_PATH' | 'SQL_ERROR' | 'ENVIRONMENT_SECRET';
  snippet?: string;
}

const STACK_TRACE_PATTERNS = [
  /at\s+[\w$.]+\s+\([^)]+:\d+:\d+\)/i,               // JS/V8 stack trace
  /at\s+[a-z0-9_$.]+\s+\([a-z0-9_/\\.-]+:\d+\)/i,  // JS stack trace
  /Traceback \(most recent call last\):/i,          // Python
  /\bat\s+[a-z0-9_$.]+\.[a-z0-9_$]+\([^)]+\.java:\d+\)/i, // Java
  /Fatal error:.*in\s+\/.*\.php\s+on\s+line\s+\d+/i, // PHP
  /Exception in thread "[^"]*"/i,
  /Goroutine \d+ \[[^\]]+\]:/i                      // Go panic
];

const FILE_PATH_PATTERNS = [
  /(?:\/home\/|\/var\/www\/|\/usr\/src\/app\/|\/etc\/|\/tmp\/)[\w.-]+/i,
  /[a-z]:\\(?:users|inetpub|windows|app)[\w\\.-]+/i,
];

const SQL_ERROR_PATTERNS = [
  /syntax error at or near/i,
  /SQLSTATE\[/i,
  /SequelizeDatabaseError/i,
  /PrismaClient(Known|Unknown)RequestError/i,
  /You have an error in your SQL syntax/i,
  /unclosed quotation mark after the character string/i,
  /sqlite3\.OperationalError/i,
  /ORA-\d{5}/i,
  /MongoServerError/i,
];

export function detectInformationLeak(body: string): LeakDetectionResult {
  if (!body || typeof body !== 'string') {
    return { hasLeak: false };
  }

  for (const pattern of STACK_TRACE_PATTERNS) {
    const match = body.match(pattern);
    if (match) {
      return {
        hasLeak: true,
        leakType: 'STACK_TRACE',
        snippet: match[0].slice(0, 150),
      };
    }
  }

  for (const pattern of SQL_ERROR_PATTERNS) {
    const match = body.match(pattern);
    if (match) {
      return {
        hasLeak: true,
        leakType: 'SQL_ERROR',
        snippet: match[0].slice(0, 150),
      };
    }
  }

  for (const pattern of FILE_PATH_PATTERNS) {
    const match = body.match(pattern);
    if (match) {
      return {
        hasLeak: true,
        leakType: 'FILE_PATH',
        snippet: match[0].slice(0, 150),
      };
    }
  }

  return { hasLeak: false };
}
