import fs from 'node:fs';
import path from 'node:path';
import { EndpointDefinition, HttpMethod } from '../types.js';

export interface ProjectStack {
  language: 'TypeScript' | 'JavaScript' | 'Python' | 'PHP' | 'Go' | 'Java' | 'Unknown';
  framework: 'Express' | 'Fastify' | 'NestJS' | 'Next.js' | 'Hono' | 'Koa' | 'FastAPI' | 'Django' | 'Flask' | 'Laravel' | 'Unknown';
  ormOrDatabase: string[];
  securityControls: {
    hasSecurityHeaders: boolean; // e.g. helmet
    hasRateLimiter: boolean;    // e.g. express-rate-limit
    hasCorsConfigured: boolean; // e.g. cors
    hasBodySizeLimits: boolean; // e.g. limit: '100kb'
    hasValidationLibrary: boolean; // e.g. zod, joi, class-validator
    hasAuthMiddleware: boolean; // e.g. jwt, passport
  };
}

export interface StaticVulnerability {
  file: string;
  line: number;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  title: string;
  snippet: string;
  recommendation: string;
}

export interface ProjectBreakdown {
  rootPath: string;
  stack: ProjectStack;
  discoveredEndpoints: EndpointDefinition[];
  staticVulnerabilities: StaticVulnerability[];
  openApiFound?: string;
  defensiveScore: number; // 0 to 100
  recommendations: string[];
}

export async function scanProject(rootPath: string = process.cwd()): Promise<ProjectBreakdown> {
  const stack = detectProjectStack(rootPath);
  const discoveredEndpoints: EndpointDefinition[] = [];
  const staticVulnerabilities: StaticVulnerability[] = [];
  const recommendations: string[] = [];

  // 1. Check for OpenAPI / Swagger specs
  const openApiFile = findOpenApiSpec(rootPath);
  if (openApiFile) {
    const endpointsFromSpec = parseOpenApiSpec(openApiFile);
    discoveredEndpoints.push(...endpointsFromSpec);
  }

  // 2. Scan source files for endpoints and SAST patterns
  const srcFiles = collectSourceFiles(rootPath);
  for (const filePath of srcFiles) {
    const content = fs.readFileSync(filePath, 'utf-8');
    const relativePath = path.relative(rootPath, filePath);

    // Endpoint extraction if not loaded from OpenAPI
    if (discoveredEndpoints.length < 50) {
      const endpointsInFile = extractEndpointsFromCode(content, stack.framework);
      for (const ep of endpointsInFile) {
        if (!discoveredEndpoints.some(e => e.path === ep.path && e.method === ep.method)) {
          discoveredEndpoints.push(ep);
        }
      }
    }

    // Static code analysis for common vulnerabilities
    scanFileForVulnerabilities(content, relativePath, staticVulnerabilities);
  }

  // Fallback endpoints if none discovered
  if (discoveredEndpoints.length === 0) {
    discoveredEndpoints.push(
      { path: '/api/health', method: 'GET', authRequired: false, expectedSuccessStatus: 200 },
      { path: '/api/users', method: 'GET', authRequired: true, requiredRole: 'user' },
      { path: '/api/users', method: 'POST', authRequired: true, requiredRole: 'user', sampleBody: { name: 'Sample' } }
    );
  }

  // 3. Compute static defensive score
  let score = 100;
  if (!stack.securityControls.hasSecurityHeaders) {
    score -= 20;
    recommendations.push('Implementar middleware de cabeceras de seguridad (ej. Helmet para Node.js).');
  }
  if (!stack.securityControls.hasRateLimiter) {
    score -= 20;
    recommendations.push('Configurar limitación de tasa (Rate Limiting) para mitigar fuerza bruta y DoS.');
  }
  if (!stack.securityControls.hasBodySizeLimits) {
    score -= 15;
    recommendations.push('Configurar límites estrictos en el analizador del cuerpo de petición (ej. limit: "100kb").');
  }
  if (!stack.securityControls.hasValidationLibrary) {
    score -= 15;
    recommendations.push('Adoptar validación estricta de esquemas DTO (ej. Zod, Joi o class-validator).');
  }

  for (const vuln of staticVulnerabilities) {
    if (vuln.severity === 'CRITICAL') score -= 15;
    else if (vuln.severity === 'HIGH') score -= 10;
    else score -= 5;
  }

  const finalScore = Math.max(10, Math.min(100, score));

  return {
    rootPath,
    stack,
    discoveredEndpoints,
    staticVulnerabilities,
    openApiFound: openApiFile ? path.relative(rootPath, openApiFile) : undefined,
    defensiveScore: finalScore,
    recommendations,
  };
}

function detectProjectStack(rootPath: string): ProjectStack {
  let language: ProjectStack['language'] = 'Unknown';
  let framework: ProjectStack['framework'] = 'Unknown';
  const orms: string[] = [];

  const pkgJsonPath = path.join(rootPath, 'package.json');
  const pyProject = path.join(rootPath, 'pyproject.toml');
  const reqTxt = path.join(rootPath, 'requirements.txt');
  const composerJson = path.join(rootPath, 'composer.json');

  let depsStr = '';

  if (fs.existsSync(pkgJsonPath)) {
    try {
      const pkg = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf-8'));
      const allDeps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
      depsStr = JSON.stringify(allDeps);

      language = fs.existsSync(path.join(rootPath, 'tsconfig.json')) || allDeps['typescript']
        ? 'TypeScript'
        : 'JavaScript';

      if (allDeps['@nestjs/core']) framework = 'NestJS';
      else if (allDeps['next']) framework = 'Next.js';
      else if (allDeps['fastify']) framework = 'Fastify';
      else if (allDeps['hono']) framework = 'Hono';
      else if (allDeps['koa']) framework = 'Koa';
      else if (allDeps['express']) framework = 'Express';

      if (allDeps['@prisma/client'] || allDeps['prisma']) orms.push('Prisma');
      if (allDeps['typeorm']) orms.push('TypeORM');
      if (allDeps['mongoose']) orms.push('Mongoose');
      if (allDeps['drizzle-orm']) orms.push('Drizzle');
      if (allDeps['sequelize']) orms.push('Sequelize');
      if (allDeps['knex']) orms.push('Knex');
    } catch {}
  } else if (fs.existsSync(pyProject) || fs.existsSync(reqTxt)) {
    language = 'Python';
    const pyContent = (fs.existsSync(pyProject) ? fs.readFileSync(pyProject, 'utf-8') : '') +
      (fs.existsSync(reqTxt) ? fs.readFileSync(reqTxt, 'utf-8') : '');
    depsStr = pyContent;

    if (/fastapi/i.test(pyContent)) framework = 'FastAPI';
    else if (/django/i.test(pyContent)) framework = 'Django';
    else if (/flask/i.test(pyContent)) framework = 'Flask';

    if (/sqlalchemy/i.test(pyContent)) orms.push('SQLAlchemy');
    if (/tortoise-orm/i.test(pyContent)) orms.push('Tortoise ORM');
  } else if (fs.existsSync(composerJson)) {
    language = 'PHP';
    framework = 'Laravel';
    orms.push('Eloquent');
  }

  // Security controls detection
  const hasSecurityHeaders = /helmet|secure-headers|django-csp|django-cors-headers/i.test(depsStr);
  const hasRateLimiter = /rate-limit|slowapi|express-rate-limit|throttler/i.test(depsStr);
  const hasCorsConfigured = /cors|django-cors/i.test(depsStr);
  const hasBodySizeLimits = /body-parser|express\.json/i.test(depsStr);
  const hasValidationLibrary = /zod|joi|class-validator|pydantic|yup/i.test(depsStr);
  const hasAuthMiddleware = /jsonwebtoken|passport|next-auth|lucia|auth0|fastapi-jwt/i.test(depsStr);

  return {
    language,
    framework,
    ormOrDatabase: orms.length > 0 ? orms : ['SQL / Driver genérico'],
    securityControls: {
      hasSecurityHeaders,
      hasRateLimiter,
      hasCorsConfigured,
      hasBodySizeLimits,
      hasValidationLibrary,
      hasAuthMiddleware,
    },
  };
}

function findOpenApiSpec(rootPath: string): string | undefined {
  const candidates = [
    'openapi.json',
    'openapi.yaml',
    'openapi.yml',
    'swagger.json',
    'swagger.yaml',
    'docs/openapi.json',
    'docs/swagger.json',
  ];

  for (const c of candidates) {
    const full = path.join(rootPath, c);
    if (fs.existsSync(full)) return full;
  }
  return undefined;
}

function parseOpenApiSpec(specPath: string): EndpointDefinition[] {
  const endpoints: EndpointDefinition[] = [];
  try {
    if (specPath.endsWith('.json')) {
      const data = JSON.parse(fs.readFileSync(specPath, 'utf-8'));
      if (data.paths) {
        for (const [routePath, methods] of Object.entries<any>(data.paths)) {
          for (const [httpMethod, details] of Object.entries<any>(methods)) {
            const upperMethod = httpMethod.toUpperCase() as HttpMethod;
            if (['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].includes(upperMethod)) {
              const hasSecurity = !!(details.security && details.security.length > 0);
              endpoints.push({
                path: routePath,
                method: upperMethod,
                description: details.summary || details.description,
                authRequired: hasSecurity,
                requiredRole: routePath.includes('admin') ? 'admin' : hasSecurity ? 'user' : undefined,
              });
            }
          }
        }
      }
    }
  } catch {}
  return endpoints;
}

function collectSourceFiles(dir: string, maxFiles = 80): string[] {
  const files: string[] = [];
  const ignoredDirs = new Set(['node_modules', 'dist', '.git', 'coverage', '.next', 'vendor', '__pycache__']);

  function walk(current: string) {
    if (files.length >= maxFiles) return;
    try {
      const entries = fs.readdirSync(current, { withFileTypes: true });
      for (const entry of entries) {
        if (entry.isDirectory()) {
          if (!ignoredDirs.has(entry.name)) {
            walk(path.join(current, entry.name));
          }
        } else if (entry.isFile()) {
          const ext = path.extname(entry.name).toLowerCase();
          const isScannerTool = entry.name.includes('project-scanner') || entry.name.includes('interactive-cli');
          if (['.ts', '.js', '.py', '.php', '.go'].includes(ext) && !entry.name.endsWith('.d.ts') && !entry.name.includes('.test.') && !isScannerTool) {
            files.push(path.join(current, entry.name));
            if (files.length >= maxFiles) return;
          }
        }
      }
    } catch {}
  }

  walk(dir);
  return files;
}

function extractEndpointsFromCode(content: string, framework: string): EndpointDefinition[] {
  const endpoints: EndpointDefinition[] = [];

  // Express / Router pattern: (app|router).(get|post|put|delete|patch)('/path', ...)
  const expressRegex = /(?:app|router)\.(get|post|put|patch|delete)\s*\(\s*['"`]([^'"`]+)['"`]/gi;
  let match: RegExpExecArray | null;
  while ((match = expressRegex.exec(content)) !== null) {
    const method = match[1].toUpperCase() as HttpMethod;
    const route = match[2];
    if (route && !route.includes('*')) {
      const isAdmin = route.includes('/admin');
      const isAuth = !route.includes('/health') && !route.includes('/login') && !route.includes('/public');
      endpoints.push({
        path: route,
        method,
        authRequired: isAuth,
        requiredRole: isAdmin ? 'admin' : isAuth ? 'user' : undefined,
      });
    }
  }

  // Native Node.js HTTP pattern: pathname === '/api/...' or req.url === '...'
  const nodeHttpRegex = /(?:pathname|req\.url|url\.pathname)\s*===?\s*['"`]([^'"`]+)['"`]/gi;
  while ((match = nodeHttpRegex.exec(content)) !== null) {
    const route = match[1];
    if (route.startsWith('/') && !route.includes('*')) {
      const isAdmin = route.includes('/admin');
      const isAuth = !route.includes('/health') && !route.includes('/login');
      endpoints.push({
        path: route,
        method: 'GET',
        authRequired: isAuth,
        requiredRole: isAdmin ? 'admin' : undefined,
      });
    }
  }

  // NestJS controller pattern: @Get('path'), @Post('path')
  const nestRegex = /@(Get|Post|Put|Patch|Delete)\s*\(\s*['"`]?([^'"`]*)['"`]?\s*\)/gi;
  while ((match = nestRegex.exec(content)) !== null) {
    const method = match[1].toUpperCase() as HttpMethod;
    const subRoute = match[2] || '';
    const fullRoute = subRoute.startsWith('/') ? subRoute : `/${subRoute}`;
    endpoints.push({
      path: fullRoute,
      method,
      authRequired: true,
      requiredRole: fullRoute.includes('admin') ? 'admin' : 'user',
    });
  }

  // FastAPI pattern: @app.get('/path') or @router.post('/path')
  const fastApiRegex = /@(?:app|router)\.(get|post|put|patch|delete)\s*\(\s*['"`]([^'"`]+)['"`]/gi;
  while ((match = fastApiRegex.exec(content)) !== null) {
    const method = match[1].toUpperCase() as HttpMethod;
    const route = match[2];
    endpoints.push({
      path: route,
      method,
      authRequired: !route.includes('health'),
    });
  }

  return endpoints;
}

function scanFileForVulnerabilities(content: string, relativePath: string, vulns: StaticVulnerability[]): void {
  const lines = content.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNum = i + 1;

    // 1. Hardcoded Secret / Token / Password
    const secretRegex = /(?:jwt_secret|api_key|secret_key|private_key|password)\s*[:=]\s*['"`]([A-Za-z0-9_\-\.]{8,})['"`]/i;
    if (secretRegex.test(line) && !line.includes('process.env') && !line.includes('dotenv')) {
      vulns.push({
        file: relativePath,
        line: lineNum,
        severity: 'CRITICAL',
        title: 'Posible Secreto o Clave Hardcodeada en Código',
        snippet: line.trim().slice(0, 80),
        recommendation: 'Extraer credenciales a variables de entorno (.env) y nunca versionarlas en el repositorio.',
      });
    }

    // 2. Raw Error Stack Leak in Response
    if (/(?:res\.send|res\.json|return res)\s*\(\s*(?:err\.stack|err|error\.stack)/i.test(line)) {
      vulns.push({
        file: relativePath,
        line: lineNum,
        severity: 'HIGH',
        title: 'Fuga de Stack Trace o Excepción Interna al Cliente',
        snippet: line.trim().slice(0, 80),
        recommendation: 'Sanitizar respuestas 500 para devolver únicamente mensajes genéricos en producción.',
      });
    }

    // 3. Raw SQL Concatenation
    if (/(?:db\.query|sequelize\.query|connection\.query)\s*\(\s*['"`].*\$\{.*\}['"`]/i.test(line) ||
        /(?:db\.query|query)\s*\(\s*['"`].*['"`]\s*\+\s*[a-zA-Z]/i.test(line)) {
      vulns.push({
        file: relativePath,
        line: lineNum,
        severity: 'CRITICAL',
        title: 'Riesgo de Inyección SQL por Concatenación de Parámetros',
        snippet: line.trim().slice(0, 80),
        recommendation: 'Utilizar sentencias preparadas o consultas parametrizadas con marcadores de posición ($1 o ?).',
      });
    }

    // 4. Overly Permissive CORS
    if (/(?:origin:\s*['"`]\*['"`]|origin:\s*true)/i.test(line) && /credentials:\s*true/i.test(content)) {
      vulns.push({
        file: relativePath,
        line: lineNum,
        severity: 'HIGH',
        title: 'CORS Permisivo con Credenciales Habilitadas',
        snippet: line.trim().slice(0, 80),
        recommendation: 'Definir una lista blanca explícita de orígenes autorizados en lugar de permitir comodín con cookies/tokens.',
      });
    }
  }
}
