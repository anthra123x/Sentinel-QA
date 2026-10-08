import fs from 'node:fs';
import path from 'node:path';
import * as p from '@clack/prompts';
import pc from 'picocolors';
import { scanProject, ProjectBreakdown } from '../scanner/project-scanner.js';
import { loadConfig } from '../config.js';
import { runDefensiveAudit, calculateSecurityScore } from '../audit/index.js';
import { runStressTestForEndpoint } from '../stress/load-engine.js';
import { analyzeBottlenecksAndRisks } from '../diagnose/bottleneck-analyzer.js';
import { saveReports } from '../report/markdown-reporter.js';
import { saveK6Script } from '../stress/k6-generator.js';
import { saveArtilleryScript } from '../stress/artillery-generator.js';
import { SentinelConfig, FullAuditReport, StressTestSummary, EndpointDefinition } from '../types.js';

export async function runInteractiveCli(): Promise<void> {
  console.clear();
  p.intro(pc.bgCyan(pc.black(' 🛡️  SENTINEL-QA : ASISTENTE INTERACTIVO DE AUDITORÍA Y CARGA ')));

  const s = p.spinner();

  while (true) {
    const action = await p.select({
      message: '¿Qué acción deseas realizar en el proyecto?',
      options: [
        { value: 'breakdown', label: '🔍 Desglose Absoluto del Proyecto', hint: 'Auto-detección de stack, endpoints, SAST y postura defensiva' },
        { value: 'run-full', label: '🚀 Ejecutar Ciclo Completo', hint: 'Auditoría + Estrés escalonado + Parches + Reporte técnico' },
        { value: 'audit', label: '🛡️  Auditoría Defensiva Rápida', hint: 'Validar cabeceras OWASP, payloads malformados, RBAC y fugas' },
        { value: 'stress', label: '⚡ Pruebas de Carga y Resiliencia', hint: 'Medir latencias p95/p99, RPS y comportamiento de Rate Limiting' },
        { value: 'export-scripts', label: '📝 Generar Scripts CI/CD', hint: 'Exportar k6-stress-test.js y artillery-stress-test.yml' },
        { value: 'wizard-config', label: '⚙️  Configurador Asistido', hint: 'Crear o actualizar sentinel.config.json interactivamente' },
        { value: 'exit', label: '🚪 Salir' },
      ],
    });

    if (p.isCancel(action) || action === 'exit') {
      p.outro(pc.cyan('¡Hasta pronto! Mantén tus APIs blindadas y resilientes con Sentinel-QA.'));
      process.exit(0);
    }

    if (action === 'breakdown') {
      await handleProjectBreakdown(s);
    } else if (action === 'run-full') {
      await handleInteractiveFullRun(s);
    } else if (action === 'audit') {
      await handleInteractiveAudit(s);
    } else if (action === 'stress') {
      await handleInteractiveStress(s);
    } else if (action === 'export-scripts') {
      await handleExportScripts();
    } else if (action === 'wizard-config') {
      await handleConfigWizard();
    }
  }
}

async function handleProjectBreakdown(s: ReturnType<typeof p.spinner>): Promise<void> {
  s.start('Analizando arquitectura, dependencias y código fuente del proyecto...');
  const breakdown = await scanProject(process.cwd());
  s.stop('¡Análisis del proyecto completado con éxito!');

  renderBreakdownCard(breakdown);

  // Ask if user wants to save discovered endpoints to config
  if (breakdown.discoveredEndpoints.length > 0) {
    const saveToConfig = await p.confirm({
      message: `¿Deseas exportar los ${breakdown.discoveredEndpoints.length} endpoints detectados a "sentinel.config.json"?`,
      initialValue: true,
    });

    if (!p.isCancel(saveToConfig) && saveToConfig) {
      const currentConfig = loadConfig();
      currentConfig.endpoints = breakdown.discoveredEndpoints;
      fs.writeFileSync(
        path.resolve(process.cwd(), 'sentinel.config.json'),
        JSON.stringify(currentConfig, null, 2),
        'utf-8'
      );
      p.log.success(pc.green('✔ Archivo sentinel.config.json sincronizado con los endpoints del proyecto.'));
    }
  }
}

function renderBreakdownCard(b: ProjectBreakdown): void {
  const scoreColor = b.defensiveScore >= 80 ? pc.green : b.defensiveScore >= 50 ? pc.yellow : pc.red;
  const scoreBadge = scoreColor(`${b.defensiveScore}/100`);

  p.note(
    `${pc.bold('📁 Raíz del Proyecto:')} ${b.rootPath}
${pc.bold('💻 Lenguaje / Runtime:')} ${pc.cyan(b.stack.language)}
${pc.bold('⚙️  Framework Backend:')} ${pc.magenta(b.stack.framework)}
${pc.bold('🗄️  ORM / Capa de Datos:')} ${b.stack.ormOrDatabase.join(', ')}
${pc.bold('🛡️  Puntuación Defensiva Estática:')} ${scoreBadge}
${b.openApiFound ? `${pc.bold('📄 Especificación OpenAPI:')} ${pc.cyan(b.openApiFound)}\n` : ''}`,
    '📦 ARQUITECTURA DETECTADA'
  );

  // Security controls table
  const ctrl = b.stack.securityControls;
  const statusIcon = (active: boolean) => active ? pc.green('✔ Activo') : pc.red('✘ Faltante');
  
  p.note(
    `• Cabeceras de Seguridad (Helmet/CSP):     ${statusIcon(ctrl.hasSecurityHeaders)}
• Limitación de Tasa (Rate Limiter):       ${statusIcon(ctrl.hasRateLimiter)}
• Límites de Tamaño en Body (>100KB DoS):  ${statusIcon(ctrl.hasBodySizeLimits)}
• Configuración Estricta de CORS:          ${statusIcon(ctrl.hasCorsConfigured)}
• Validación de DTOs (Zod/Joi/Pydantic):   ${statusIcon(ctrl.hasValidationLibrary)}
• Middleware de Autenticación / JWT:       ${statusIcon(ctrl.hasAuthMiddleware)}`,
    '🛡️  ESTADO DE CONTROLES DEFENSIVOS'
  );

  // Discovered endpoints
  if (b.discoveredEndpoints.length > 0) {
    const epLines = b.discoveredEndpoints.slice(0, 8).map(ep => {
      const auth = ep.authRequired ? pc.yellow('[Auth]') : pc.green('[Público]');
      const role = ep.requiredRole ? pc.red(`(${ep.requiredRole})`) : '';
      return `  • ${pc.bold(ep.method.padEnd(6))} ${ep.path} ${auth} ${role}`;
    }).join('\n');
    const remaining = b.discoveredEndpoints.length > 8 ? `\n  ${pc.dim(`...y ${b.discoveredEndpoints.length - 8} endpoints adicionales`)}` : '';

    p.note(
      `${epLines}${remaining}\n\n${pc.bold('Total de superficie expuesta:')} ${b.discoveredEndpoints.length} endpoints`,
      '🌐 MAPA DE ENDPOINTS DESCUBIERTOS'
    );
  }

  // Static vulnerabilities
  if (b.staticVulnerabilities.length > 0) {
    const vulnLines = b.staticVulnerabilities.slice(0, 5).map(v => {
      const sev = v.severity === 'CRITICAL' ? pc.bgRed(pc.white(` ${v.severity} `)) : pc.yellow(`[${v.severity}]`);
      return `${sev} ${pc.bold(v.title)} (${v.file}:${v.line})\n  ${pc.gray(v.snippet)}`;
    }).join('\n\n');

    p.note(vulnLines, pc.red(`⚠️  VULNERABILIDADES ESTÁTICAS DETECTADAS (${b.staticVulnerabilities.length})`));
  } else {
    p.log.success(pc.green('✔ No se detectaron vulnerabilidades críticas en el escaneo estático de código.'));
  }

  // Recommendations
  if (b.recommendations.length > 0) {
    p.note(
      b.recommendations.map(r => `• ${r}`).join('\n'),
      '💡 RECOMENDACIONES DE MEJORA INMEDIATA'
    );
  }
}

async function handleInteractiveFullRun(s: ReturnType<typeof p.spinner>): Promise<void> {
  const config = loadConfig();

  const targetUrl = await p.text({
    message: 'Ingresa la URL Base del servidor a evaluar:',
    defaultValue: config.baseUrl,
    placeholder: 'http://localhost:3000',
  });
  if (p.isCancel(targetUrl)) return;
  config.baseUrl = targetUrl.replace(/\/+$/, '');

  const intensity = await p.select({
    message: 'Selecciona el perfil de intensidad para las pruebas de carga:',
    options: [
      { value: 'light', label: '🟢 Ligero', hint: 'Hasta 15 VUs, 5 segundos (Ideal para pruebas rápidas)' },
      { value: 'moderate', label: '🟡 Moderado (Recomendado)', hint: 'Ramp-up hasta 50 VUs, 10 segundos' },
      { value: 'heavy', label: '🔴 Intensivo / Stress', hint: 'Ramp-up hasta 100 VUs, saturación y detección de knee' },
    ],
  });
  if (p.isCancel(intensity)) return;

  if (intensity === 'light') {
    config.stress = {
      rampUpStages: [
        { durationSec: 2, targetVUs: 5 },
        { durationSec: 3, targetVUs: 15 },
      ],
      maxVUs: 15,
      thresholds: { p95LatencyMs: 300, p99LatencyMs: 600, maxErrorRatePercent: 1.0 },
    };
  } else if (intensity === 'moderate') {
    config.stress = {
      rampUpStages: [
        { durationSec: 2, targetVUs: 10 },
        { durationSec: 3, targetVUs: 30 },
        { durationSec: 3, targetVUs: 50 },
      ],
      maxVUs: 50,
      thresholds: { p95LatencyMs: 300, p99LatencyMs: 600, maxErrorRatePercent: 1.0 },
    };
  } else {
    config.stress = {
      rampUpStages: [
        { durationSec: 2, targetVUs: 15 },
        { durationSec: 4, targetVUs: 60 },
        { durationSec: 4, targetVUs: 100 },
      ],
      maxVUs: 100,
      thresholds: { p95LatencyMs: 400, p99LatencyMs: 800, maxErrorRatePercent: 2.0 },
    };
  }

  // Phase 1: Audit
  s.start(`[1/3] Ejecutando Auditoría Defensiva contra ${config.baseUrl}...`);
  const auditResults = await runDefensiveAudit(config);
  const score = calculateSecurityScore(auditResults);
  s.stop(`[1/3] Auditoría finalizada. Puntuación de Seguridad: ${score}/100`);

  // Phase 2: Stress
  s.start(`[2/3] Ejecutando Pruebas de Estrés y Medición de Percentiles...`);
  const stressSummaries: StressTestSummary[] = [];
  for (const ep of config.endpoints) {
    s.message(`Benchmarking [${ep.method} ${ep.path}] con ${config.stress.maxVUs} VUs...`);
    const summary = await runStressTestForEndpoint(config, ep);
    stressSummaries.push(summary);
  }
  s.stop(`[2/3] Pruebas de carga finalizadas en ${config.endpoints.length} endpoints.`);

  // Phase 3: Diagnose & Save Report
  s.start('[3/3] Diagnosticando cuellos de botella y generando reporte técnico...');
  const diagnostics = analyzeBottlenecksAndRisks(auditResults, stressSummaries);
  saveK6Script(config);
  saveArtilleryScript(config);

  const reportData: FullAuditReport = {
    timestamp: new Date().toISOString(),
    baseUrl: config.baseUrl,
    securityScore: score,
    auditResults,
    stressResults: stressSummaries,
    diagnostics,
    remediationCount: diagnostics.length,
  };

  const { mdPath, jsonPath } = saveReports(reportData, config.outputDir || './sentinel-reports');
  s.stop('¡Ciclo completo finalizado exitosamente!');

  // Display summary card
  const failedAudits = auditResults.filter(r => !r.passed);
  p.note(
    `${pc.bold('Puntuación de Seguridad:')} ${score}/100
${pc.bold('Verificaciones superadas:')} ${auditResults.length - failedAudits.length}/${auditResults.length}
${pc.bold('Acciones de Remediación Identificadas:')} ${diagnostics.length}
${pc.bold('Reporte Markdown:')} ${pc.cyan(mdPath)}
${pc.bold('Datos Telemetría JSON:')} ${pc.cyan(jsonPath)}
${pc.bold('Script de Reproducción Curl:')} ${pc.yellow('sentinel-reports/reproduce-audit.sh')}`,
    '📊 RESUMEN EJECUTIVO DEL CICLO'
  );

  await p.text({
    message: 'Presiona Enter para regresar al menú principal...',
    placeholder: '',
  });
}

async function handleInteractiveAudit(s: ReturnType<typeof p.spinner>): Promise<void> {
  const config = loadConfig();
  s.start(`Auditoria defensiva en ejecución contra ${config.baseUrl}...`);
  const results = await runDefensiveAudit(config);
  const score = calculateSecurityScore(results);
  s.stop('Auditoría defensiva completada.');

  const failed = results.filter(r => !r.passed);
  if (failed.length === 0) {
    p.log.success(pc.green(`✔ Todas las verificaciones defensivas fueron superadas (${score}/100)!`));
  } else {
    p.log.warn(pc.yellow(`Se encontraron ${failed.length} riesgos de seguridad (${score}/100):`));
    for (const f of failed.slice(0, 6)) {
      p.log.error(`[${f.severity}] ${f.title} en ${f.endpoint} -> ${f.evidence}`);
    }
  }

  await p.text({ message: 'Presiona Enter para continuar...', placeholder: '' });
}

async function handleInteractiveStress(s: ReturnType<typeof p.spinner>): Promise<void> {
  const config = loadConfig();
  s.start(`Ejecutando pruebas sintéticas de estrés en ${config.baseUrl}...`);
  const summaries: StressTestSummary[] = [];
  for (const ep of config.endpoints) {
    s.message(`Cargando endpoint ${ep.method} ${ep.path}...`);
    const sum = await runStressTestForEndpoint(config, ep);
    summaries.push(sum);
  }
  s.stop('Pruebas de estrés completadas.');

  for (const s of summaries) {
    p.note(
      `• Solicitudes Totales: ${s.totalRequests} | RPS: ${s.overallRps}
• Latencias: p50: ${s.overallLatencies.p50}ms | p95: ${s.overallLatencies.p95}ms | p99: ${s.overallLatencies.p99}ms
• Tasa de Error: ${s.errorRatePercent}%
• Rate Limiting: ${s.rateLimitEnforced ? pc.green('Activo (429 recibido)') : pc.yellow('No forzado')}`,
      `Rendimiento: ${s.endpoint}`
    );
  }

  await p.text({ message: 'Presiona Enter para continuar...', placeholder: '' });
}

async function handleExportScripts(): Promise<void> {
  const config = loadConfig();
  const k6Path = saveK6Script(config);
  const artPath = saveArtilleryScript(config);

  p.log.success(pc.green(`✔ Script k6 generado en: ${k6Path}`));
  p.log.success(pc.green(`✔ Script Artillery generado en: ${artPath}`));
  p.log.info(pc.dim(`Ejecuta: k6 run ${k6Path}`));
  p.log.info(pc.dim(`Ejecuta: npx artillery run ${artPath}`));

  await p.text({ message: 'Presiona Enter para continuar...', placeholder: '' });
}

async function handleConfigWizard(): Promise<void> {
  const config = loadConfig();

  const baseUrl = await p.text({
    message: 'Ingresa la URL Base por defecto:',
    defaultValue: config.baseUrl,
  });
  if (p.isCancel(baseUrl)) return;
  config.baseUrl = baseUrl;

  const userToken = await p.text({
    message: 'Token de prueba de usuario estándar (opcional):',
    defaultValue: config.auth?.userToken || '',
  });
  if (p.isCancel(userToken)) return;

  const adminToken = await p.text({
    message: 'Token de prueba de administrador (opcional):',
    defaultValue: config.auth?.adminToken || '',
  });
  if (p.isCancel(adminToken)) return;

  config.auth = {
    ...config.auth,
    userToken,
    adminToken,
  };

  const targetPath = path.resolve(process.cwd(), 'sentinel.config.json');
  fs.writeFileSync(targetPath, JSON.stringify(config, null, 2), 'utf-8');
  p.log.success(pc.green(`✔ Archivo ${targetPath} guardado correctamente.`));

  await p.text({ message: 'Presiona Enter para continuar...', placeholder: '' });
}
