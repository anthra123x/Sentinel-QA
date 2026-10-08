import fs from 'node:fs';
import path from 'node:path';
import { FullAuditReport } from '../types.js';

export function generateMarkdownReport(report: FullAuditReport): string {
  const failedAudits = report.auditResults.filter(r => !r.passed);
  const passedAudits = report.auditResults.filter(r => r.passed);

  const securityBadge = report.securityScore >= 80 ? '🟢 APROBADO' : report.securityScore >= 50 ? '🟡 ADVERTENCIA' : '🔴 CRÍTICO';

  let md = `# Reporte Técnico de Auditoría, Carga y Mitigación Defensiva

> **Generado por Sentinel-QA**  
> **Fecha:** ${report.timestamp}  
> **Objetivo:** \`${report.baseUrl}\`  
> **Puntuación de Seguridad Defensiva:** **${report.securityScore}/100** (${securityBadge})  
> **Total Verificaciones:** ${report.auditResults.length} (${passedAudits.length} superadas, ${failedAudits.length} fallidas)

---

## 1. Vulnerabilidades y Cuellos de Botella Identificados

${failedAudits.length === 0 ? '✅ **No se detectaron vulnerabilidades activas en las verificaciones ejecutadas.**' : ''}

`;

  if (failedAudits.length > 0) {
    md += `### Hallazgos de Seguridad e Integración Defensiva\n\n`;
    for (const item of failedAudits) {
      md += `#### [${item.severity}] ${item.title}\n`;
      md += `- **Endpoint:** \`${item.method} ${item.endpoint}\`\n`;
      md += `- **Categoría:** \`${item.category}\`\n`;
      md += `- **Descripción:** ${item.description}\n`;
      if (item.httpStatus) md += `- **Código HTTP Obtenido:** \`${item.httpStatus}\` (Esperado: \`${item.expectedStatus || '4xx controlado'}\`)\n`;
      if (item.evidence) md += `- **Evidencia:** \`${item.evidence}\`\n`;
      if (item.reproduceCurl) {
        md += `\n**Comando de reproducción (\`curl\`):**\n\`\`\`bash\n${item.reproduceCurl}\n\`\`\`\n`;
      }
      md += `\n`;
    }
  }

  if (report.stressResults && report.stressResults.length > 0) {
    md += `### Cuellos de Botella de Rendimiento y Resiliencia\n\n`;
    for (const stress of report.stressResults) {
      if (stress.saturationKneeVUs || stress.errorRatePercent > 2 || !stress.rateLimitEnforced) {
        md += `- **Endpoint:** \`${stress.endpoint}\`\n`;
        if (stress.saturationKneeVUs) {
          md += `  - ⚠️ **Umbral de Saturación Detectado:** Degradación severa a partir de **${stress.saturationKneeVUs} Usuarios Virtuales (VUs)**.\n`;
        }
        if (!stress.rateLimitEnforced) {
          md += `  - ⚠️ **Ausencia de Rate Limiting:** No se detectó código HTTP 429 durante el tráfico concurrente (${stress.totalRequests} peticiones).\n`;
        }
        if (stress.errorRatePercent > 2) {
          md += `  - 🚨 **Tasa de Errores Crítica:** ${stress.errorRatePercent}% de solicitudes fallidas bajo estrés.\n`;
        }
        md += `\n`;
      }
    }
  }

  md += `---

## 2. Parches y Mejoras de Código Implementadas y Recomendadas

A continuación se detallan las remediaciones técnicas para mitigar las fallas y cuellos de botella detectados:

`;

  if (report.diagnostics.length === 0) {
    md += `No se requieren parches urgentes. Los controles actuales cumplen con los estándares defensivos establecidos.\n\n`;
  } else {
    for (const diag of report.diagnostics) {
      md += `### [${diag.severity}] ${diag.title}\n`;
      md += `- **Impacto:** ${diag.impact}\n`;
      md += `- **Causa Raíz:** ${diag.rootCause}\n\n`;
      md += `**Solución / Parche Recomendado:**\n\`\`\`typescript\n${diag.remediationCode}\n\`\`\`\n\n`;
    }
  }

  md += `---

## 3. Métricas de Rendimiento Observadas

`;

  if (!report.stressResults || report.stressResults.length === 0) {
    md += `*No se ejecutaron pruebas de estrés en esta sesión.*  \n*(Utilice \`sentinel-qa stress\` o \`sentinel-qa run\` para incluirlas).*\n\n`;
  } else {
    md += `### Resumen General por Endpoint\n\n`;
    md += `| Endpoint | Solicitudes | RPS Global | p50 (ms) | p90 (ms) | p95 (ms) | p99 (ms) | Error % | Rate Limit Activo |\n`;
    md += `| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |\n`;

    for (const s of report.stressResults) {
      md += `| \`${s.endpoint}\` | ${s.totalRequests} | ${s.overallRps} | ${s.overallLatencies.p50} | ${s.overallLatencies.p90} | **${s.overallLatencies.p95}** | **${s.overallLatencies.p99}** | ${s.errorRatePercent}% | ${s.rateLimitEnforced ? '✅ Sí (429)' : '❌ No'} |\n`;
    }

    md += `\n### Desglose Escalonado de Carga (Ramp-up por Etapas)\n\n`;
    for (const s of report.stressResults) {
      md += `#### Detalle: \`${s.endpoint}\`\n\n`;
      md += `| Etapa (VUs) | Duración | Solicitudes | RPS | p50 (ms) | p95 (ms) | p99 (ms) | Fallos | Rate Limited (429) |\n`;
      md += `| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |\n`;
      for (const st of s.stages) {
        md += `| **${st.vus} VUs** | ${st.durationSec}s | ${st.totalRequests} | ${st.rps} | ${st.latencies.p50} | ${st.latencies.p95} | ${st.latencies.p99} | ${st.failedRequests} | ${st.rateLimitedRequests} |\n`;
      }
      md += `\n`;
    }
  }

  md += `---

## 4. Recomendaciones Pendientes para el Despliegue Seguro a Producción

Para garantizar resiliencia, alta disponibilidad y cumplimiento estricto con los estándares de seguridad (OWASP Top 10):

1. **Defensa en Profundidad en Reverse Proxy / Ingress:**
   - Implementar limitación de tasa basada en IP/token (\`Rate Limiting\` y \`Burst Protection\`) en el nivel de NGINX, Cloudflare o Envoy.
   - Forzar TLS 1.3 con HSTS estricto (\`max-age=63072000; includeSubDomains; preload\`).
2. **Hardening de Modelos y Capa de Datos:**
   - Asegurar que todas las consultas a base de datos utilicen sentencias preparadas o consultas indexadas para evitar problemas de N+1 bajo concurrencia.
   - Definir un límite estricto de conexiones en el pool de la base de datos (\`max_connections\`, \`idleTimeout\`).
3. **Manejo Defensivo de Errores y Logging Seguro:**
   - Garantizar que en producción la variable \`NODE_ENV=production\` desactive por completo la emisión de stack traces hacia el cliente HTTP.
   - Sanitizar logs para no almacenar tokens JWT, credenciales ni información de identificación personal (PII).
4. **Monitoreo Continuo y Pruebas Sintéticas de Regresión:**
   - Integrar los scripts generados (\`k6-stress-test.js\` o \`artillery-stress-test.yml\`) en la canalización CI/CD para validar que las métricas de percentil p95 < 300ms no se degraden en futuros despliegues.
   - Emplear el script generado \`reproduce-audit.sh\` como suite de validación defensiva automática previa a cada merge.

---
*Reporte generado automáticamente por Sentinel-QA CLI Suite.*
`;

  return md;
}

export function saveReports(report: FullAuditReport, outputDir: string): { mdPath: string; jsonPath: string } {
  const dir = path.resolve(process.cwd(), outputDir);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }

  const mdContent = generateMarkdownReport(report);
  const mdPath = path.join(dir, 'AUDIT_REPORT.md');
  fs.writeFileSync(mdPath, mdContent, 'utf-8');

  const jsonPath = path.join(dir, 'audit-report.json');
  fs.writeFileSync(jsonPath, JSON.stringify(report, null, 2), 'utf-8');

  return { mdPath, jsonPath };
}
