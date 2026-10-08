import pc from 'picocolors';
import { AuditCheckResult, StressTestSummary, FullAuditReport } from '../types.js';

export function printBanner(): void {
  console.log(pc.cyan(`
 ╔══════════════════════════════════════════════════════════════════════╗
 ║      🛡️  SENTINEL-QA : DEFENSIVE AUDIT & STRESS TESTING SUITE        ║
 ║      Senior QA, Performance & Defensive Security Engineering         ║
 ╚══════════════════════════════════════════════════════════════════════╝
`));
}

export function printAuditSummary(results: AuditCheckResult[], score: number): void {
  console.log(pc.bold('\n─── [1/4] AUDITORÍA DEFENSIVA Y PRUEBAS DE INTEGRACIÓN ──────────────\n'));

  for (const r of results) {
    const icon = r.passed ? pc.green('✔ PASS') : pc.red(`✘ FAIL [${r.severity}]`);
    const endpointTag = pc.dim(`[${r.method} ${r.endpoint}]`);
    console.log(`${icon} ${endpointTag} ${r.title}`);
    if (!r.passed) {
      console.log(pc.gray(`       Evidence: ${r.evidence}`));
      if (r.reproduceCurl) {
        console.log(pc.yellow(`       Reproduce: ${r.reproduceCurl}`));
      }
    }
  }

  const scoreColor = score >= 80 ? pc.green : score >= 50 ? pc.yellow : pc.red;
  console.log(pc.bold(`\n  Defensive Security Score: ${scoreColor(`${score}/100`)}`));
}

export function printStressSummary(stressResults: StressTestSummary[]): void {
  console.log(pc.bold('\n─── [2/4] PRUEBAS DE CARGA Y RESILIENCIA (STRESS TESTING) ────────────\n'));

  for (const s of stressResults) {
    console.log(pc.cyan(`▶ Target: ${s.endpoint}`));
    console.log(`  Total Requests: ${pc.bold(s.totalRequests.toString())} | RPS: ${pc.bold(s.overallRps.toString())}`);
    console.log(`  Latencies: p50: ${s.overallLatencies.p50}ms | p90: ${s.overallLatencies.p90}ms | ${pc.magenta(`p95: ${s.overallLatencies.p95}ms`)} | ${pc.red(`p99: ${s.overallLatencies.p99}ms`)}`);
    console.log(`  Error Rate: ${s.errorRatePercent > 2 ? pc.red(`${s.errorRatePercent}%`) : pc.green(`${s.errorRatePercent}%`)} | Rate Limiting: ${s.rateLimitEnforced ? pc.green('Active (429 detected)') : pc.yellow('Not enforced')}`);
    
    if (s.saturationKneeVUs) {
      console.log(pc.yellow(`  ⚠ Saturation Knee Point: ~${s.saturationKneeVUs} concurrent VUs`));
    }
    console.log('');
  }
}

export function printReportPaths(mdPath: string, jsonPath: string): void {
  console.log(pc.bold('\n─── [4/4] REPORTE TÉCNICO DE CIERRE ─────────────────────────────────\n'));
  console.log(pc.green(`✔ Markdown Report: ${mdPath}`));
  console.log(pc.green(`✔ Raw JSON Data:   ${jsonPath}`));
  console.log(pc.cyan(`✔ Reproduction Script: sentinel-reports/reproduce-audit.sh`));
  console.log('\n───────────────────────────────────────────────────────────────────────\n');
}
