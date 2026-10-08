import fs from 'node:fs';
import path from 'node:path';
import { SentinelConfig, AuditCheckResult, FullAuditReport } from '../types.js';
import { auditSecurityHeaders } from './header-auditor.js';
import { auditPayloads } from './payload-auditor.js';
import { auditRbacAndAuth } from './rbac-auditor.js';

export async function runDefensiveAudit(config: SentinelConfig): Promise<AuditCheckResult[]> {
  const allResults: AuditCheckResult[] = [];

  for (const endpoint of config.endpoints) {
    // 1. Audit Headers
    const headerResults = await auditSecurityHeaders(config, endpoint);
    allResults.push(...headerResults);

    // 2. Audit Payloads & Injections
    const payloadResults = await auditPayloads(config, endpoint);
    allResults.push(...payloadResults);

    // 3. Audit RBAC & Auth
    const rbacResults = await auditRbacAndAuth(config, endpoint);
    allResults.push(...rbacResults);
  }

  // Generate reproduction bash script if there are failed checks
  generateReproductionScript(config, allResults);

  return allResults;
}

export function calculateSecurityScore(results: AuditCheckResult[]): number {
  if (results.length === 0) return 100;

  const weights: Record<string, number> = {
    CRITICAL: 25,
    HIGH: 15,
    MEDIUM: 7,
    LOW: 3,
    INFO: 0,
  };

  let totalDeduction = 0;
  for (const r of results) {
    if (!r.passed) {
      totalDeduction += weights[r.severity] || 5;
    }
  }

  return Math.max(0, Math.min(100, 100 - totalDeduction));
}

function generateReproductionScript(config: SentinelConfig, results: AuditCheckResult[]): void {
  const failedResults = results.filter((r) => !r.passed && r.reproduceCurl);
  if (failedResults.length === 0) return;

  const outputDir = path.resolve(process.cwd(), config.outputDir || './sentinel-reports');
  if (!fs.existsSync(outputDir)) {
    fs.mkdirSync(outputDir, { recursive: true });
  }

  const lines: string[] = [
    '#!/usr/bin/env bash',
    '# ==============================================================================',
    '# Sentinel-QA: Reproduction Script for Identified Security & Defensive Flaws',
    `# Target: ${config.baseUrl}`,
    `# Generated at: ${new Date().toISOString()}`,
    '# ==============================================================================',
    'set -euo pipefail',
    '',
    'echo "=== Running Sentinel Defensive Reproductions ==="',
    '',
  ];

  for (const check of failedResults) {
    lines.push(`# [${check.severity}] ${check.title}`);
    lines.push(`# Expected: ${check.expectedStatus || 'Proper defensive response'}`);
    lines.push(`echo "-> Testing: [${check.method}] ${check.endpoint} (${check.title})"`);
    lines.push(`${check.reproduceCurl} || true`);
    lines.push('echo ""');
    lines.push('echo "---------------------------------------------------------"');
    lines.push('');
  }

  const scriptPath = path.join(outputDir, 'reproduce-audit.sh');
  fs.writeFileSync(scriptPath, lines.join('\n'), { mode: 0o755 });
}
