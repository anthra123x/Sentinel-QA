import fs from 'node:fs';
import path from 'node:path';
import { Command } from 'commander';
import pc from 'picocolors';
import { loadConfig, generateSampleConfigJson } from './config.js';
import { runDefensiveAudit, calculateSecurityScore } from './audit/index.js';
import { runStressTestForEndpoint } from './stress/load-engine.js';
import { saveK6Script } from './stress/k6-generator.js';
import { saveArtilleryScript } from './stress/artillery-generator.js';
import { analyzeBottlenecksAndRisks } from './diagnose/bottleneck-analyzer.js';
import { saveReports } from './report/markdown-reporter.js';
import { printBanner, printAuditSummary, printStressSummary, printReportPaths } from './report/console-reporter.js';
import { FullAuditReport, StressTestSummary } from './types.js';

const program = new Command();

program
  .name('sentinel-qa')
  .description('Defensive QA, Performance Resilience & Security Auditing Suite')
  .version('1.0.0');

// Subcommand: init
program
  .command('init')
  .description('Scaffold a default sentinel.config.json in the current working directory')
  .action(() => {
    const target = path.resolve(process.cwd(), 'sentinel.config.json');
    if (fs.existsSync(target)) {
      console.log(pc.yellow(`File sentinel.config.json already exists at ${target}`));
      return;
    }
    fs.writeFileSync(target, generateSampleConfigJson(), 'utf-8');
    console.log(pc.green(`✔ Created starter configuration file at: ${target}`));
  });

// Subcommand: audit
program
  .command('audit')
  .description('Run defensive security and integration audit against target endpoints')
  .option('-u, --url <url>', 'Target base URL (e.g. http://localhost:3000)')
  .option('-c, --config <path>', 'Path to sentinel.config.json')
  .option('-o, --output <dir>', 'Output directory for reports')
  .action(async (options) => {
    printBanner();
    const config = loadConfig(options.config, { baseUrl: options.url, outputDir: options.output });
    console.log(pc.cyan(`Target Base URL: ${config.baseUrl}`));
    console.log(pc.dim(`Auditing ${config.endpoints.length} configured endpoints...\n`));

    const auditResults = await runDefensiveAudit(config);
    const score = calculateSecurityScore(auditResults);
    printAuditSummary(auditResults, score);

    const diagnostics = analyzeBottlenecksAndRisks(auditResults);
    const reportData: FullAuditReport = {
      timestamp: new Date().toISOString(),
      baseUrl: config.baseUrl,
      securityScore: score,
      auditResults,
      diagnostics,
      remediationCount: diagnostics.length,
    };

    const { mdPath, jsonPath } = saveReports(reportData, config.outputDir || './sentinel-reports');
    printReportPaths(mdPath, jsonPath);
  });

// Subcommand: stress
program
  .command('stress')
  .description('Execute synthetic stress and concurrency ramp-up tests')
  .option('-u, --url <url>', 'Target base URL')
  .option('-c, --config <path>', 'Path to sentinel.config.json')
  .option('-o, --output <dir>', 'Output directory for reports')
  .action(async (options) => {
    printBanner();
    const config = loadConfig(options.config, { baseUrl: options.url, outputDir: options.output });
    console.log(pc.cyan(`Running load testing against: ${config.baseUrl}`));

    const stressSummaries: StressTestSummary[] = [];
    for (const ep of config.endpoints) {
      console.log(pc.yellow(`\nBenchmarking endpoint: ${ep.method} ${ep.path}...`));
      const summary = await runStressTestForEndpoint(config, ep, (current, total, stage) => {
        console.log(`  [Stage ${current}/${total}] ${stage.vus} VUs | RPS: ${stage.rps} | p95: ${stage.latencies.p95}ms | p99: ${stage.latencies.p99}ms | 429s: ${stage.rateLimitedRequests}`);
      });
      stressSummaries.push(summary);
    }

    printStressSummary(stressSummaries);

    const diagnostics = analyzeBottlenecksAndRisks([], stressSummaries);
    const reportData: FullAuditReport = {
      timestamp: new Date().toISOString(),
      baseUrl: config.baseUrl,
      securityScore: 100,
      auditResults: [],
      stressResults: stressSummaries,
      diagnostics,
      remediationCount: diagnostics.length,
    };

    const { mdPath, jsonPath } = saveReports(reportData, config.outputDir || './sentinel-reports');
    printReportPaths(mdPath, jsonPath);
  });

// Subcommand: k6
program
  .command('k6')
  .description('Generate production-ready k6 stress test script')
  .option('-c, --config <path>', 'Path to sentinel.config.json')
  .option('-o, --output <path>', 'Output file path')
  .action((options) => {
    const config = loadConfig(options.config);
    const savedPath = saveK6Script(config, options.output);
    console.log(pc.green(`✔ Generated k6 script at: ${savedPath}`));
    console.log(pc.cyan(`  Run with: k6 run ${savedPath}`));
  });

// Subcommand: artillery
program
  .command('artillery')
  .description('Generate production-ready Artillery load test script')
  .option('-c, --config <path>', 'Path to sentinel.config.json')
  .option('-o, --output <path>', 'Output file path')
  .action((options) => {
    const config = loadConfig(options.config);
    const savedPath = saveArtilleryScript(config, options.output);
    console.log(pc.green(`✔ Generated Artillery script at: ${savedPath}`));
    console.log(pc.cyan(`  Run with: npx artillery run ${savedPath}`));
  });

// Subcommand: run (Full Cycle)
program
  .command('run')
  .description('Execute full lifecycle: Defensive Audit -> Stress Test -> Remediation Diagnosis -> Technical Report')
  .option('-u, --url <url>', 'Target base URL (e.g. http://localhost:3000)')
  .option('-c, --config <path>', 'Path to sentinel.config.json')
  .option('-o, --output <dir>', 'Output directory for reports')
  .action(async (options) => {
    printBanner();
    const config = loadConfig(options.config, { baseUrl: options.url, outputDir: options.output });
    console.log(pc.cyan(`Target Base URL: ${config.baseUrl}`));
    console.log(pc.dim(`Auditing ${config.endpoints.length} configured endpoints...\n`));

    // Phase 1: Defensive Security Audit
    const auditResults = await runDefensiveAudit(config);
    const score = calculateSecurityScore(auditResults);
    printAuditSummary(auditResults, score);

    // Phase 2: Stress Testing
    console.log(pc.bold('\n─── [2/4] PRUEBAS DE CARGA Y RESILIENCIA (STRESS TESTING) ────────────\n'));
    const stressSummaries: StressTestSummary[] = [];
    for (const ep of config.endpoints) {
      console.log(pc.yellow(`Benchmarking endpoint: ${ep.method} ${ep.path}...`));
      const summary = await runStressTestForEndpoint(config, ep, (current, total, stage) => {
        console.log(`  [Stage ${current}/${total}] ${stage.vus} VUs | RPS: ${stage.rps} | p95: ${stage.latencies.p95}ms | p99: ${stage.latencies.p99}ms | 429s: ${stage.rateLimitedRequests}`);
      });
      stressSummaries.push(summary);
    }
    printStressSummary(stressSummaries);

    // Phase 3: Diagnostics & Remediation
    console.log(pc.bold('─── [3/4] DIAGNÓSTICO Y REMEDIACIÓN ─────────────────────────────────\n'));
    const diagnostics = analyzeBottlenecksAndRisks(auditResults, stressSummaries);
    console.log(pc.magenta(`Identificadas ${diagnostics.length} acciones de remediación y endurecimiento:`));
    for (const d of diagnostics) {
      console.log(`  - [${d.severity}] ${pc.bold(d.title)}`);
      console.log(pc.gray(`    ${d.impact}`));
    }

    // Also export k6 & artillery scripts
    saveK6Script(config);
    saveArtilleryScript(config);

    // Phase 4: Full Report
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
    printReportPaths(mdPath, jsonPath);
  });

program.parse(process.argv);
