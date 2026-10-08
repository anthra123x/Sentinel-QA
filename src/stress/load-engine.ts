import http from 'node:http';
import https from 'node:https';
import { performance } from 'node:perf_hooks';
import { SentinelConfig, EndpointDefinition, StressStageResult, StressTestSummary, LatencyStats } from '../types.js';

export function calculatePercentiles(latencies: number[]): LatencyStats {
  if (latencies.length === 0) {
    return { min: 0, max: 0, mean: 0, p50: 0, p90: 0, p95: 0, p99: 0 };
  }

  const sorted = [...latencies].sort((a, b) => a - b);
  const total = sorted.length;
  const sum = sorted.reduce((acc, val) => acc + val, 0);

  const getPercentile = (p: number) => {
    const idx = Math.min(Math.floor((p / 100) * total), total - 1);
    return Math.round(sorted[idx] * 100) / 100;
  };

  return {
    min: Math.round(sorted[0] * 100) / 100,
    max: Math.round(sorted[total - 1] * 100) / 100,
    mean: Math.round((sum / total) * 100) / 100,
    p50: getPercentile(50),
    p90: getPercentile(90),
    p95: getPercentile(95),
    p99: getPercentile(99),
  };
}

export async function runStressTestForEndpoint(
  config: SentinelConfig,
  endpoint: EndpointDefinition,
  onProgress?: (stageIndex: number, totalStages: number, stage: StressStageResult) => void
): Promise<StressTestSummary> {
  const fullUrl = `${config.baseUrl}${endpoint.path}`;
  const stagesConfig = config.stress?.rampUpStages || [
    { durationSec: 2, targetVUs: 5 },
    { durationSec: 3, targetVUs: 20 },
    { durationSec: 3, targetVUs: 50 },
  ];

  const stageResults: StressStageResult[] = [];
  const allLatencies: number[] = [];
  let totalRequestsAll = 0;
  let rateLimitedCount = 0;
  let baselineP95 = 0;
  let saturationKneeVUs: number | undefined;

  for (let sIdx = 0; sIdx < stagesConfig.length; sIdx++) {
    const stageConf = stagesConfig[sIdx];
    const stageResult = await executeStage(config, endpoint, fullUrl, stageConf.targetVUs, stageConf.durationSec);
    
    stageResults.push(stageResult);
    allLatencies.push(...stageResult.latenciesArray);
    totalRequestsAll += stageResult.totalRequests;
    rateLimitedCount += stageResult.rateLimitedRequests;

    if (sIdx === 0) {
      baselineP95 = stageResult.latencies.p95;
    } else if (!saturationKneeVUs && baselineP95 > 0) {
      // If p95 is more than 3x baseline or error rate > 5%, we reached the saturation knee
      if (stageResult.latencies.p95 > baselineP95 * 3 || (stageResult.failedRequests / stageResult.totalRequests) > 0.05) {
        saturationKneeVUs = stageConf.targetVUs;
      }
    }

    if (onProgress) {
      onProgress(sIdx + 1, stagesConfig.length, stageResult);
    }
  }

  const overallLatencies = calculatePercentiles(allLatencies);
  const totalDurationSec = stagesConfig.reduce((acc, s) => acc + s.durationSec, 0);
  const overallRps = totalDurationSec > 0 ? Math.round((totalRequestsAll / totalDurationSec) * 10) / 10 : 0;
  
  const totalFailed = stageResults.reduce((acc, s) => acc + s.failedRequests, 0);
  const errorRatePercent = totalRequestsAll > 0 ? Math.round((totalFailed / totalRequestsAll) * 1000) / 10 : 0;

  return {
    endpoint: `${endpoint.method} ${endpoint.path}`,
    totalRequests: totalRequestsAll,
    overallRps,
    overallLatencies,
    stages: stageResults,
    errorRatePercent,
    rateLimitEnforced: rateLimitedCount > 0,
    saturationKneeVUs,
  };
}

interface InternalStageResult extends StressStageResult {
  latenciesArray: number[];
}

async function executeStage(
  config: SentinelConfig,
  endpoint: EndpointDefinition,
  fullUrl: string,
  vus: number,
  durationSec: number
): Promise<InternalStageResult> {
  const urlObj = new URL(fullUrl);
  const isHttps = urlObj.protocol === 'https:';
  const httpAgent = isHttps
    ? new https.Agent({ keepAlive: true, maxSockets: vus * 2 })
    : new http.Agent({ keepAlive: true, maxSockets: vus * 2 });

  const headers: Record<string, string> = {
    'User-Agent': 'Sentinel-QA-Stress/1.0',
    ...(endpoint.sampleHeaders || {}),
  };

  if (endpoint.authRequired && config.auth?.userToken) {
    const headerName = config.auth.authHeader || 'Authorization';
    const prefix = config.auth.tokenPrefix || 'Bearer ';
    headers[headerName] = `${prefix}${config.auth.userToken}`;
  }

  if (endpoint.sampleBody && ['POST', 'PUT', 'PATCH'].includes(endpoint.method)) {
    headers['Content-Type'] = 'application/json';
  }

  const bodyData = endpoint.sampleBody && ['POST', 'PUT', 'PATCH'].includes(endpoint.method)
    ? JSON.stringify(endpoint.sampleBody)
    : undefined;

  const endTime = Date.now() + durationSec * 1000;
  const latencies: number[] = [];
  let successfulRequests = 0;
  let failedRequests = 0;
  let rateLimitedRequests = 0;

  // Worker loop per virtual user
  const worker = async () => {
    while (Date.now() < endTime) {
      const start = performance.now();
      try {
        const res = await sendRawRequest({
          urlObj,
          method: endpoint.method,
          headers,
          body: bodyData,
          agent: httpAgent,
          timeoutMs: config.stress?.requestTimeoutMs || 5000,
        });

        const elapsed = performance.now() - start;
        latencies.push(elapsed);

        if (res.statusCode === 429) {
          rateLimitedRequests++;
          successfulRequests++; // Treated as defended rate limiting
        } else if (res.statusCode >= 200 && res.statusCode < 400) {
          successfulRequests++;
        } else if (res.statusCode >= 400 && res.statusCode < 500) {
          successfulRequests++; // Client rejection
        } else {
          failedRequests++; // 5xx or server crash
        }
      } catch (err) {
        const elapsed = performance.now() - start;
        latencies.push(elapsed);
        failedRequests++;
      }
    }
  };

  const workers = Array.from({ length: vus }, () => worker());
  await Promise.all(workers);

  httpAgent.destroy();

  const totalRequests = latencies.length;
  const rps = durationSec > 0 ? Math.round((totalRequests / durationSec) * 10) / 10 : 0;
  const latencyStats = calculatePercentiles(latencies);

  return {
    vus,
    durationSec,
    totalRequests,
    successfulRequests,
    failedRequests,
    rateLimitedRequests,
    rps,
    latencies: latencyStats,
    latenciesArray: latencies,
  };
}

interface RawRequestParams {
  urlObj: URL;
  method: string;
  headers: Record<string, string>;
  body?: string;
  agent: http.Agent | https.Agent;
  timeoutMs: number;
}

function sendRawRequest(params: RawRequestParams): Promise<{ statusCode: number; headers: http.IncomingHttpHeaders }> {
  return new Promise((resolve, reject) => {
    const isHttps = params.urlObj.protocol === 'https:';
    const requester = isHttps ? https.request : http.request;

    const req = requester(
      params.urlObj,
      {
        method: params.method,
        headers: params.headers,
        agent: params.agent,
        timeout: params.timeoutMs,
      },
      (res: http.IncomingMessage) => {
        // Drain response data stream to avoid backpressure
        res.on('data', () => {});
        res.on('end', () => {
          resolve({
            statusCode: res.statusCode || 0,
            headers: res.headers,
          });
        });
      }
    );

    req.on('timeout', () => {
      req.destroy(new Error('Request timeout'));
    });

    req.on('error', (err: Error) => {
      reject(err);
    });

    if (params.body) {
      req.write(params.body);
    }

    req.end();
  });
}
