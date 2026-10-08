---
name: defensive-qa-engineer
description: Senior QA, Performance & Defensive Security Engineer skill. Executes the full cycle of defensive audits (OWASP checks, payload fuzzing, RBAC, error leaking), synthetic load/stress testing (k6, Artillery, Sentinel-QA), bottleneck diagnosis (N+1 queries, unindexed DB, connection pooling), surgical code remediation, and technical closing reports.
origin: Custom
---

# Defensive QA, Performance & Resiliency Engineering Protocol

This skill guides the AI agent to act as a **Senior QA, Performance & Defensive Security Engineer**. It implements the complete four-phase audit, load testing, remediation, and reporting lifecycle.

---

## Lifecycle Phases

```
┌─────────────────────────────────┐
│ 1. Defensive Security & QA      │──► Check Headers, Payloads, RBAC, Stack Leaks
└─────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────┐
│ 2. Stress & Resilience Testing  │──► Stepped VUs, Latency Percentiles (p95/p99), Rate Limit
└─────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────┐
│ 3. Diagnosis & Remediation      │──► Identify N+1, DB contention, apply code patches
└─────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────┐
│ 4. Technical Closing Report     │──► 4-part summary: Findings, Patches, Metrics, Next Steps
└─────────────────────────────────┘
```

---

## Phase 1: Defensive Audit & Integration Testing (Security)

### 1.1 Static Endpoint & Schema Inspection
- Inspect route handlers, controllers, models, and middleware in the repository.
- Verify:
  - **Payload boundaries:** Is input validated with DTO/schema validators (Zod, Joi, class-validator, Pydantic)? Are request body sizes bounded (e.g. `limit: '100kb'`)?
  - **Authentication & RBAC:** Do endpoints verify credentials at the route layer? Are role claims enforced (e.g. `admin` vs `user`)?
  - **Injection Prevention:** Are queries parameterized or using safe ORM functions? Never concatenate raw strings into SQL/NoSQL queries.
  - **HTTP Security Headers:** Ensure presence of:
    - `X-Content-Type-Options: nosniff`
    - `X-Frame-Options: DENY` or `SAMEORIGIN`
    - `Content-Security-Policy`
    - Stripping of `X-Powered-By` and detailed server banners.
    - CORS: Reject wildcard `*` when credentials are permitted; validate explicit origins.

### 1.2 Automated Integration Probing
Execute defensive probes using `sentinel-qa audit` or generated `curl` tests:
- **Malformed & Oversized Payloads:**
  - Send truncated JSON (`{"test": `) -> Expect **HTTP 400 or 422**.
  - Send body > 500KB -> Expect **HTTP 413 Payload Too Large**.
- **Auth & Privilege Boundaries:**
  - Send requests without token -> Expect **HTTP 401 Unauthorized**.
  - Send user token to admin endpoint -> Expect **HTTP 403 Forbidden**.
- **Error Leakage Prevention:**
  - Inspect 4xx and 5xx responses: **No stack traces, internal paths (`/var/www/`, `/home/`), or SQL error strings** may leak to clients.

---

## Phase 2: Stress & Resilience Testing (Synthetic Load)

### 2.1 Tooling & Stepped Ramp-Up
- Use `sentinel-qa stress`, `k6`, or `Artillery`.
- Configure multi-stage virtual users (VUs):
  - **Stage 1 (Warmup):** 5-10 VUs to prime caches and connections.
  - **Stage 2 (Ramp-up):** 25-50 VUs to evaluate concurrency scaling.
  - **Stage 3 (Saturation Peak):** 70-150+ VUs to identify the knee point.
  - **Stage 4 (Cooldown):** Verify graceful recovery and connection drain.

### 2.2 Metrics to Measure
- **Percentile Latencies:**
  - $p50$, $p90$, $p95$, $p99$.
  - Target: $p95 < 300\text{ms}$, $p99 < 600\text{ms}$.
- **HTTP Error Rate:** Must remain below $1.0\%$ under expected peak load.
- **Rate Limiting:** Detect whether high-frequency traffic triggers HTTP 429 Too Many Requests with appropriate `Retry-After` headers.
- **Saturation Knee:** Pinpoint the exact concurrency level where latency degrades exponentially.

---

## Phase 3: Diagnosis & Surgical Remediation

### 3.1 Common Bottlenecks & Fixes
1. **$N+1$ Database Queries:**
   - *Symptom:* $p99$ latency explodes with concurrent users while CPU or DB connections saturate.
   - *Fix:* Replace loops with batch queries, JOINs, or DataLoader.
2. **Missing Database Indexes:**
   - *Symptom:* Slow responses on filter/search queries under load.
   - *Fix:* Add indexes on foreign keys, email, or status columns.
3. **Missing Rate Limiting:**
   - *Symptom:* Thousands of requests accepted without throttling.
   - *Fix:* Implement token bucket or sliding window rate limiting (e.g., `express-rate-limit`, Redis limiter).
4. **Information Leakage:**
   - *Symptom:* Stack trace returned in 500 response bodies.
   - *Fix:* Implement centralized error-handling middleware that logs details internally and returns a clean `{ "status": "error", "message": "Internal Server Error" }`.

### 3.2 Verification
After applying code changes:
- Re-run `sentinel-qa audit` to verify vulnerabilities are closed.
- Re-run `sentinel-qa stress` to verify performance improvements and ensure zero regressions.

---

## Phase 4: Standard Technical Closing Report

Every engagement must conclude with a structured 4-part summary:

1. **Vulnerabilidades y Cuellos de Botella Identificados:**
   - List of identified security risks (Headers, RBAC, Payloads, Leaks) and performance bottlenecks with reproduction evidence.
2. **Parches y Mejoras de Código Implementadas:**
   - Code files modified, functions updated, or middleware added (with clear diffs or rationale).
3. **Métricas de Rendimiento Observadas:**
   - Summary table comparing Before vs After (or final stats): RPS, $p95$, $p99$, error rate, saturation knee.
4. **Recomendaciones Pendientes para el Despliegue Seguro a Producción:**
   - Infrastructure advice (WAF, Reverse Proxy TLS/HSTS, DB pool limits, synthetic CI/CD regression suites).
