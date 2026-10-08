# 🛡️ Sentinel-QA

<div align="center">

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Node.js](https://img.shields.io/badge/node-%3E%3D18.0.0-green.svg)
![TypeScript](https://img.shields.io/badge/typescript-5.8-blue.svg)
![Security](https://img.shields.io/badge/OWASP-Top%2010%20Compliant-red.svg)
![Load Testing](https://img.shields.io/badge/k6%20%26%20Artillery-Supported-orange.svg)

**La suite definitiva de Auditoría Defensiva, Pruebas de Carga Sintéticas y Mitigación de Vulnerabilidades para APIs.**  
*Diseñada para ingenieros de QA, DevSecOps y arquitectos de backend.*

[Características](#-características) •
[Instalación](#-instalación) •
[Uso Rápido](#-uso-rápido) •
[Comandos CLI](#-comandos-cli) •
[Configuración](#-archivo-de-configuración) •
[Habilidad de IA](#-habilidad-de-agente-ia-defensive-qa-engineer) •
[CI/CD](#-integración-en-cicd)

</div>

---

## 📋 Descripción General

**Sentinel-QA** automatiza el ciclo de vida completo de verificación de seguridad defensiva y resiliencia para cualquier API HTTP/REST. Combina análisis de cabeceras OWASP, pruebas de frontera y *fuzzing* de payloads, verificación estricta de RBAC, detección de fugas de información interna y pruebas sintéticas de estrés concurrentes con ramp-up de usuarios virtuales.

Además de diagnosticar fallas y cuellos de botella (como consultas $N+1$ o ausencia de limitadores de tasa), Sentinel-QA genera parches correctivos inmediatos, scripts de reproducción en `curl` y scripts de carga exportables en **k6** y **Artillery**.

---

## ⚡ Flujo de Trabajo en 4 Fases

```
┌────────────────────────────────────────────────────────┐
│ 1. Auditoría Defensiva & Integración                   │
│    • Cabeceras OWASP (CSP, HSTS, X-Content-Type)       │
│    • Payloads malformados y Body Bombs (>100KB)        │
│    • Control RBAC (401 Anónimo / 403 No privilegiado)  │
│    • Detección de fugas (Stack traces en 500)          │
└──────────────────────────┬─────────────────────────────┘
                           │
                           ▼
┌────────────────────────────────────────────────────────┐
│ 2. Pruebas de Carga & Resiliencia (Stress Testing)     │
│    • Motor HTTP nativo ultrarrápido (>9,000 req/s)     │
│    • Ramp-up escalonado de VUs (Warmup -> Peak)        │
│    • Percentiles de latencia (p50, p90, p95, p99)      │
│    • Detección del codo de saturación & Rate Limiting  │
└──────────────────────────┬─────────────────────────────┘
                           │
                           ▼
┌────────────────────────────────────────────────────────┐
│ 3. Diagnóstico y Remediación Automática                │
│    • Detección de consultas lentas y problemas N+1     │
│    • Sugerencias de código listas para producción      │
│    • Configuración de rate limits, índices y cabeceras │
└──────────────────────────┬─────────────────────────────┘
                           │
                           ▼
┌────────────────────────────────────────────────────────┐
│ 4. Reporte Técnico de Cierre & Artefactos              │
│    • AUDIT_REPORT.md & audit-report.json               │
│    • Script Bash de reproducción: reproduce-audit.sh   │
│    • Scripts de carga: k6-stress-test.js & Artillery   │
└────────────────────────────────────────────────────────┘
```

---

## ✨ Características

- 🔒 **Inspección de Seguridad Estricta:**
  - Verifica cabeceras críticas: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Content-Security-Policy` y `Referrer-Policy`.
  - Asegura que `X-Powered-By` y firmas de servidores estén deshabilitadas.
  - Audita configuraciones CORS inseguras (como orígenes reflejados arbitrarios o comodines `*` con credenciales).
- 💥 **Pruebas de Frontera & Payloads:**
  - Evalúa la resiliencia ante JSON malformado (debe devolver 400/422 controlado sin excepciones no capturadas).
  - Simula ataques DoS por tamaño (*body bombs* > 600KB) para comprobar límites `413 Payload Too Large`.
  - Prueba de inyecciones SQL/NoSQL básicas para verificar que las entradas no expongan errores de controladores de base de datos.
- 🛡️ **Verificación de Control de Acceso (RBAC):**
  - Confirma que endpoints protegidos devuelvan **HTTP 401 Unauthorized** ante llamadas sin credenciales o con tokens inválidos.
  - Verifica que cuentas de usuario estándar reciban **HTTP 403 Forbidden** al invocar rutas reservadas para administradores.
- 🕵️ **Detector de Fugas de Información:**
  - Escanea respuestas de error buscando volcados de memoria, *stack traces* (Node.js V8, Python Tracebacks, Java, PHP), rutas del sistema de archivos (`/home/`, `/var/www/`) y consultas SQL crudas.
- 🚀 **Motor de Estrés Nativo y Sin Dependencias Externas:**
  - Ejecuta pruebas de alta concurrencia usando sockets HTTP con `keep-alive` capaces de generar decenas de miles de peticiones por segundo en local o staging.
  - Calcula estadísticas completas: min, max, media, p50, p90, p95 y p99.
  - Verifica si el backend activa correctamente respuestas **HTTP 429 Too Many Requests** con cabeceras `Retry-After`.
- 📊 **Exportadores a Estándares de la Industria:**
  - Genera automáticamente scripts de prueba para **k6** (`k6-stress-test.js`) y **Artillery** (`artillery-stress-test.yml`).

---

## 📦 Instalación

### Requisitos Previos
- **Node.js** >= 18.0.0
- **npm** o **bun**

### Clonar e Instalar
```bash
git clone https://github.com/anthra123x/Sentinel-QA.git
cd Sentinel-QA
npm install
npm run build
```

Opcionalmente, enlaza el binario globalmente:
```bash
npm link
# Ahora puedes ejecutar `sentinel-qa` directamente desde cualquier directorio
```

---

## 🚀 Uso Rápido

### 1. Modo Interactivo (Asistente Visual)
Simplemente ejecuta `sentinel-qa` sin argumentos (o `sentinel-qa interactive`) para abrir el asistente interactivo con menús, spinners animados y asistentes de configuración:
```bash
sentinel-qa
```

### 2. Desglose Absoluto del Proyecto (Auto-Discovery & SAST)
Escanea el backend actual, detecta el framework, mapea todos los endpoints y analiza vulnerabilidades estáticas en código fuente:
```bash
sentinel-qa scan
```

### 3. Ejecutar el Ciclo Completo Directo (Auditoría + Estrés + Diagnóstico + Reporte)
```bash
sentinel-qa run --url http://localhost:3000
```

### 4. Ejecutar solo la Auditoría de Seguridad e Integración
```bash
sentinel-qa audit --url http://localhost:3000
```

### 5. Ejecutar solo las Pruebas de Carga
```bash
sentinel-qa stress --url http://localhost:3000
```

### 6. Generar Scripts para k6 o Artillery
```bash
sentinel-qa k6
# Ejecutar con k6:
k6 run sentinel-reports/k6-stress-test.js

sentinel-qa artillery
# Ejecutar con Artillery:
npx artillery run sentinel-reports/artillery-stress-test.yml
```

---

## 📖 Comandos CLI

| Comando | Descripción | Opciones principales |
| :--- | :--- | :--- |
| `sentinel-qa` | **Modo Interactivo por defecto**: Menús visuales, escaneo y wizards | N/A |
| `sentinel-qa interactive` (o `ui`) | Lanza el asistente interactivo en la terminal | N/A |
| `sentinel-qa scan` | **Desglose absoluto del proyecto**: Stack, endpoints, SAST y recomendaciones | N/A |
| `sentinel-qa run` | Ejecuta el ciclo integral (Auditoría + Estrés + Parches + Reporte) | `-u, --url <url>`, `-c, --config <file>`, `-o, --output <dir>` |
| `sentinel-qa audit` | Ejecuta únicamente las verificaciones defensivas y de seguridad | `-u, --url <url>`, `-c, --config <file>`, `-o, --output <dir>` |
| `sentinel-qa stress` | Ejecuta pruebas sintéticas de concurrencia y percentiles | `-u, --url <url>`, `-c, --config <file>`, `-o, --output <dir>` |
| `sentinel-qa k6` | Genera el script de estrés para **k6** con umbrales configurados | `-c, --config <file>`, `-o, --output <file>` |
| `sentinel-qa artillery` | Genera la especificación de carga para **Artillery** | `-c, --config <file>`, `-o, --output <file>` |
| `sentinel-qa init` | Crea un archivo `sentinel.config.json` inicial | N/A |

---

## ⚙️ Archivo de Configuración (`sentinel.config.json`)

Puedes configurar en detalle los endpoints a probar, credenciales de prueba y parámetros de estrés:

```json
{
  "baseUrl": "http://localhost:3000",
  "endpoints": [
    {
      "path": "/api/health",
      "method": "GET",
      "authRequired": false,
      "expectedSuccessStatus": 200
    },
    {
      "path": "/api/users",
      "method": "GET",
      "authRequired": true,
      "requiredRole": "user"
    },
    {
      "path": "/api/users",
      "method": "POST",
      "authRequired": true,
      "requiredRole": "user",
      "sampleBody": {
        "name": "Jane Doe",
        "email": "jane@example.com"
      }
    },
    {
      "path": "/api/admin/metrics",
      "method": "GET",
      "authRequired": true,
      "requiredRole": "admin"
    }
  ],
  "auth": {
    "userToken": "user-jwt-or-bearer-token",
    "adminToken": "admin-jwt-or-bearer-token",
    "authHeader": "Authorization",
    "tokenPrefix": "Bearer "
  },
  "stress": {
    "durationSec": 15,
    "rampUpStages": [
      { "durationSec": 3, "targetVUs": 10 },
      { "durationSec": 5, "targetVUs": 30 },
      { "durationSec": 5, "targetVUs": 70 },
      { "durationSec": 2, "targetVUs": 10 }
    ],
    "thresholds": {
      "p95LatencyMs": 300,
      "p99LatencyMs": 600,
      "maxErrorRatePercent": 1.0
    }
  },
  "outputDir": "./sentinel-reports"
}
```

### Variables de Entorno Admitidas
- `BASE_URL`: URL base del backend objetivo.
- `SENTINEL_USER_TOKEN`: Token de autenticación de usuario estándar.
- `SENTINEL_ADMIN_TOKEN`: Token de rol de administrador.

---

## 🤖 Habilidad de Agente IA (`defensive-qa-engineer`)

Sentinel-QA incluye una especificación de habilidad (*Skill*) para agentes inteligentes y asistentes de código (como Antigravity, Claude Code o Copilot):

- Ubicación local del proyecto: [`.agents/skills/defensive-qa-engineer/SKILL.md`](.agents/skills/defensive-qa-engineer/SKILL.md)
- Ubicación global en el sistema: `~/.gemini/config/skills/defensive-qa-engineer/SKILL.md`

Esta habilidad otorga al agente la persona y directrices de un **Ingeniero Sénior de QA, Rendimiento y Seguridad Defensiva**, asegurando que:
1. Inspeccione código en busca de omisiones OWASP.
2. Ejecute pruebas defensivas automatizadas antes de cualquier merge.
3. Aplique remediaciones quirúrgicas (sin componentes duplicados ni código muerto).
4. Emita un informe técnico de cierre estandarizado en 4 puntos.

---

## 🧪 Entorno de Prueba y Demostración Incluido

Sentinel-QA cuenta con un servidor de demostración integrado para ilustrar el ciclo de vulnerabilidad y remediación:

```bash
# Iniciar servidor en modo VULNERABLE (sin cabeceras, sin rate limit, con fugas)
npm run demo

# En otra terminal, ejecuta la auditoría:
./bin/sentinel.js run --url http://localhost:3001
# -> Observarás puntuación baja (0/100) y reporte detallado con reproducciones en curl

# Detén el servidor y lánzalo en modo HARDENED (endurecido):
npm run demo:hardened

# Vuelve a correr el análisis:
./bin/sentinel.js run --url http://localhost:3001
# -> Observarás la activación de Rate Limiting (429), cabeceras seguras y control RBAC.
```

---

## 🔄 Integración en CI/CD

Puedes integrar Sentinel-QA en GitHub Actions agregando `.github/workflows/sentinel-ci.yml`:

```yaml
name: Sentinel-QA Defensive Check

on: [push, pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
      - run: npm ci
      - run: npm run build
      - name: Start Application
        run: npm start &
      - name: Run Defensive QA
        run: ./bin/sentinel.js audit --url http://localhost:3000
```

---

## 📄 Licencia

Este proyecto está distribuido bajo la licencia [MIT](LICENSE).
