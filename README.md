# 🛡️ Guardrail API Security CLI

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Node.js Version](https://img.shields.io/badge/Node.js-%3E%3D20-brightgreen.svg)](https://nodejs.org)

**Guardrail API** es una herramienta de línea de comandos (CLI) diseñada para auditar la seguridad de APIs modernas mediante un enfoque híbrido:
1. **Análisis Estático (OpenAPI Spec Linting)**: Inspecciona contratos OpenAPI/Swagger (JSON o YAML) en busca de esquemas de autenticación ausentes, validaciones débiles de tipos o parámetros, y endpoints críticos expuestos.
2. **Análisis Dinámico Ligero (DAST / Contract-Driven Probing)**: Ejecuta pruebas activas contra la API en vivo para verificar la obligatoriedad de autenticación, cabeceras HTTP de seguridad, configuraciones permisivas de CORS y manejo robusto de excepciones ante fuzzing de tipos (esperando `400 Bad Request` en lugar de fallos internos `500`).
3. **CI/CD Ready**: Permite definir umbrales de fallo (`--fail-on critical`) retornando código de salida `1` para pausar o cancelar pipelines en GitHub Actions, GitLab CI, etc.

---

## 🚀 Instalación y Requisitos

- **Node.js**: v20 o superior.

```bash
# Instalar dependencias y compilar
npm install
npm run build

# Enlace global local (opcional)
npm link
```

---

## 💻 Uso de la CLI

### 1. Auditoría Estática (Sin necesidad de API levantada)
Analiza el contrato OpenAPI local o remoto:

```bash
# Usando binario compilado
guardrail-api audit --spec ./swagger.json --static-only

# O directamente con node / npm
npm start -- audit --spec ./swagger.yaml --static-only
```

### 2. Auditoría Completa (Estática + Dinámica)
Ejecuta tanto el análisis del contrato como los probes activos contra la API:

```bash
guardrail-api audit \
  --spec ./swagger.json \
  --target http://localhost:3000 \
  --fail-on high
```

### 3. Exportar Reportes (JSON, Markdown, HTML)
```bash
# Reporte interactivo HTML
guardrail-api audit --spec ./swagger.json --output report.html

# Reporte Markdown (ideal para GitHub Pull Request Summaries)
guardrail-api audit --spec ./swagger.json --format markdown --output report.md

# Reporte JSON (para ingesta en SIEM o herramientas CI/CD)
guardrail-api audit --spec ./swagger.json --format json --output report.json
```

---

## ⚙️ Opciones del Comando `audit`

| Flag | Descripción | Por Defecto |
| :--- | :--- | :--- |
| `-s, --spec <pathOrUrl>` | **Requerido**. Ruta local o URL de la especificación OpenAPI (JSON o YAML). | - |
| `-t, --target <url>` | URL base de la API en ejecución para las pruebas dinámicas. | `spec.servers[0]` |
| `--static-only` | Ejecutar únicamente análisis estático del contrato. | `false` |
| `--dynamic-only` | Ejecutar únicamente pruebas dinámicas contra el target. | `false` |
| `--fail-on <severity>` | Nivel mínimo de severidad para retornar código de salida `1`: `critical`, `high`, `medium`, `low`, `info`. | `critical` |
| `-f, --format <format>` | Formato de salida: `console`, `json`, `markdown`, `html`. | `console` |
| `-o, --output <path>` | Guardar el informe generado en la ruta indicada. | - |
| `--timeout <ms>` | Tiempo límite por petición HTTP en milisegundos. | `5000` |
| `-H, --header <key:val...>` | Cabeceras HTTP adicionales para las peticiones dinámicas. | - |

---

## 🛡️ Catálogo de Reglas de Seguridad

### Reglas Estáticas (SAST)
- **`ST-001: Missing Authentication Scheme`**:
  Verifica si los endpoints o la especificación carecen de esquemas de autenticación (JWT/Bearer, API Key, OAuth2).
- **`ST-002: Strict Parameter & Schema Validation`**:
  Detecta parámetros sin tipo, cadenas sin restricciones de longitud o formato (`maxLength`, `pattern`), números sin límites (`minimum`, `maximum`) y objetos de request body sin `additionalProperties: false` (riesgo de Mass Assignment).
- **`ST-003: Unprotected Sensitive Endpoints`**:
  Identifica endpoints administrativos o de recursos sensibles (`/admin`, `/users`, `/accounts`, etc.) y métodos destructivos (`DELETE`, `PUT`, `PATCH`) expuestos sin autenticación.

### Reglas Dinámicas (DAST)
- **`DY-001: Missing Authentication Enforcement`**:
  Intenta consumir endpoints documentados como protegidos sin enviar credenciales. Dispara alerta `CRÍTICA` si la API responde con `200 OK` u otro código de éxito en lugar de `401 Unauthorized` o `403 Forbidden`.
- **`DY-002: Security Headers Validation`**:
  Verifica la presencia de `X-Content-Type-Options: nosniff`, `Strict-Transport-Security`, `X-Frame-Options` / CSP `frame-ancestors`, `Content-Security-Policy`, y alerta ante fugas de versión en `X-Powered-By` y `Server`.
- **`DY-003: CORS Misconfiguration Check`**:
  Envía peticiones con `Origin: https://malicious-domain.com` y detecta orígenes arbitrarios reflejados, orígenes con credenciales activas (`Access-Control-Allow-Credentials: true`) y comodines `*` en endpoints autenticados.
- **`DY-004: Input Validation Fuzzing & Error Handling`**:
  Envía entradas malformadas y tipos inconsistentes. Alerta con severidad `ALTA` si la API colapsa con `500 Internal Server Error` en vez de responder con una excepción controlada (`400 Bad Request` o `422 Unprocessable Entity`).

---

## 🔄 Integración con GitHub Actions

```yaml
name: API Security Audit

on:
  push:
    branches: [main]
  pull_request:

jobs:
  security-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: 22

      - name: Install dependencies & Build
        run: |
          npm ci
          npm run build

      - name: Run Guardrail API Security Audit
        run: |
          ./bin/guardrail.js audit \
            --spec ./docs/openapi.yaml \
            --target https://staging-api.example.com \
            --fail-on critical \
            --format markdown \
            --output report.md

      - name: Publish Report in Job Summary
        if: always()
        run: cat report.md >> $GITHUB_STEP_SUMMARY
```

---

## 🧪 Pruebas Automatizadas

```bash
# Ejecutar suite completa de tests unitarios y de integración con Vitest
npm test
```
