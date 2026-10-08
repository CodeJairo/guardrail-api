import type { AuditReport } from '../engine/runner.js';
import type { Severity } from '../rules/types.js';

export function generateHtmlReport(report: AuditReport): string {
  const severityOrder: Record<Severity, number> = {
    CRITICAL: 5,
    HIGH: 4,
    MEDIUM: 3,
    LOW: 2,
    INFO: 1,
  };

  const sortedFindings = [...report.findings].sort(
    (a, b) => severityOrder[b.severity] - severityOrder[a.severity]
  );

  const findingsHtml = sortedFindings
    .map((f) => {
      const badgeClass = f.severity.toLowerCase();
      const loc = f.path ? `${f.method || ''} ${f.path}` : 'Specification Root';
      const reproductionHtml = f.reproduction
        ? `<div class="meta-row reproduction-row"><strong>cURL Reproduction:</strong> <code>${escapeHtml(f.reproduction)}</code></div>`
        : '';
      const detailsHtml =
        f.details && Object.keys(f.details).length > 0
          ? `<pre class="details-pre"><code>${escapeHtml(JSON.stringify(f.details, null, 2))}</code></pre>`
          : '';

      return `
      <div class="finding-card ${badgeClass}">
        <div class="card-header">
          <span class="badge ${badgeClass}">${f.severity}</span>
          <span class="rule-id">[${f.ruleId}]</span>
          <h3 class="card-title">${escapeHtml(f.title)}</h3>
        </div>
        <div class="card-body">
          <div class="meta-row"><strong>Location:</strong> <code>${escapeHtml(loc)}</code></div>
          <div class="meta-row"><strong>Category:</strong> <span>${f.category}</span></div>
          <div class="meta-row"><strong>Description:</strong> <p>${escapeHtml(f.message)}</p></div>
          <div class="meta-row remediation">
            <strong>Remediation:</strong>
            <p>${escapeHtml(f.remediation)}</p>
          </div>
          ${reproductionHtml}
          ${detailsHtml}
        </div>
      </div>
      `;
    })
    .join('\n');

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Guardrail API Security Report - ${escapeHtml(report.specTitle)}</title>
  <style>
    :root {
      --bg: #0f172a;
      --card-bg: #1e293b;
      --text: #f8fafc;
      --text-muted: #94a3b8;
      --border: #334155;
      --critical: #ef4444;
      --high: #f97316;
      --medium: #eab308;
      --low: #38bdf8;
      --info: #a855f7;
      --success: #22c55e;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background-color: var(--bg);
      color: var(--text);
      line-height: 1.6;
      padding: 2rem;
    }
    .container { max-width: 1100px; margin: 0 auto; }
    header {
      border-bottom: 1px solid var(--border);
      padding-bottom: 1.5rem;
      margin-bottom: 2rem;
    }
    h1 { font-size: 2rem; color: #38bdf8; display: flex; align-items: center; gap: 0.5rem; }
    .subtitle { color: var(--text-muted); font-size: 0.95rem; margin-top: 0.25rem; }
    .meta-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 1rem;
      margin-top: 1.5rem;
    }
    .meta-item {
      background: var(--card-bg);
      padding: 1rem;
      border-radius: 8px;
      border: 1px solid var(--border);
    }
    .meta-label { color: var(--text-muted); font-size: 0.8rem; text-transform: uppercase; }
    .meta-value { font-size: 1.1rem; font-weight: 600; margin-top: 0.25rem; word-break: break-all; }
    
    .metrics {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
      gap: 1rem;
      margin: 2rem 0;
    }
    .metric-card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 1rem;
      text-align: center;
    }
    .metric-val { font-size: 2.2rem; font-weight: 700; }
    .critical-val { color: var(--critical); }
    .high-val { color: var(--high); }
    .medium-val { color: var(--medium); }
    .low-val { color: var(--low); }
    .total-val { color: #f8fafc; }

    .findings-section h2 { margin-bottom: 1rem; }
    .finding-card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      margin-bottom: 1.25rem;
      overflow: hidden;
    }
    .card-header {
      padding: 1rem 1.25rem;
      display: flex;
      align-items: center;
      gap: 0.75rem;
      background: rgba(255, 255, 255, 0.03);
      border-bottom: 1px solid var(--border);
    }
    .badge {
      font-size: 0.75rem;
      font-weight: 700;
      padding: 0.25rem 0.6rem;
      border-radius: 4px;
      text-transform: uppercase;
    }
    .badge.critical { background: var(--critical); color: white; }
    .badge.high { background: var(--high); color: white; }
    .badge.medium { background: var(--medium); color: black; }
    .badge.low { background: var(--low); color: black; }
    .badge.info { background: var(--info); color: white; }

    .rule-id { color: var(--text-muted); font-size: 0.9rem; font-family: monospace; }
    .card-title { font-size: 1.1rem; }
    .card-body { padding: 1.25rem; }
    .meta-row { margin-bottom: 0.75rem; }
    .meta-row code {
      background: #090d16;
      padding: 0.2rem 0.4rem;
      border-radius: 4px;
      font-size: 0.9rem;
      color: #38bdf8;
    }
    .remediation {
      background: rgba(34, 197, 94, 0.1);
      border-left: 4px solid var(--success);
      padding: 0.75rem 1rem;
      border-radius: 0 4px 4px 0;
      margin-top: 1rem;
    }
    .remediation strong { color: var(--success); display: block; margin-bottom: 0.25rem; }
    .details-pre {
      background: #090d16;
      border: 1px solid var(--border);
      padding: 0.75rem;
      border-radius: 6px;
      overflow-x: auto;
      margin-top: 0.75rem;
      font-size: 0.85rem;
    }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <h1>🛡️ Guardrail API Security Audit</h1>
      <p class="subtitle">Contract-Driven OpenAPI Static & Dynamic Security Assessment</p>
      
      <div class="meta-grid">
        <div class="meta-item">
          <div class="meta-label">Specification</div>
          <div class="meta-value">${escapeHtml(report.specTitle)}</div>
        </div>
        <div class="meta-item">
          <div class="meta-label">Target URL</div>
          <div class="meta-value">${escapeHtml(report.targetUrl || 'Static Only')}</div>
        </div>
        <div class="meta-item">
          <div class="meta-label">Endpoints Analyzed</div>
          <div class="meta-value">${report.totalOperations}</div>
        </div>
        <div class="meta-item">
          <div class="meta-label">Duration</div>
          <div class="meta-value">${report.durationMs}ms</div>
        </div>
      </div>
    </header>

    <div class="metrics">
      <div class="metric-card">
        <div class="meta-label">Critical</div>
        <div class="metric-val critical-val">${report.summary.critical}</div>
      </div>
      <div class="metric-card">
        <div class="meta-label">High</div>
        <div class="metric-val high-val">${report.summary.high}</div>
      </div>
      <div class="metric-card">
        <div class="meta-label">Medium</div>
        <div class="metric-val medium-val">${report.summary.medium}</div>
      </div>
      <div class="metric-card">
        <div class="meta-label">Low</div>
        <div class="metric-val low-val">${report.summary.low}</div>
      </div>
      <div class="metric-card">
        <div class="meta-label">Total Findings</div>
        <div class="metric-val total-val">${report.summary.total}</div>
      </div>
    </div>

    <div class="findings-section">
      <h2>Security Findings (${report.findings.length})</h2>
      ${findingsHtml || '<p style="color: var(--success); font-weight: bold;">🎉 No security findings detected!</p>'}
    </div>
  </div>
</body>
</html>`;
}

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
