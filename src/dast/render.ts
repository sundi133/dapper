// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Pure renderers: DastAnalysis -> markdown.
 * `renderDastMarkdown` is the standalone deliverable; `renderReconSection` is
 * the concise, marker-wrapped block folded into recon_deliverable.md so the
 * vuln/exploit agents prioritise and validate the confirmed live signals.
 */

import type { DastAnalysis, DastFinding, DastSeverity } from './types.js';

/** Stable marker so the recon fold is idempotent across Temporal retries. */
export const DAST_SECTION_MARKER = '<!-- dapper:dast-analysis -->';

const SEVERITY_ORDER: Record<DastSeverity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

function bySeverity(a: DastFinding, b: DastFinding): number {
  return SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity];
}
function esc(s: string): string {
  return (s || '').replace(/\|/g, '\\|').replace(/\n/g, ' ').trim();
}
function counts(findings: DastFinding[]): string {
  const c: Record<DastSeverity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) c[f.severity]++;
  return `critical ${c.critical} · high ${c.high} · medium ${c.medium} · low ${c.low} · info ${c.info}`;
}

const CATEGORY_LABELS: Record<string, string> = {
  cors: 'CORS misconfiguration',
  'open-redirect': 'Open redirect',
  ssti: 'Server-side template injection',
  xxe: 'XML external entity (XXE)',
  'security-headers': 'Missing/weak security headers',
  exposure: 'Sensitive files / exposures',
  tls: 'TLS/SSL configuration',
  graphql: 'GraphQL',
  'file-upload': 'File upload',
  'js-lib-cve': 'Vulnerable JS libraries',
  other: 'Other',
};

function groupByCategory(findings: DastFinding[]): Map<string, DastFinding[]> {
  const m = new Map<string, DastFinding[]>();
  for (const f of findings) {
    const arr = m.get(f.category) ?? [];
    arr.push(f);
    m.set(f.category, arr);
  }
  return m;
}

/** Full standalone deliverable. */
export function renderDastMarkdown(a: DastAnalysis): string {
  const lines: string[] = [];
  lines.push('# Deterministic DAST Probe Results (nuclei / testssl / retire.js)');
  lines.push('');
  lines.push(
    'Deterministic, repeatable black-box probes run against the live target. These are ' +
      'high-precision confirmed live signals — treat them as a seed to validate and weaponise ' +
      'dynamically, not as noise to re-discover.'
  );
  lines.push('');
  const ran = Object.entries(a.toolsRun).filter(([, v]) => v).map(([k]) => k);
  lines.push(`- **Target:** ${esc(a.target)}`);
  lines.push(`- **Tools run:** ${ran.length ? ran.join(', ') : 'none'}`);
  if (a.toolsSkipped.length) lines.push(`- **Tools skipped (not installed):** ${a.toolsSkipped.join(', ')}`);
  lines.push(`- **Findings:** ${a.findings.length} — ${counts(a.findings)}`);
  if (a.errors.length) lines.push(`- **Non-fatal tool notes:** ${a.errors.length} (see end)`);
  lines.push('');

  if (a.findings.length === 0) {
    lines.push('_No deterministic DAST findings._');
  } else {
    const groups = groupByCategory(a.findings);
    for (const [cat, items] of groups) {
      lines.push(`## ${CATEGORY_LABELS[cat] ?? cat} (${items.length})`);
      lines.push('');
      lines.push('| Severity | Finding | Location | CVE | Evidence | Tool |');
      lines.push('|---|---|---|---|---|---|');
      for (const f of [...items].sort(bySeverity)) {
        lines.push(
          `| ${f.severity} | ${esc(f.name)} | ${esc(f.matchedAt)} | ${esc(f.cve.join(', ') || '—')} | ${esc(f.evidence || '—')} | ${f.tool} |`
        );
      }
      lines.push('');
    }
  }

  if (a.errors.length) {
    lines.push('## Non-fatal Tool Notes');
    for (const e of a.errors) lines.push(`- ${esc(e)}`);
    lines.push('');
  }
  lines.push('---');
  lines.push(`Generated at: ${a.generatedAt}`);
  return lines.join('\n');
}

/**
 * Concise block folded into recon_deliverable.md. Marker-wrapped for idempotency.
 * Lists the actionable findings (info-level dropped) so agents focus their effort.
 */
export function renderReconSection(a: DastAnalysis): string {
  const actionable = a.findings.filter((f) => f.severity !== 'info').sort(bySeverity);
  const lines: string[] = [];
  lines.push(DAST_SECTION_MARKER);
  lines.push('');
  lines.push('## Deterministic DAST Probe Results (nuclei / testssl / retire.js)');
  lines.push('');
  lines.push(
    'Confirmed live signals from deterministic scanners against the target. Treat these as ' +
      'high-precision seeds: prioritise verifying/weaponising them and do NOT re-discover them ' +
      'from scratch. Full detail in `deliverables/dast_analysis.md` and `deliverables/dast_findings.json`.'
  );
  lines.push('');
  lines.push(`**Total:** ${a.findings.length} findings — ${counts(a.findings)}.`);
  lines.push('');

  if (actionable.length === 0) {
    lines.push('_No actionable (>= low) DAST findings; see the full deliverable for info-level items._');
  } else {
    lines.push('**Actionable findings (verify & exploit these):**');
    for (const f of actionable.slice(0, 40)) {
      const cve = f.cve.length ? ` [${f.cve.join(', ')}]` : '';
      lines.push(`- [${f.severity}] ${CATEGORY_LABELS[f.category] ?? f.category}: ${f.name}${cve} — at ${f.matchedAt}`);
    }
    if (actionable.length > 40) lines.push(`- _…and ${actionable.length - 40} more (see dast_findings.json)._`);
  }
  lines.push('');
  lines.push(DAST_SECTION_MARKER);
  return lines.join('\n');
}
