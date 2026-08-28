// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Pure renderers: WhiteboxAnalysis -> markdown.
 *
 * `renderWhiteboxMarkdown` produces the standalone deliverable.
 * `renderPreReconSection` produces the concise, marker-wrapped block folded
 * into pre_recon_deliverable.md so the existing LLM agents (threat-model, vuln,
 * report) prioritise and dynamically validate the deterministic findings
 * (capabilities 1.6 / 1.7). No side effects, no Node imports.
 */

import type { WhiteboxAnalysis, WhiteboxSeverity } from './types.js';

/** Stable marker so the pre-recon fold is idempotent across Temporal retries. */
export const WHITEBOX_SECTION_MARKER = '<!-- dapper:whitebox-analysis -->';

const SEVERITY_ORDER: Record<WhiteboxSeverity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

function bySeverity<T extends { severity: WhiteboxSeverity }>(a: T, b: T): number {
  return SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity];
}

function severityCounts(items: Array<{ severity: WhiteboxSeverity }>): string {
  const counts: Record<WhiteboxSeverity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
  for (const it of items) counts[it.severity]++;
  return `critical ${counts.critical} · high ${counts.high} · medium ${counts.medium} · low ${counts.low} · info ${counts.info}`;
}

function esc(s: string): string {
  // keep markdown tables intact
  return (s || '').replace(/\|/g, '\\|').replace(/\n/g, ' ').trim();
}

const AUTHZ_RENDER_CAP = 100;

/** Full standalone deliverable. */
export function renderWhiteboxMarkdown(a: WhiteboxAnalysis): string {
  const lines: string[] = [];
  lines.push('# Deterministic White-Box Analysis (SAST / SCA / Dataflow)');
  lines.push('');
  lines.push(
    'Deterministic, repeatable static analysis produced by off-the-shelf scanners. ' +
      'It complements the LLM source review: use it as a high-precision seed of real ' +
      'sinks, tainted flows, dependency CVEs, and secrets to validate dynamically.'
  );
  lines.push('');
  const ran = Object.entries(a.toolsRun)
    .filter(([, v]) => v)
    .map(([k]) => k);
  lines.push(`- **Tools run:** ${ran.length ? ran.join(', ') : 'none'}`);
  if (a.toolsSkipped.length) lines.push(`- **Tools skipped (not installed):** ${a.toolsSkipped.join(', ')}`);
  lines.push(
    `- **Totals:** ${a.cve.length} CVEs · ${a.secrets.length} secrets · ${a.taint.length} tainted flows · ${a.sast.length} SAST sinks · ${a.authz.length} routes`
  );
  if (a.errors.length) lines.push(`- **Non-fatal tool notes:** ${a.errors.length} (see end)`);
  lines.push('');

  // 1.5 CVEs
  lines.push('## Dependency Vulnerabilities (SCA / CVE)');
  if (a.cve.length === 0) {
    lines.push('None found (or no lockfiles present).');
  } else {
    lines.push(`Severity spread: ${severityCounts(a.cve)}`);
    lines.push('');
    lines.push('| Severity | Package | Installed | Vuln ID | Fixed in | Summary |');
    lines.push('|---|---|---|---|---|---|');
    for (const c of [...a.cve].sort(bySeverity)) {
      lines.push(
        `| ${c.severity} | ${esc(c.packageName)} (${esc(c.ecosystem)}) | ${esc(c.installedVersion)} | ${esc(c.vulnId)} | ${esc(c.fixedVersion ?? '—')} | ${esc(c.summary)} |`
      );
    }
  }
  lines.push('');

  // 1.2 + 1.3 taint / reachability
  lines.push('## Tainted Dataflows (source → sink, with reachability)');
  if (a.taint.length === 0) {
    lines.push('None found.');
  } else {
    lines.push(`Severity spread: ${severityCounts(a.taint)}`);
    lines.push('');
    lines.push('| Severity | Category | Internet-reachable | Source | Sink | Rule |');
    lines.push('|---|---|---|---|---|---|');
    for (const t of [...a.taint].sort(bySeverity)) {
      const reach = t.reachableFromInternet ? 'YES (HTTP input)' : 'no';
      lines.push(
        `| ${t.severity} | ${esc(t.category)} | ${reach} | ${esc(t.source.file)}:${t.source.line} | ${esc(t.sink.file)}:${t.sink.line} | ${esc(t.ruleId)} |`
      );
    }
  }
  lines.push('');

  // 1.1 SAST sinks
  lines.push('## Dangerous Sinks (SAST)');
  if (a.sast.length === 0) {
    lines.push('None found.');
  } else {
    lines.push(`Severity spread: ${severityCounts(a.sast)}`);
    lines.push('');
    lines.push('| Severity | Category | Location | Message | Rule |');
    lines.push('|---|---|---|---|---|');
    for (const s of [...a.sast].sort(bySeverity)) {
      lines.push(
        `| ${s.severity} | ${esc(s.category)} | ${esc(s.location.file)}:${s.location.line} | ${esc(s.message)} | ${esc(s.ruleId)} |`
      );
    }
  }
  lines.push('');

  // 1.1 secrets
  lines.push('## Hardcoded Secrets');
  if (a.secrets.length === 0) {
    lines.push('None found.');
  } else {
    lines.push('| Rule | Location | Preview (redacted) | Description |');
    lines.push('|---|---|---|---|');
    for (const s of a.secrets) {
      lines.push(
        `| ${esc(s.ruleId)} | ${esc(s.file)}:${s.startLine} | ${esc(s.secretPreview)} | ${esc(s.description)} |`
      );
    }
  }
  lines.push('');

  // 1.4 authz surface
  lines.push('## Authorization Surface (routes to verify)');
  if (a.authz.length === 0) {
    lines.push('No internet-facing route handlers detected by static analysis.');
  } else {
    lines.push(
      `${a.authz.length} route handler(s) surfaced. Heuristic map of the authorization attack surface — each should be verified for authentication / ownership / role enforcement.`
    );
    lines.push('');
    lines.push('| Method | Route | Location |');
    lines.push('|---|---|---|');
    for (const r of a.authz.slice(0, AUTHZ_RENDER_CAP)) {
      lines.push(`| ${esc(r.method ?? '—')} | ${esc(r.route ?? '—')} | ${esc(r.file)}:${r.line} |`);
    }
    if (a.authz.length > AUTHZ_RENDER_CAP) {
      lines.push('');
      lines.push(`_…and ${a.authz.length - AUTHZ_RENDER_CAP} more (see whitebox_findings.json)._`);
    }
  }
  lines.push('');

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
 * Concise block folded into pre_recon_deliverable.md. Marker-wrapped so the
 * fold is idempotent. This is what downstream LLM agents actually read.
 */
export function renderPreReconSection(a: WhiteboxAnalysis): string {
  const reachableTaint = a.taint.filter((t) => t.reachableFromInternet);
  const topCve = [...a.cve].sort(bySeverity).slice(0, 15);

  const lines: string[] = [];
  lines.push(WHITEBOX_SECTION_MARKER);
  lines.push('');
  lines.push('## Deterministic White-Box Analysis (SAST / SCA / Dataflow)');
  lines.push('');
  lines.push(
    'The following were produced by deterministic scanners (osv-scanner / gitleaks / semgrep) ' +
      'and are high-precision seeds. Treat them as confirmed static signals to prioritise and ' +
      'validate dynamically — do NOT re-derive them from scratch. Full detail in ' +
      '`deliverables/whitebox_analysis.md` and `deliverables/whitebox_findings.json`.'
  );
  lines.push('');
  lines.push(
    `**Totals:** ${a.cve.length} dependency CVEs · ${a.secrets.length} hardcoded secrets · ` +
      `${reachableTaint.length}/${a.taint.length} tainted flows reachable from HTTP input · ` +
      `${a.sast.length} dangerous sinks · ${a.authz.length} route handlers to authz-check.`
  );
  lines.push('');

  if (topCve.length) {
    lines.push('**Top dependency CVEs (prioritise verifying exploitability):**');
    for (const c of topCve) {
      lines.push(
        `- [${c.severity}] ${c.packageName}@${c.installedVersion} — ${c.vulnId}${c.fixedVersion ? ` (fixed in ${c.fixedVersion})` : ''}: ${c.summary}`
      );
    }
    lines.push('');
  }

  if (reachableTaint.length) {
    lines.push('**Internet-reachable tainted flows (highest-priority injection candidates):**');
    for (const t of [...reachableTaint].sort(bySeverity).slice(0, 20)) {
      lines.push(
        `- [${t.severity}] ${t.category}: HTTP input at ${t.source.file}:${t.source.line} → sink at ${t.sink.file}:${t.sink.line}`
      );
    }
    lines.push('');
  }

  if (a.secrets.length) {
    lines.push(`**Hardcoded secrets:** ${a.secrets.length} (see full deliverable; values redacted).`);
    lines.push('');
  }

  lines.push(WHITEBOX_SECTION_MARKER);
  return lines.join('\n');
}
