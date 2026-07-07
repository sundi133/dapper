// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Render a {@link ReportModel} into enhanced Markdown — the same content depth
 * as the HTML report, with charts expressed as Markdown tables and the attack
 * chain as a Mermaid flowchart. Git-diffable, no styling.
 */

import { SEVERITY_ORDER } from './aggregations.js';
import type { ComputedFinding, ReportModel } from './types.js';

/** Escape pipe characters so cell text doesn't break Markdown tables. */
function cell(value: unknown): string {
  return String(value ?? '').replace(/\|/g, '\\|').replace(/\n/g, ' ');
}

function mermaidId(id: string): string {
  return id.replace(/[^A-Za-z0-9_]/g, '_');
}

function header(m: ReportModel): string {
  const a = m.assessment;
  const lines = [
    '# Security Assessment Report',
    '',
    '## Document Control',
    '',
    `- **Target Application:** ${a.target_url}`,
    a.github_url ? `- **Repository:** ${a.github_url}` : '',
    `- **Assessment Type:** ${a.assessment_type}`,
    `- **Coverage Mode:** ${a.coverage_mode}`,
    `- **Assessment Date:** ${a.assessment_date}`,
    a.models && a.models.length ? `- **Model:** ${a.models.join(', ')}` : '',
    '',
  ];
  return lines.filter((l) => l !== '').join('\n') + '\n';
}

function execBrief(m: ReportModel): string {
  const c = m.severityCounts;
  const out = ['## Executive Brief', ''];
  const exploited = m.reported.filter((f) => f.status === 'Exploited' || f.status === 'Blocked_by_Security').length;
  const codeVerified = m.reported.filter((f) => f.status === 'Code_Verified').length;
  const breakdown =
    codeVerified > 0
      ? ` (${exploited} runtime-exploited, ${codeVerified} confirmed in source but not runtime-exploited)`
      : '';
  out.push(
    m.reported.length === 0
      ? `**Posture: ${m.postureGrade}.** No exploitable vulnerabilities were confirmed within the tested scope.`
      : `**Posture: ${m.postureGrade}.** The assessment identified **${c.Critical} critical** and **${c.High} high** severity findings across ${m.byCategory.length} categories${breakdown}.`
  );
  out.push('', '### Severity Distribution', '', '| Severity | Count |', '| --- | --- |');
  for (const s of SEVERITY_ORDER) out.push(`| ${s} | ${c[s]} |`);
  out.push(`| **Total** | **${m.reported.length}** |`, '');
  return out.join('\n') + '\n';
}

function categorySection(m: ReportModel): string {
  if (m.byCategory.length === 0) return '';
  const out = ['### Findings by Category', '', '| Category | Count |', '| --- | --- |'];
  for (const c of m.byCategory) out.push(`| ${cell(c.category)} | ${c.count} |`);
  return out.join('\n') + '\n';
}

function chainSection(m: ReportModel): string {
  if (m.chains.length === 0) return '';
  const out = ['### Key Attack Chains', '', '```mermaid', 'flowchart LR'];
  m.chains.slice(0, 2).forEach((chain, ci) => {
    for (let i = 0; i < chain.nodes.length; i++) {
      const node = chain.nodes[i]!;
      const nid = `c${ci}_${mermaidId(node.id)}`;
      out.push(`  ${nid}["${node.label.replace(/"/g, "'")}"]`);
      if (i > 0) {
        const prev = chain.nodes[i - 1]!;
        const pid = `c${ci}_${mermaidId(prev.id)}`;
        out.push(`  ${pid} --> ${nid}`);
      }
    }
  });
  out.push('```', '');
  return out.join('\n') + '\n';
}

function topFindingsSection(m: ReportModel): string {
  if (m.reported.length === 0) return '';
  const top = [...m.reported].sort((a, b) => b.cvss_score - a.cvss_score);
  const out = [
    '### Findings Summary',
    '',
    '| # | ID | Finding | Category | CVSS | Severity | Status |',
    '| --- | --- | --- | --- | --- | --- | --- |',
  ];
  top.forEach((f, i) => {
    out.push(
      `| ${i + 1} | ${cell(f.id)} | ${cell(f.title)} | ${cell(f.category)} | ${f.cvss_score.toFixed(1)} | ${f.severity} | ${cell(f.status.replace(/_/g, ' '))} |`
    );
  });
  return out.join('\n') + '\n';
}

function scopeSection(m: ReportModel): string {
  const out = ['## Scope & Coverage', '', '| Vulnerability Class | Findings | Result |', '| --- | --- | --- |'];
  for (const s of m.scopeCoverage) {
    out.push(`| ${cell(s.category)} | ${s.count} | ${s.clean ? 'Clean' : 'Findings present'} |`);
  }
  return out.join('\n') + '\n';
}

function owaspSection(m: ReportModel): string {
  if (m.owaspCoverage.length === 0) return '';
  const out = ['## OWASP Top 10 Coverage', '', '| Category | Findings |', '| --- | --- |'];
  for (const o of m.owaspCoverage) out.push(`| ${cell(o.id)} | ${o.count} |`);
  return out.join('\n') + '\n';
}

function roadmapSection(m: ReportModel): string {
  const out = ['## Remediation Roadmap', ''];
  const lane = (key: 'Now' | 'Soon' | 'Later', title: string): void => {
    out.push(`### ${title}`, '');
    const items = m.roadmap[key];
    if (items.length === 0) {
      out.push('_Nothing scheduled._', '');
    } else {
      for (const f of items) out.push(`- ${f.remediation.summary || f.title} (${f.id})`);
      out.push('');
    }
  };
  lane('Now', 'Now · 0–30 days');
  lane('Soon', 'Soon · 30–90 days');
  lane('Later', 'Later · 90+ days');
  return out.join('\n') + '\n';
}

function findingDetail(f: ComputedFinding): string {
  const out = [
    `### ${f.id}: ${f.title}`,
    '',
    `- **Severity:** ${f.severity} (CVSS ${f.cvss_score.toFixed(1)})`,
    f.cvss_vector ? `- **CVSS Vector:** \`${f.cvss_vector}\`` : '',
    f.cwe ? `- **CWE:** ${f.cwe}` : '',
    f.owasp ? `- **OWASP:** ${f.owasp}` : '',
    `- **Category:** ${f.category}`,
    `- **Status:** ${f.status.replace(/_/g, ' ')} · **Confidence:** ${f.confidence}`,
    `- **Location:** ${f.location}${f.affected_endpoint ? ` — ${f.affected_endpoint}` : ''}`,
    '',
  ].filter((l) => l !== '');
  if (f.summary) out.push(f.summary, '');
  out.push(`**Business Impact:** ${f.business_impact}`, '');
  if (f.poc) out.push('**Proof of Concept:**', '', '```', f.poc, '```', '');
  out.push(
    '**Remediation:**',
    '',
    `${f.remediation.detail ? f.remediation.detail + ' ' : ''}${f.remediation.summary}`,
    '',
    `**Verify:** ${f.remediation.verification}`,
    ''
  );
  return out.join('\n');
}

function technicalSection(m: ReportModel): string {
  const out = ['## Technical Findings — Detailed Evidence', ''];
  if (m.reported.length === 0) {
    out.push('_No exploitable findings were confirmed within the tested scope._', '');
    return out.join('\n');
  }
  const sorted = [...m.reported].sort((a, b) => b.cvss_score - a.cvss_score);
  for (const f of sorted) out.push(findingDetail(f));
  return out.join('\n');
}

export function renderMarkdown(m: ReportModel, generatedAt?: string): string {
  const footer = generatedAt ? `\n---\n\n_Generated by Dapper · ${generatedAt} · Confidential._\n` : '';
  return (
    [
      header(m),
      execBrief(m),
      categorySection(m),
      chainSection(m),
      topFindingsSection(m),
      scopeSection(m),
      owaspSection(m),
      roadmapSection(m),
      technicalSection(m),
    ]
      .filter((s) => s.trim() !== '')
      .join('\n') + footer
  );
}
