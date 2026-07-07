// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Render a {@link ReportModel} into a self-contained, styled HTML document in
 * the Modern Security Firm theme. One report, two sections: Executive Brief
 * flows into Technical Findings. All model-derived text is HTML-escaped.
 */

import {
  THEME_CSS,
  donutGradient,
  escapeHtml,
  severityBadge,
  severityColor,
} from './theme.js';
import { SEVERITY_ORDER } from './aggregations.js';
import type { ComputedFinding, ReportModel, Severity } from './types.js';

function coverSection(m: ReportModel): string {
  const a = m.assessment;
  const metaBits = [
    `<b>${escapeHtml(a.target_url)}</b>`,
    escapeHtml(a.assessment_type),
    `${escapeHtml(a.coverage_mode)} mode`,
    escapeHtml(a.assessment_date),
  ];
  const models = a.models && a.models.length ? `<div class="meta">Model: ${escapeHtml(a.models.join(', '))}</div>` : '';
  return `
  <div class="cover">
    <div class="eyebrow">Confidential · Security Assessment</div>
    <h1>Security Assessment Report</h1>
    <div class="meta">${metaBits.join(' · ')}</div>
    ${models}
  </div>`;
}

function dashboard(m: ReportModel): string {
  const total = m.reported.length;
  const stats = SEVERITY_ORDER.map(
    (s: Severity) =>
      `<div class="stat"><div class="n" style="color:${severityColor(s)}">${m.severityCounts[s]}</div><div class="l">${escapeHtml(s)}</div></div>`
  ).join('');
  return `
    <div class="row" style="margin-top:16px;">
      <div class="donut" style="background:${donutGradient(m.severityCounts)}"><div class="hole"><div class="tot">${total}</div><div class="lab">Findings</div></div></div>
      <div style="flex:2;"><div class="row">${stats}</div></div>
    </div>`;
}

function postureStatement(m: ReportModel): string {
  const grade = m.postureGrade;
  const color = grade.startsWith('CRITICAL')
    ? '#b91c1c'
    : grade.startsWith('HIGH')
      ? '#c2410c'
      : grade.startsWith('MEDIUM')
        ? '#a16207'
        : '#0369a1';
  const c = m.severityCounts;
  const exploited = m.reported.filter((f) => f.status === 'Exploited' || f.status === 'Blocked_by_Security').length;
  const codeVerified = m.reported.filter((f) => f.status === 'Code_Verified').length;
  const breakdown =
    codeVerified > 0
      ? ` (${exploited} runtime-exploited, ${codeVerified} confirmed in source but not runtime-exploited)`
      : '';
  const headline =
    total(m) === 0
      ? 'No exploitable vulnerabilities were confirmed within the tested scope.'
      : `The assessment identified <b>${c.Critical} critical</b> and <b>${c.High} high</b> severity findings across ${m.byCategory.length} categories${breakdown}. Prioritized remediation is advised before the next release.`;
  return `<div class="posture"><span class="grade" style="background:${color}">${escapeHtml(grade)}</span> ${headline}</div>`;
}

function total(m: ReportModel): number {
  return m.reported.length;
}

function categoryChart(m: ReportModel): string {
  if (m.byCategory.length === 0) return '<p class="empty">No findings to chart.</p>';
  const max = Math.max(...m.byCategory.map((c) => c.count));
  const rows = m.byCategory
    .map(
      (c) =>
        `<div class="barrow"><span class="cat">${escapeHtml(c.category)}</span><span class="track"><span class="fill" style="width:${(c.count / max) * 100}%"></span></span><span class="ct">${c.count}</span></div>`
    )
    .join('');
  return `<div class="bars">${rows}</div>`;
}

function attackChains(m: ReportModel): string {
  if (m.chains.length === 0) return '';
  // Show up to the top 2 ranked chains.
  const top = m.chains.slice(0, 2);
  const blocks = top
    .map((chain) => {
      const nodes = chain.nodes
        .map((n, idx) => {
          const isEnd = idx === chain.nodes.length - 1;
          const sep = idx > 0 ? '<span class="arrow">→</span>' : '';
          return `${sep}<span class="node${isEnd ? ' end' : ''}">${escapeHtml(n.label)}</span>`;
        })
        .join('');
      return `<div class="chain">${nodes}</div>`;
    })
    .join('');
  return `
  <div class="sec">
    <p class="seclabel">Key Attack Chain${top.length > 1 ? 's' : ''}</p>
    <div style="font-size:12px;color:#334155;">Highest-impact exploitation path${top.length > 1 ? 's' : ''} demonstrated end-to-end:</div>
    ${blocks}
  </div>`;
}

function topFindings(m: ReportModel): string {
  const top = [...m.reported].sort((a, b) => b.cvss_score - a.cvss_score).slice(0, 10);
  if (top.length === 0) return '<p class="empty">No reportable findings.</p>';
  const rows = top
    .map(
      (f, i) => `
      <tr>
        <td>${i + 1}</td>
        <td><code>${escapeHtml(f.id)}</code></td>
        <td>${escapeHtml(f.title)}</td>
        <td>${escapeHtml(f.category)}</td>
        <td>${f.cvss_score.toFixed(1)}</td>
        <td>${severityBadge(f.severity)}</td>
        <td>${escapeHtml(f.status.replace(/_/g, ' '))}</td>
      </tr>`
    )
    .join('');
  return `<table><tr><th>#</th><th>ID</th><th>Finding</th><th>Category</th><th>CVSS</th><th>Severity</th><th>Status</th></tr>${rows}</table>`;
}

function scopeSection(m: ReportModel): string {
  const chips = m.scopeCoverage
    .map((s) =>
      s.clean
        ? `<span class="chip clean">${escapeHtml(s.category)} · clean</span>`
        : `<span class="chip hit">${escapeHtml(s.category)} · ${s.count}</span>`
    )
    .join('');
  return `
  <div class="sec">
    <p class="seclabel">Scope &amp; Coverage</p>
    <div style="font-size:12px;color:#334155;margin-bottom:8px;">All ${m.scopeCoverage.length} vulnerability classes were tested — including those that returned clean.</div>
    <div class="cov">${chips}</div>
  </div>`;
}

function owaspSection(m: ReportModel): string {
  if (m.owaspCoverage.length === 0) return '';
  const chips = m.owaspCoverage
    .map((o) => `<span class="chip hit">${escapeHtml(o.id)} · ${o.count}</span>`)
    .join('');
  return `
  <div class="sec">
    <p class="seclabel">OWASP Top 10 Coverage</p>
    <div class="cov">${chips}</div>
  </div>`;
}

function roadmapSection(m: ReportModel): string {
  const lane = (key: 'Now' | 'Soon' | 'Later', cls: string, title: string): string => {
    const items = m.roadmap[key];
    const lis =
      items.length === 0
        ? '<li class="empty">Nothing scheduled</li>'
        : items.map((f) => `<li>${escapeHtml(f.remediation.summary || f.title)}</li>`).join('');
    return `<div class="lane ${cls}"><h5>${title}</h5><ul>${lis}</ul></div>`;
  };
  return `
  <div class="sec">
    <p class="seclabel">Remediation Roadmap</p>
    <div class="road">
      ${lane('Now', 'now', 'Now · 0–30 days')}
      ${lane('Soon', 'soon', 'Soon · 30–90 days')}
      ${lane('Later', 'later', 'Later · 90+ days')}
    </div>
  </div>`;
}

function findingCard(f: ComputedFinding): string {
  const tags = [
    f.cwe ? `<span class="tag">${escapeHtml(f.cwe)}</span>` : '',
    f.owasp ? `<span class="tag">OWASP ${escapeHtml(f.owasp)}</span>` : '',
    `<span class="tag">${escapeHtml(f.category)}</span>`,
  ].join('');
  const vector = f.cvss_vector ? `<div class="vector">${escapeHtml(f.cvss_vector)}</div>` : '';
  const summary = f.summary ? `<b>Summary.</b> ${escapeHtml(f.summary)}` : '';
  const poc = f.poc
    ? `<div class="block"><div class="h">Proof of Concept</div><pre>${escapeHtml(f.poc)}</pre></div>`
    : '';
  const remediationDetail = f.remediation.detail ? `${escapeHtml(f.remediation.detail)} ` : '';
  return `
    <div class="finding" id="${escapeHtml(f.id.toLowerCase())}">
      <div class="fhead">
        <div>
          <div class="id">${escapeHtml(f.id)} · Status: ${escapeHtml(f.status.replace(/_/g, ' '))} · Confidence: ${escapeHtml(f.confidence)}</div>
          <h4>${escapeHtml(f.title)}</h4>
          ${tags}
          ${vector}
        </div>
        <div class="cvss" style="background:${severityColor(f.severity)}"><div class="score">${f.cvss_score.toFixed(1)}</div><div class="sev">${escapeHtml(f.severity)}</div></div>
      </div>
      <div class="fbody">
        ${summary}
        <div class="block"><div class="h">Business Impact</div><div class="impact">${escapeHtml(f.business_impact)}</div></div>
        <div class="block"><div class="h">Affected Location</div><code>${escapeHtml(f.location)}</code>${f.affected_endpoint ? ` — <code>${escapeHtml(f.affected_endpoint)}</code>` : ''}</div>
        ${poc}
        <div class="block"><div class="h">Remediation</div><div class="remedy">${remediationDetail}${escapeHtml(f.remediation.summary)} <b>Verify:</b> ${escapeHtml(f.remediation.verification)}</div></div>
      </div>
    </div>`;
}

function technicalSection(m: ReportModel): string {
  if (m.reported.length === 0) {
    return `<div class="sec" style="background:#fbfcfd;"><p class="seclabel">Technical Findings — Detailed Evidence</p><p class="empty">No exploitable findings were confirmed within the tested scope.</p></div>`;
  }
  const cards = [...m.reported].sort((a, b) => b.cvss_score - a.cvss_score).map(findingCard).join('');
  return `
  <div class="sec" style="background:#fbfcfd;">
    <p class="seclabel">Technical Findings — Detailed Evidence</p>
    ${cards}
  </div>`;
}

export function renderHtml(m: ReportModel, generatedAt?: string): string {
  const stamp = generatedAt ? ` · Generated ${escapeHtml(generatedAt)}` : '';
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Security Assessment Report — ${escapeHtml(m.assessment.target_url)}</title>
  <style>${THEME_CSS}</style>
</head>
<body>
  <div class="doc">
    ${coverSection(m)}
    <div class="sec">
      <p class="seclabel">Executive Brief</p>
      ${postureStatement(m)}
      ${dashboard(m)}
    </div>
    <div class="sec">
      <p class="seclabel">Findings by Category</p>
      ${categoryChart(m)}
    </div>
    ${attackChains(m)}
    <div class="sec">
      <p class="seclabel">Top Findings</p>
      ${topFindings(m)}
    </div>
    ${scopeSection(m)}
    ${owaspSection(m)}
    ${roadmapSection(m)}
    ${technicalSection(m)}
    <div class="footer">Generated by Dapper${stamp} · Confidential — for the authorized recipient only.</div>
  </div>
</body>
</html>`;
}
