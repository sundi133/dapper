// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Render the findings CSV — one row per reported finding (Exploited /
 * Blocked_by_Security; the model already filters these into `reported`).
 * RFC-4180 quoting.
 */

import type { ReportModel } from './types.js';

const COLUMNS = [
  'id',
  'title',
  'category',
  'severity',
  'cvss_score',
  'cvss_vector',
  'cwe',
  'owasp',
  'status',
  'location',
  'affected_endpoint',
  'remediation_summary',
  'confidence',
  'remediation_priority',
  'business_impact',
] as const;

function csvField(value: unknown): string {
  const s = String(value ?? '');
  if (/[",\r\n]/.test(s)) {
    return '"' + s.replace(/"/g, '""') + '"';
  }
  return s;
}

export function renderCsv(m: ReportModel): string {
  const lines: string[] = [COLUMNS.join(',')];
  for (const f of m.reported) {
    const row = [
      f.id,
      f.title,
      f.category,
      f.severity,
      f.cvss_score.toFixed(1),
      f.cvss_vector ?? '',
      f.cwe ?? '',
      f.owasp ?? '',
      f.status,
      f.location,
      f.affected_endpoint,
      f.remediation.summary,
      f.confidence,
      f.remediation.priority,
      f.business_impact,
    ];
    lines.push(row.map(csvField).join(','));
  }
  // Trailing newline for POSIX-friendliness.
  return lines.join('\r\n') + '\r\n';
}
