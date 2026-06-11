// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Pure aggregation helpers over computed findings: severity tallies, category
 * and OWASP breakdowns, scope coverage (including clean classes), remediation
 * roadmap grouping, and the overall posture grade.
 */

import {
  CANONICAL_CATEGORIES,
  SEVERITY_ORDER,
  type CategoryCount,
  type ComputedFinding,
  type OwaspCount,
  type PostureGrade,
  type Priority,
  type ScopeCoverage,
  type Severity,
} from './types.js';

export function severityCounts(findings: ComputedFinding[]): Record<Severity, number> {
  const counts: Record<Severity, number> = {
    Critical: 0,
    High: 0,
    Medium: 0,
    Low: 0,
    Informational: 0,
  };
  for (const f of findings) counts[f.severity]++;
  return counts;
}

export function byCategory(findings: ComputedFinding[]): CategoryCount[] {
  const map = new Map<string, number>();
  for (const f of findings) {
    map.set(f.category, (map.get(f.category) ?? 0) + 1);
  }
  return [...map.entries()]
    .map(([category, count]) => ({ category, count }))
    .sort((a, b) => b.count - a.count);
}

export function owaspCoverage(findings: ComputedFinding[]): OwaspCount[] {
  const map = new Map<string, number>();
  for (const f of findings) {
    if (!f.owasp) continue;
    map.set(f.owasp, (map.get(f.owasp) ?? 0) + 1);
  }
  return [...map.entries()]
    .map(([id, count]) => ({ id, count }))
    .sort((a, b) => b.count - a.count || a.id.localeCompare(b.id));
}

/** Coverage across all 15 canonical classes; classes with 0 findings are clean. */
export function scopeCoverage(findings: ComputedFinding[]): ScopeCoverage[] {
  const map = new Map<string, number>();
  for (const f of findings) {
    map.set(f.category, (map.get(f.category) ?? 0) + 1);
  }
  return CANONICAL_CATEGORIES.map((category) => {
    const count = map.get(category) ?? 0;
    return { category, count, clean: count === 0 };
  });
}

export function roadmap(findings: ComputedFinding[]): Record<Priority, ComputedFinding[]> {
  const groups: Record<Priority, ComputedFinding[]> = { Now: [], Soon: [], Later: [] };
  for (const f of findings) {
    const priority = f.remediation?.priority ?? 'Later';
    groups[priority].push(f);
  }
  return groups;
}

export function postureGrade(findings: ComputedFinding[]): PostureGrade {
  const counts = severityCounts(findings);
  if (counts.Critical > 0) return 'CRITICAL RISK';
  if (counts.High > 0) return 'HIGH RISK';
  if (counts.Medium > 0) return 'MEDIUM RISK';
  return 'LOW RISK';
}

export { SEVERITY_ORDER };
