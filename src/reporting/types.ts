// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Data model for the enriched, multi-format security report.
 *
 * `findings.json` (a {@link FindingsDocument}) holds only the LLM's *judgment*
 * fields. All mechanical/computed values (CVSS score, severity band, attack
 * chains, aggregations) are derived deterministically in `model.ts` at render
 * time and are never persisted — "LLM judges, TypeScript computes".
 */

export type Severity = 'Critical' | 'High' | 'Medium' | 'Low' | 'Informational';
export type Status = 'Exploited' | 'Blocked_by_Security' | 'Code_Verified' | 'False_Positive' | 'Out_of_Scope_Internal';
export type Priority = 'Now' | 'Soon' | 'Later';
export type Confidence = 'High' | 'Medium' | 'Low';

export interface Remediation {
  summary: string;
  detail: string;
  verification: string;
  priority: Priority;
}

/** Raw judgment fields as emitted by the enrichment LLM in findings.json. */
export interface Finding {
  id: string; // e.g. AUTH-VULN-07
  title: string;
  category: string; // one of the 15 canonical vuln classes
  cvss_vector: string | null; // CVSS v3.1 vector; null if not assessable
  llm_severity: Severity; // fallback when cvss_vector is null/invalid
  cwe: string | null; // e.g. CWE-798
  owasp: string | null; // e.g. A07:2021
  status: Status;
  confidence: Confidence;
  location: string; // file:line or component
  affected_endpoint: string; // URL/route
  business_impact: string; // money/risk/compliance language
  remediation: Remediation;
  chain_prerequisites: string[]; // artifact tags an attacker must already hold
  chain_enables: string[]; // artifact tags this finding grants
  // Optional preserved prose for the technical section.
  poc?: string; // proof-of-concept (code/HTTP)
  summary?: string; // 1-2 sentence description
}

export interface Assessment {
  target_url: string;
  github_url?: string;
  assessment_type: string;
  coverage_mode: string;
  assessment_date: string;
  models: string[];
}

export interface FindingsDocument {
  assessment: Assessment;
  findings: Finding[];
}

/** A finding decorated with computed fields. */
export interface ComputedFinding extends Finding {
  cvss_score: number; // computed from vector, or mapped from llm_severity
  severity: Severity; // computed from score (or llm_severity on invalid vector)
  evidence_ref: string; // anchor back to prose evidence
}

export interface AttackChainNode {
  id: string;
  label: string;
}

export interface AttackChain {
  nodes: AttackChainNode[];
  maxScore: number;
}

export type PostureGrade = 'CRITICAL RISK' | 'HIGH RISK' | 'MEDIUM RISK' | 'LOW RISK';

export interface CategoryCount {
  category: string;
  count: number;
}

export interface OwaspCount {
  id: string;
  count: number;
}

export interface ScopeCoverage {
  category: string;
  count: number;
  clean: boolean;
}

export interface ReportModel {
  assessment: Assessment;
  findings: ComputedFinding[]; // all findings
  reported: ComputedFinding[]; // status Exploited | Blocked_by_Security (+ Code_Verified in coverage mode)
  severityCounts: Record<Severity, number>;
  byCategory: CategoryCount[];
  owaspCoverage: OwaspCount[];
  scopeCoverage: ScopeCoverage[];
  roadmap: Record<Priority, ComputedFinding[]>;
  chains: AttackChain[];
  postureGrade: PostureGrade;
}

/** The 15 canonical vulnerability classes Dapper tests for. */
export const CANONICAL_CATEGORIES: string[] = [
  'Authentication',
  'Authorization',
  'Injection',
  'XSS',
  'SSRF',
  'Web Attacks',
  'Session & Auth',
  'Business Logic',
  'Client-Side',
  'Info Gathering',
  'Config & Deploy',
  'Session Management',
  'Error Handling',
  'Cryptography',
  'API Testing',
];

export const SEVERITY_ORDER: Severity[] = ['Critical', 'High', 'Medium', 'Low', 'Informational'];
