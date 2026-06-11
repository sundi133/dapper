// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Hand-rolled validation of the LLM-produced `findings.json`. Returns specific
 * error strings so they can be fed back into the enrichment retry prompt.
 */

import type {
  Confidence,
  FindingsDocument,
  Priority,
  Severity,
  Status,
} from './types.js';

const SEVERITIES: Severity[] = ['Critical', 'High', 'Medium', 'Low', 'Informational'];
const STATUSES: Status[] = ['Exploited', 'Blocked_by_Security', 'False_Positive', 'Out_of_Scope_Internal'];
const PRIORITIES: Priority[] = ['Now', 'Soon', 'Later'];
const CONFIDENCES: Confidence[] = ['High', 'Medium', 'Low'];

type ValidationResult =
  | { ok: true; doc: FindingsDocument }
  | { ok: false; errors: string[] };

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function isStringArray(v: unknown): v is string[] {
  return Array.isArray(v) && v.every((x) => typeof x === 'string');
}

export function validateFindingsDocument(obj: unknown): ValidationResult {
  const errors: string[] = [];

  if (!isRecord(obj)) {
    return { ok: false, errors: ['Root must be an object with "assessment" and "findings".'] };
  }

  // --- assessment ---
  const assessment = obj.assessment;
  if (!isRecord(assessment)) {
    errors.push('Missing or invalid "assessment" object.');
  } else {
    for (const field of ['target_url', 'assessment_type', 'coverage_mode', 'assessment_date']) {
      if (typeof assessment[field] !== 'string' || !(assessment[field] as string).length) {
        errors.push(`assessment.${field} must be a non-empty string.`);
      }
    }
    if (assessment.models !== undefined && !isStringArray(assessment.models)) {
      errors.push('assessment.models must be an array of strings.');
    }
  }

  // --- findings ---
  const findings = obj.findings;
  if (!Array.isArray(findings)) {
    errors.push('"findings" must be an array.');
  } else {
    findings.forEach((f, idx) => {
      const where = `findings[${idx}]`;
      if (!isRecord(f)) {
        errors.push(`${where} must be an object.`);
        return;
      }
      const id = typeof f.id === 'string' ? f.id : where;
      const at = `finding ${id}`;

      for (const field of ['id', 'title', 'category', 'location', 'affected_endpoint', 'business_impact']) {
        if (typeof f[field] !== 'string') errors.push(`${at}: ${field} must be a string.`);
      }
      if (f.cvss_vector !== null && typeof f.cvss_vector !== 'string') {
        errors.push(`${at}: cvss_vector must be a string or null.`);
      }
      if (typeof f.cvss_vector === 'string' && !f.cvss_vector.startsWith('CVSS:3.')) {
        errors.push(`${at}: cvss_vector must be a CVSS v3.x vector (got "${f.cvss_vector}").`);
      }
      if (f.cwe !== null && typeof f.cwe !== 'string') errors.push(`${at}: cwe must be a string or null.`);
      if (f.owasp !== null && typeof f.owasp !== 'string') errors.push(`${at}: owasp must be a string or null.`);
      if (!SEVERITIES.includes(f.llm_severity as Severity)) {
        errors.push(`${at}: llm_severity must be one of ${SEVERITIES.join(', ')}.`);
      }
      if (!STATUSES.includes(f.status as Status)) {
        errors.push(`${at}: status must be one of ${STATUSES.join(', ')}.`);
      }
      if (!CONFIDENCES.includes(f.confidence as Confidence)) {
        errors.push(`${at}: confidence must be one of ${CONFIDENCES.join(', ')}.`);
      }
      if (!isStringArray(f.chain_prerequisites)) errors.push(`${at}: chain_prerequisites must be a string array.`);
      if (!isStringArray(f.chain_enables)) errors.push(`${at}: chain_enables must be a string array.`);

      const r = f.remediation;
      if (!isRecord(r)) {
        errors.push(`${at}: remediation must be an object.`);
      } else {
        for (const field of ['summary', 'detail', 'verification']) {
          if (typeof r[field] !== 'string') errors.push(`${at}: remediation.${field} must be a string.`);
        }
        if (!PRIORITIES.includes(r.priority as Priority)) {
          errors.push(`${at}: remediation.priority must be one of ${PRIORITIES.join(', ')}.`);
        }
      }
    });
  }

  if (errors.length > 0) return { ok: false, errors };
  return { ok: true, doc: obj as unknown as FindingsDocument };
}
