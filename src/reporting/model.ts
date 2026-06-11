// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Assemble a {@link ReportModel} from a validated {@link FindingsDocument}.
 *
 * This is where "TypeScript computes": CVSS scores are derived from vectors,
 * severities from scores, attack chains stitched, and all aggregations built.
 * The findings document carries only the LLM's judgment.
 */

import chalk from 'chalk';
import { cvssBaseScore, scoreFromSeverity, severityFromScore } from './cvss.js';
import { buildChains } from './attack-chains.js';
import {
  byCategory,
  owaspCoverage,
  postureGrade,
  roadmap,
  scopeCoverage,
  severityCounts,
} from './aggregations.js';
import type {
  ComputedFinding,
  FindingsDocument,
  ReportModel,
  Severity,
  Status,
} from './types.js';

const REPORTED_STATUSES: Status[] = ['Exploited', 'Blocked_by_Security'];

function computeFinding(f: FindingsDocument['findings'][number]): ComputedFinding {
  let cvss_score: number;
  let severity: Severity;

  if (f.cvss_vector) {
    try {
      cvss_score = cvssBaseScore(f.cvss_vector);
      severity = severityFromScore(cvss_score);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.log(chalk.yellow(`⚠️ Finding ${f.id}: invalid CVSS vector, falling back to llm_severity (${msg})`));
      cvss_score = scoreFromSeverity(f.llm_severity);
      severity = f.llm_severity;
    }
  } else {
    cvss_score = scoreFromSeverity(f.llm_severity);
    severity = f.llm_severity;
  }

  return {
    ...f,
    cvss_score,
    severity,
    evidence_ref: `#${f.id.toLowerCase()}`,
  };
}

export function buildReportModel(doc: FindingsDocument): ReportModel {
  const findings = doc.findings.map(computeFinding);
  const reported = findings.filter((f) => REPORTED_STATUSES.includes(f.status));

  return {
    assessment: doc.assessment,
    findings,
    reported,
    severityCounts: severityCounts(reported),
    byCategory: byCategory(reported),
    owaspCoverage: owaspCoverage(reported),
    scopeCoverage: scopeCoverage(reported),
    roadmap: roadmap(reported),
    chains: buildChains(reported),
    postureGrade: postureGrade(reported),
  };
}
