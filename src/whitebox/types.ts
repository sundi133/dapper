// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Shared types for the deterministic white-box analysis subsystem.
 *
 * This subsystem augments Dapper's LLM-driven source review with deterministic,
 * repeatable static analysis by orchestrating off-the-shelf scanners:
 *   - osv-scanner  -> dependency CVE / SCA         (capability 1.5)
 *   - gitleaks     -> hardcoded secrets            (capability 1.1, secrets)
 *   - semgrep      -> dangerous sinks (SAST)       (capability 1.1, sinks)
 *                     interprocedural taint/dataflow (capability 1.2)
 *                     reachability annotation      (capability 1.3)
 *                     authorization surface        (capability 1.4)
 *
 * The results are written as deterministic deliverables and folded into the
 * pre-recon deliverable so the existing LLM agents (threat-model, vuln, report)
 * prioritise and validate them (capabilities 1.6 / 1.7) with no prompt changes.
 *
 * Everything here is data-only; no side effects, no Node imports.
 */

export type WhiteboxSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

/** A dependency vulnerability from osv-scanner. */
export interface CveFinding {
  packageName: string;
  ecosystem: string;
  installedVersion: string;
  vulnId: string; // primary id (CVE / GHSA / OSV id)
  aliases: string[];
  summary: string;
  severity: WhiteboxSeverity;
  fixedVersion?: string;
  referenceUrl?: string;
  manifestPath?: string;
}

/** A hardcoded secret from gitleaks (value always redacted). */
export interface SecretFinding {
  ruleId: string;
  description: string;
  file: string;
  startLine: number;
  secretPreview: string; // redacted / truncated, never the full secret
  entropy?: number;
}

export interface CodeLocation {
  file: string;
  line: number;
}

/** A dangerous-sink / SAST finding from semgrep (no dataflow trace). */
export interface SastFinding {
  ruleId: string;
  category: string; // e.g. 'sqli', 'command-injection', 'xss', 'ssrf', 'crypto'
  severity: WhiteboxSeverity;
  message: string;
  location: CodeLocation;
  cwe: string[];
  owasp: string[];
}

export interface DataflowStep {
  file: string;
  line: number;
  content?: string;
}

/**
 * An interprocedural taint finding from semgrep taint-mode: untrusted input
 * (source) reaching a dangerous operation (sink), with a reachability signal.
 */
export interface TaintFinding {
  ruleId: string;
  category: string;
  severity: WhiteboxSeverity;
  message: string;
  source: DataflowStep;
  sink: DataflowStep;
  intermediate: DataflowStep[];
  /** True when the taint source is untrusted HTTP input (capability 1.3). */
  reachableFromInternet: boolean;
  sourceKind: string; // 'http-input' | 'unknown'
  cwe: string[];
  owasp: string[];
}

/** A row in the authorization surface map (capability 1.4). */
export interface AuthzRoute {
  file: string;
  line: number;
  method?: string;
  route?: string;
  guarded: boolean; // whether an auth/permission check was detected
  note: string;
}

/** The full deterministic white-box result set. */
export interface WhiteboxAnalysis {
  generatedAt: string;
  repoPath: string;
  toolsRun: { osvScanner: boolean; gitleaks: boolean; semgrep: boolean };
  toolsSkipped: string[];
  cve: CveFinding[];
  secrets: SecretFinding[];
  sast: SastFinding[];
  taint: TaintFinding[];
  authz: AuthzRoute[];
  errors: string[]; // non-fatal per-tool errors, for transparency
}

export interface WhiteboxToolAvailability {
  osvScanner: boolean;
  gitleaks: boolean;
  /** semgrep is invokable either as `semgrep` or `python3 -m semgrep`. */
  semgrep: boolean;
  semgrepViaPython: boolean;
}
