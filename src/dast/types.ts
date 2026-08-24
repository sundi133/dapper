// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Shared types for the deterministic DAST (dynamic) probe subsystem.
 *
 * This augments Dapper's LLM-driven live testing with deterministic, repeatable
 * black-box probes by orchestrating off-the-shelf scanners against the running
 * target — covering categories the agents don't otherwise cover, and cheap
 * systematic sweeps that would waste agent tokens:
 *   - nuclei     -> XXE, SSTI, CORS, open-redirect, security-headers,
 *                   sensitive files / exposures, GraphQL, file-upload, misc CVEs
 *   - testssl.sh -> deep TLS/SSL configuration and chain issues
 *   - retire.js  -> vulnerable client-side JavaScript libraries (JS-lib CVEs)
 *
 * Results are written as deterministic deliverables and folded into the recon
 * deliverable so the existing LLM vuln/exploit agents prioritise and validate
 * the confirmed live signals rather than discovering them blind.
 *
 * Data-only: no side effects, no Node imports.
 */

export type DastSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

/** A single normalized DAST finding from any tool. */
export interface DastFinding {
  tool: 'nuclei' | 'testssl' | 'retire';
  id: string; // nuclei template-id / testssl id / retire component@version
  /** Normalized bucket: 'cors' | 'open-redirect' | 'ssti' | 'xxe' | 'security-headers'
   *  | 'exposure' | 'tls' | 'graphql' | 'file-upload' | 'js-lib-cve' | 'other' */
  category: string;
  name: string;
  severity: DastSeverity;
  matchedAt: string; // URL / host:port where the issue was observed
  description: string;
  cve: string[];
  cwe: string[];
  reference: string[];
  evidence: string; // short, safe extract (matched value / header / library@version)
}

/** The full deterministic DAST result set. */
export interface DastAnalysis {
  generatedAt: string;
  target: string;
  toolsRun: { nuclei: boolean; testssl: boolean; retire: boolean };
  toolsSkipped: string[];
  findings: DastFinding[];
  errors: string[]; // non-fatal per-tool errors, for transparency
}

export interface DastToolAvailability {
  nuclei: boolean;
  testssl: boolean; // testssl.sh (or `testssl`)
  testsslCmd: string; // resolved command ('testssl.sh' | 'testssl' | '')
  retire: boolean; // retire.js CLI (or via npx)
  retireViaNpx: boolean;
}
