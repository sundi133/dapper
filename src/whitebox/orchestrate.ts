// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Orchestrates the deterministic white-box pass end to end:
 * detect tools -> run scanners (guarded) -> parse -> assemble -> write.
 *
 * Best-effort throughout: returns null when there is nothing to do, and
 * `writeWhiteboxDeliverables` folds a concise summary into the pre-recon
 * deliverable idempotently so downstream LLM agents ingest it.
 */

import { fs, path } from 'zx';
import chalk from 'chalk';
import type { WhiteboxAnalysis } from './types.js';
import { detectWhiteboxTools } from './availability.js';
import { runOsvScanner, runGitleaks, runSemgrep } from './runners.js';
import { parseOsvScanner, parseGitleaks, parseSemgrep } from './parsers.js';
import { renderWhiteboxMarkdown, renderPreReconSection, WHITEBOX_SECTION_MARKER } from './render.js';

export interface WhiteboxRunOptions {
  /** Repository root (working dir; where deliverables/ lives). */
  repoPath: string;
  /** Optional subdirectory to scope the source scan to. */
  subDir?: string;
  /** ISO timestamp (passed in so the caller controls it). */
  generatedAt: string;
}

/**
 * Run all available scanners and assemble a WhiteboxAnalysis.
 * Returns null when no scanners are installed or the source path is missing.
 */
export async function runWhiteboxAnalysis(opts: WhiteboxRunOptions): Promise<WhiteboxAnalysis | null> {
  const scanRoot = opts.subDir ? path.join(opts.repoPath, opts.subDir) : opts.repoPath;

  if (!(await fs.pathExists(scanRoot))) {
    console.log(chalk.gray(`    ⏭️ White-box: source path not found (${scanRoot}), skipping`));
    return null;
  }

  const avail = await detectWhiteboxTools();
  if (!avail.osvScanner && !avail.gitleaks && !avail.semgrep) {
    console.log(chalk.gray('    ⏭️ White-box: no scanners installed, skipping (install osv-scanner / gitleaks / semgrep to enable)'));
    return null;
  }

  const analysis: WhiteboxAnalysis = {
    generatedAt: opts.generatedAt,
    repoPath: scanRoot,
    toolsRun: { osvScanner: false, gitleaks: false, semgrep: false },
    toolsSkipped: [],
    cve: [],
    secrets: [],
    sast: [],
    taint: [],
    authz: [],
    errors: [],
  };

  // 1.5 — dependency CVEs
  if (avail.osvScanner) {
    console.log(chalk.blue('    🔍 osv-scanner (dependency CVEs)...'));
    const { json, error } = await runOsvScanner(scanRoot);
    analysis.toolsRun.osvScanner = true;
    if (json) analysis.cve = parseOsvScanner(json);
    if (error) analysis.errors.push(error);
  } else {
    analysis.toolsSkipped.push('osv-scanner');
  }

  // 1.1 (secrets) — gitleaks
  if (avail.gitleaks) {
    console.log(chalk.blue('    🔍 gitleaks (hardcoded secrets)...'));
    const { json, error } = await runGitleaks(scanRoot);
    analysis.toolsRun.gitleaks = true;
    if (json) analysis.secrets = parseGitleaks(json);
    if (error) analysis.errors.push(error);
  } else {
    analysis.toolsSkipped.push('gitleaks');
  }

  // 1.1 (sinks) + 1.2 (taint) + 1.3 (reachability) + 1.4 (authz) — semgrep
  if (avail.semgrep) {
    console.log(chalk.blue('    🔍 semgrep (SAST / taint / authz surface)...'));
    const { json, error } = await runSemgrep(scanRoot, avail.semgrepViaPython);
    analysis.toolsRun.semgrep = true;
    if (json) {
      const parsed = parseSemgrep(json);
      analysis.sast = parsed.sast;
      analysis.taint = parsed.taint;
      analysis.authz = parsed.authz;
    }
    if (error) analysis.errors.push(error);
  } else {
    analysis.toolsSkipped.push('semgrep');
  }

  return analysis;
}

/**
 * Deliverable files the downstream LLM agents actually read as their pre-recon
 * context, so the white-box summary must land in these to drive prioritisation
 * and validation (capabilities 1.6 / 1.7):
 *   - code_analysis_deliverable.md — the pre-recon agent's real output; read by
 *     the threat-model agent and several vuln agents. Exists on the Temporal path.
 *   - pre_recon_deliverable.md — referenced by recon + the offensive vuln agents
 *     (injection/authz/xss/ssrf/…), but NOT created on the Temporal path, so we
 *     create it here as a white-box supplement rather than let those agents read
 *     a missing file.
 */
const FOLD_TARGETS: Array<{ name: string; title: string }> = [
  { name: 'code_analysis_deliverable.md', title: 'Code Analysis' },
  { name: 'pre_recon_deliverable.md', title: 'Pre-Reconnaissance' },
];

/**
 * Persist the analysis as standalone deliverables and fold a concise summary
 * into the pre-recon-family deliverables the agents read. Idempotent (marker-
 * guarded) so it is safe across Temporal activity retries.
 */
export async function writeWhiteboxDeliverables(analysis: WhiteboxAnalysis, repoPath: string): Promise<void> {
  const deliverablesDir = path.join(repoPath, 'deliverables');
  await fs.ensureDir(deliverablesDir);

  // Standalone deterministic deliverables (always written).
  await fs.writeFile(
    path.join(deliverablesDir, 'whitebox_findings.json'),
    JSON.stringify(analysis, null, 2)
  );
  await fs.writeFile(path.join(deliverablesDir, 'whitebox_analysis.md'), renderWhiteboxMarkdown(analysis));

  // Fold the concise block into each target the LLM agents read (idempotent).
  const section = renderPreReconSection(analysis);
  for (const target of FOLD_TARGETS) {
    const p = path.join(deliverablesDir, target.name);
    if (await fs.pathExists(p)) {
      const existing = await fs.readFile(p, 'utf8');
      if (!existing.includes(WHITEBOX_SECTION_MARKER)) {
        await fs.appendFile(p, `\n\n${section}\n`);
      }
    } else {
      // File not produced on this path — create it so the agents that read it
      // still receive the deterministic white-box intel. Clearly labelled as a
      // supplement; full external recon lives in recon_deliverable.md.
      const header = `# ${target.title} (deterministic white-box supplement)\n\n_External scan output (nmap/whatweb) and dynamic recon are in recon_deliverable.md._\n\n`;
      await fs.writeFile(p, `${header}${section}\n`);
    }
  }
}
