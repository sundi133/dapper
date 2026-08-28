// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Orchestrates the deterministic DAST pass end to end: detect tools -> run
 * scanners (guarded) -> parse -> assemble -> write. Best-effort throughout;
 * folds a concise summary into recon_deliverable.md (idempotent) so the LLM
 * vuln/exploit agents prioritise and validate the confirmed live signals.
 */

import { fs, path } from 'zx';
import chalk from 'chalk';
import type { DastAnalysis } from './types.js';
import { detectDastTools } from './availability.js';
import { runNuclei, runTestssl, runRetire } from './runners.js';
import { parseNuclei, parseTestssl, parseRetire } from './parsers.js';
import { fetchServedScripts } from './fetch-js.js';
import { renderDastMarkdown, renderReconSection, DAST_SECTION_MARKER } from './render.js';

export interface DastRunOptions {
  /** The live target URL (http/https). */
  target: string;
  /** ISO timestamp (caller-controlled). */
  generatedAt: string;
}

/** Derive host:port for testssl. Defaults to 443 (most sites also serve TLS). */
function toHostPort(target: string): string | null {
  try {
    const u = new URL(target);
    const port = u.port || '443';
    return u.hostname ? `${u.hostname}:${port}` : null;
  } catch {
    return null;
  }
}

/**
 * Run all available DAST scanners against the target and assemble a DastAnalysis.
 * Returns null when the target is invalid or no scanners are installed.
 */
export async function runDastAnalysis(opts: DastRunOptions): Promise<DastAnalysis | null> {
  try {
    new URL(opts.target);
  } catch {
    console.log(chalk.gray(`    ⏭️ DAST: invalid target URL (${opts.target}), skipping`));
    return null;
  }

  const avail = await detectDastTools();
  if (!avail.nuclei && !avail.testssl && !avail.retire) {
    console.log(chalk.gray('    ⏭️ DAST: no scanners installed, skipping (install nuclei / testssl.sh / retire to enable)'));
    return null;
  }

  const analysis: DastAnalysis = {
    generatedAt: opts.generatedAt,
    target: opts.target,
    toolsRun: { nuclei: false, testssl: false, retire: false },
    toolsSkipped: [],
    findings: [],
    errors: [],
  };

  // nuclei — the workhorse (most of the ADD group)
  if (avail.nuclei) {
    console.log(chalk.blue('    🔍 nuclei (CORS/redirect/SSTI/XXE/headers/exposures/graphql/upload/TLS)...'));
    const { json, error } = await runNuclei(opts.target);
    analysis.toolsRun.nuclei = true;
    if (json) analysis.findings.push(...parseNuclei(json));
    if (error) analysis.errors.push(error);
  } else {
    analysis.toolsSkipped.push('nuclei');
  }

  // testssl.sh — deep TLS
  if (avail.testssl) {
    const hostPort = toHostPort(opts.target);
    analysis.toolsRun.testssl = true;
    if (hostPort) {
      console.log(chalk.blue(`    🔍 testssl.sh (${hostPort})...`));
      const { json, error } = await runTestssl(avail.testsslCmd, hostPort);
      if (json) analysis.findings.push(...parseTestssl(json, hostPort));
      if (error) analysis.errors.push(error);
    }
  } else {
    analysis.toolsSkipped.push('testssl');
  }

  // retire.js — vulnerable client-side JS libraries (fetch served JS, then scan)
  if (avail.retire) {
    analysis.toolsRun.retire = true;
    console.log(chalk.blue('    🔍 retire.js (vulnerable client-side libraries)...'));
    const fetched = await fetchServedScripts(opts.target);
    if (fetched) {
      const urlByPath = new Map<string, string>();
      for (const s of fetched.manifest) {
        urlByPath.set(s.localPath, s.url);
        urlByPath.set(path.basename(s.localPath), s.url);
      }
      const { json, error } = await runRetire(fetched.dir);
      if (json) {
        analysis.findings.push(
          ...parseRetire(json, (file) => urlByPath.get(file) ?? urlByPath.get(path.basename(file)) ?? '')
        );
      }
      if (error) analysis.errors.push(error);
      await fs.remove(fetched.dir).catch(() => undefined);
    } else {
      analysis.errors.push('retire: no served JavaScript could be fetched from the target');
    }
  } else {
    analysis.toolsSkipped.push('retire');
  }

  return analysis;
}

/**
 * Persist the analysis and fold a concise summary into recon_deliverable.md,
 * which all vuln agents read. Idempotent (marker-guarded) for Temporal retries.
 */
export async function writeDastDeliverables(analysis: DastAnalysis, repoPath: string): Promise<void> {
  const deliverablesDir = path.join(repoPath, 'deliverables');
  await fs.ensureDir(deliverablesDir);

  await fs.writeFile(path.join(deliverablesDir, 'dast_findings.json'), JSON.stringify(analysis, null, 2));
  await fs.writeFile(path.join(deliverablesDir, 'dast_analysis.md'), renderDastMarkdown(analysis));

  const section = renderReconSection(analysis);
  const reconPath = path.join(deliverablesDir, 'recon_deliverable.md');
  if (await fs.pathExists(reconPath)) {
    const existing = await fs.readFile(reconPath, 'utf8');
    if (!existing.includes(DAST_SECTION_MARKER)) {
      await fs.appendFile(reconPath, `\n\n${section}\n`);
    }
  } else {
    // recon deliverable not produced on this path — create it so the vuln agents
    // (which read recon_deliverable.md) still receive the deterministic DAST intel.
    const header =
      '# Reconnaissance (deterministic DAST supplement)\n\n_Full recon is in the agent-produced report; this file carries the deterministic scanner findings._\n\n';
    await fs.writeFile(reconPath, `${header}${section}\n`);
  }
}
