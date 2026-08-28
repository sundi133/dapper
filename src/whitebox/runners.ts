// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Guarded runners for each deterministic scanner. Every runner:
 *   - captures stdout even when the tool exits non-zero on findings (`nothrow`),
 *   - never throws (returns { json: null, error } on failure),
 *   - so an absent/broken tool can never break the pipeline.
 */

import { $, fs, path } from 'zx';
import * as os from 'node:os';
import { SEMGREP_RULESET_YAML } from './rules.js';

export interface RunnerResult {
  json: string | null;
  error?: string;
}

function firstLine(s: string | undefined): string {
  return (s || '').split('\n').map((l) => l.trim()).filter(Boolean)[0] ?? '';
}
function msg(e: unknown): string {
  if (e && typeof e === 'object' && 'message' in e) return String((e as { message: unknown }).message);
  return String(e);
}
function tmpFile(name: string): string {
  return path.join(os.tmpdir(), `dapper-${name}-${process.pid}`);
}

/** Dependency CVE / SCA (capability 1.5). */
export async function runOsvScanner(scanRoot: string): Promise<RunnerResult> {
  try {
    const r = await $({ nothrow: true, stdio: ['ignore', 'pipe', 'pipe'] })`osv-scanner --format json -r ${scanRoot}`;
    const out = (r.stdout || '').trim();
    if (out) return { json: out };
    const err = firstLine(r.stderr);
    return err ? { json: null, error: `osv-scanner: ${err}` } : { json: null };
  } catch (e) {
    return { json: null, error: `osv-scanner failed: ${msg(e)}` };
  }
}

/** Hardcoded secrets (capability 1.1, secrets). */
export async function runGitleaks(scanRoot: string): Promise<RunnerResult> {
  const report = tmpFile('gitleaks.json');
  try {
    await $({
      nothrow: true,
      stdio: ['ignore', 'pipe', 'pipe'],
    })`gitleaks detect --no-git --source ${scanRoot} --report-format json --report-path ${report} --redact`;
    if (await fs.pathExists(report)) {
      const j = await fs.readFile(report, 'utf8');
      await fs.remove(report).catch(() => undefined);
      return { json: j };
    }
    return { json: null };
  } catch (e) {
    await fs.remove(report).catch(() => undefined);
    return { json: null, error: `gitleaks failed: ${msg(e)}` };
  }
}

/** SAST sinks (1.1) + taint/dataflow (1.2) + reachability (1.3) + authz (1.4). */
export async function runSemgrep(scanRoot: string, viaPython: boolean): Promise<RunnerResult> {
  const rulesFile = tmpFile('semgrep-rules.yaml');
  try {
    await fs.writeFile(rulesFile, SEMGREP_RULESET_YAML, 'utf8');
    const bin = viaPython ? ['python3', '-m', 'semgrep'] : ['semgrep'];
    const args = [
      '--config',
      rulesFile,
      '--json',
      '--dataflow-traces', // ensure taint-mode findings include source->sink traces (caps 1.2/1.3)
      '--quiet',
      '--no-git-ignore',
      '--timeout',
      '30',
      '--max-target-bytes',
      '2000000',
      '--disable-version-check',
      scanRoot,
    ];
    const r = await $({ nothrow: true, stdio: ['ignore', 'pipe', 'pipe'] })`${bin} ${args}`;
    await fs.remove(rulesFile).catch(() => undefined);
    const out = (r.stdout || '').trim();
    if (out) return { json: out };
    const err = firstLine(r.stderr);
    return err ? { json: null, error: `semgrep: ${err}` } : { json: null };
  } catch (e) {
    await fs.remove(rulesFile).catch(() => undefined);
    return { json: null, error: `semgrep failed: ${msg(e)}` };
  }
}
