// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Guarded runners for each DAST scanner. Every runner captures output even when
 * the tool exits non-zero on findings (`nothrow`) and never throws, so an
 * absent/broken tool can never break the pipeline. nuclei is rate-limited so we
 * never hammer the target.
 */

import { $, fs, path } from 'zx';
import * as os from 'node:os';

export interface RunnerResult {
  json: string | null; // JSON (retire/testssl) or JSONL (nuclei)
  error?: string;
}

// Template tags aligned to the ADD group: XXE, SSTI, CORS, open-redirect,
// GraphQL, file-upload, TLS, security-headers, sensitive files / exposures.
// nuclei tags are exact-match, so every real variant is listed explicitly
// (e.g. both `fileupload` and `file-upload`) to avoid silent coverage gaps.
const NUCLEI_TAGS = [
  'cors',
  'redirect',
  'open-redirect', // open-redirect (2.9)
  'ssti', // server-side template injection (2.5)
  'xxe', // XML external entity (2.4)
  'graphql', // GraphQL (2.12)
  'fileupload',
  'file-upload', // file upload (2.14) — real variant, ~133 templates
  'upload',
  'exposure', // sensitive files / exposures (2.17)
  'exposures',
  'disclosure', // info disclosure (2.17) — ~176 templates
  'backup', // backup files (2.17)
  'files', // exposed files (2.17) — ~133 templates
  'misconfig', // includes the missing-security-headers template (2.16)
  'headers', // security headers (2.16)
  'hsts',
  'ssl', // TLS/SSL (2.15)
  'tls', // TLS/SSL (2.15) — real variant, ~41 templates
].join(',');

// Conservative safety limits so we never flood a customer target.
const NUCLEI_RATE_LIMIT = '40'; // requests/sec
const NUCLEI_CONCURRENCY = '20';

function firstLine(s: string | undefined): string {
  return (s || '').split('\n').map((l) => l.trim()).filter(Boolean)[0] ?? '';
}
function msg(e: unknown): string {
  if (e && typeof e === 'object' && 'message' in e) return String((e as { message: unknown }).message);
  return String(e);
}
function tmpFile(name: string): string {
  return path.join(os.tmpdir(), `dapper-dast-${name}-${process.pid}`);
}

// Hard wall-clock caps so a scan can never run unbounded inside the activity.
// nuclei streams JSONL to a file, so partial results survive a cap.
const NUCLEI_MAX_DURATION = '900s'; // 15 min
const TESTSSL_MAX_DURATION = '600s'; // 10 min

/** nuclei — covers XXE/SSTI/CORS/redirect/headers/exposures/graphql/upload/TLS + CVEs. */
export async function runNuclei(targetUrl: string): Promise<RunnerResult> {
  const report = tmpFile('nuclei.jsonl');
  try {
    // In the container, templates are pre-downloaded to a fixed path (NUCLEI_TEMPLATES_DIR);
    // locally, nuclei uses its own default store. Only pass -t when the dir actually exists.
    const templatesDir = process.env['NUCLEI_TEMPLATES_DIR'] ?? '';
    const templatesArgs =
      templatesDir && (await fs.pathExists(templatesDir)) ? ['-t', templatesDir] : [];
    const argv = [
      'nuclei',
      '-u',
      targetUrl,
      ...templatesArgs,
      '-tags',
      NUCLEI_TAGS,
      '-jsonl',
      '-o',
      report, // write incrementally so a timeout still leaves partial findings
      '-silent',
      '-rate-limit',
      NUCLEI_RATE_LIMIT,
      '-concurrency',
      NUCLEI_CONCURRENCY,
      '-timeout',
      '10',
      '-retries',
      '1',
      '-no-interactsh', // do not phone home to a public OOB server during a client engagement
      '-disable-update-check',
    ];
    try {
      await $({ nothrow: true, stdio: ['ignore', 'pipe', 'pipe'] })`${argv}`.timeout(NUCLEI_MAX_DURATION);
    } catch {
      /* timed out or errored — partial findings already streamed to the file */
    }
    if (await fs.pathExists(report)) {
      const j = await fs.readFile(report, 'utf8');
      await fs.remove(report).catch(() => undefined);
      return { json: j.trim() || null };
    }
    return { json: null };
  } catch (e) {
    await fs.remove(report).catch(() => undefined);
    return { json: null, error: `nuclei failed: ${msg(e)}` };
  }
}

/** testssl.sh — deep TLS/SSL configuration and chain issues. */
export async function runTestssl(testsslCmd: string, hostPort: string): Promise<RunnerResult> {
  const report = tmpFile('testssl.json');
  try {
    const argv = [
      testsslCmd,
      '--quiet',
      '--color',
      '0',
      '--warnings',
      'batch', // non-interactive; never prompt
      '--fast', // skip exhaustive cipher enumeration to stay bounded
      '--jsonfile-pretty',
      report,
      hostPort,
    ];
    try {
      await $({ nothrow: true, stdio: ['ignore', 'pipe', 'pipe'] })`${argv}`.timeout(TESTSSL_MAX_DURATION);
    } catch {
      /* timed out or errored — partial findings already written to the file */
    }
    if (await fs.pathExists(report)) {
      const j = await fs.readFile(report, 'utf8');
      await fs.remove(report).catch(() => undefined);
      return { json: j };
    }
    return { json: null };
  } catch (e) {
    await fs.remove(report).catch(() => undefined);
    return { json: null, error: `testssl failed: ${msg(e)}` };
  }
}

/** retire.js — vulnerable client-side JS libraries in a directory of downloaded scripts. */
export async function runRetire(jsDir: string): Promise<RunnerResult> {
  const report = tmpFile('retire.json');
  try {
    const argv = ['retire', '--path', jsDir, '--outputformat', 'json', '--outputpath', report];
    await $({ nothrow: true, stdio: ['ignore', 'pipe', 'pipe'] })`${argv}`;
    if (await fs.pathExists(report)) {
      const j = await fs.readFile(report, 'utf8');
      await fs.remove(report).catch(() => undefined);
      return { json: j };
    }
    return { json: null };
  } catch (e) {
    await fs.remove(report).catch(() => undefined);
    return { json: null, error: `retire failed: ${msg(e)}` };
  }
}
