// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Detect which deterministic white-box scanners are installed. Everything is
 * best-effort: a missing tool is simply skipped, never an error.
 */

import { $ } from 'zx';
import chalk from 'chalk';
import type { WhiteboxToolAvailability } from './types.js';

async function commandExists(cmd: string): Promise<boolean> {
  try {
    await $({ nothrow: true, stdio: ['ignore', 'ignore', 'ignore'] })`command -v ${cmd}`.then((r) => {
      if (r.exitCode !== 0) throw new Error('not found');
    });
    return true;
  } catch {
    return false;
  }
}

export async function detectWhiteboxTools(): Promise<WhiteboxToolAvailability> {
  console.log(chalk.blue('🔧 Checking white-box tool availability...'));

  const osvScanner = await commandExists('osv-scanner');
  const gitleaks = await commandExists('gitleaks');

  let semgrep = await commandExists('semgrep');
  let semgrepViaPython = false;
  if (!semgrep) {
    // semgrep is also usable as a python module even when the CLI shim is absent
    try {
      const r = await $({ nothrow: true, stdio: ['ignore', 'ignore', 'ignore'] })`python3 -c ${'import semgrep'}`;
      if (r.exitCode === 0) {
        semgrep = true;
        semgrepViaPython = true;
      }
    } catch {
      /* not available */
    }
  }

  const report = (name: string, ok: boolean): void =>
    console.log(ok ? chalk.green(`  ✅ ${name} - available`) : chalk.yellow(`  ⚠️ ${name} - not found (skipped)`));
  report('osv-scanner', osvScanner);
  report('gitleaks', gitleaks);
  report('semgrep', semgrep);

  return { osvScanner, gitleaks, semgrep, semgrepViaPython };
}
