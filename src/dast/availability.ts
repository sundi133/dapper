// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Detect which deterministic DAST scanners are installed. Best-effort: a missing
 * tool is skipped, never an error.
 */

import { $ } from 'zx';
import chalk from 'chalk';
import type { DastToolAvailability } from './types.js';

async function commandExists(cmd: string): Promise<boolean> {
  try {
    const r = await $({ nothrow: true, stdio: ['ignore', 'ignore', 'ignore'] })`command -v ${cmd}`;
    return r.exitCode === 0;
  } catch {
    return false;
  }
}

export async function detectDastTools(): Promise<DastToolAvailability> {
  console.log(chalk.blue('🔧 Checking DAST tool availability...'));

  const nuclei = await commandExists('nuclei');

  // testssl ships as `testssl.sh` or (packaged) `testssl`
  let testsslCmd = '';
  if (await commandExists('testssl.sh')) testsslCmd = 'testssl.sh';
  else if (await commandExists('testssl')) testsslCmd = 'testssl';
  const testssl = testsslCmd !== '';

  const retire = await commandExists('retire');
  const retireViaNpx = retire; // only the direct binary is used; npx auto-install is avoided offline

  const report = (name: string, ok: boolean): void =>
    console.log(ok ? chalk.green(`  ✅ ${name} - available`) : chalk.yellow(`  ⚠️ ${name} - not found (skipped)`));
  report('nuclei', nuclei);
  report('testssl', testssl);
  report('retire.js', retire);

  return { nuclei, testssl, testsslCmd, retire, retireViaNpx };
}
