// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * CVSS v3.1 base score computation (FIRST.org specification §7.1).
 *
 * Pure functions only. `cvssBaseScore` returns a number 0.0–10.0 and throws on
 * an unparseable vector; `severityFromScore` maps a score to the qualitative
 * severity band.
 */

import type { Severity } from './types.js';

const AV: Record<string, number> = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 };
const AC: Record<string, number> = { L: 0.77, H: 0.44 };
const UI: Record<string, number> = { N: 0.85, R: 0.62 };
const CIA: Record<string, number> = { H: 0.56, L: 0.22, N: 0.0 };
// Privileges Required depends on Scope.
const PR_UNCHANGED: Record<string, number> = { N: 0.85, L: 0.62, H: 0.27 };
const PR_CHANGED: Record<string, number> = { N: 0.85, L: 0.68, H: 0.5 };

interface Metrics {
  AV: string;
  AC: string;
  PR: string;
  UI: string;
  S: string;
  C: string;
  I: string;
  A: string;
}

const REQUIRED_METRICS: (keyof Metrics)[] = ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A'];

function parseVector(vector: string): Metrics {
  if (typeof vector !== 'string' || !vector.startsWith('CVSS:3.')) {
    throw new Error(`Invalid CVSS v3.1 vector: ${vector}`);
  }
  const parts = vector.split('/').slice(1); // drop "CVSS:3.1"
  const map: Record<string, string> = {};
  for (const part of parts) {
    const [key, value] = part.split(':');
    if (key && value) map[key] = value;
  }
  for (const m of REQUIRED_METRICS) {
    if (!map[m]) throw new Error(`CVSS vector missing required base metric ${m}: ${vector}`);
  }
  return map as unknown as Metrics;
}

/**
 * Official CVSS v3.1 "roundup": round up to one decimal place using integer
 * arithmetic to avoid binary float error (spec Appendix A).
 */
function roundup(input: number): number {
  const intInput = Math.round(input * 100000);
  if (intInput % 10000 === 0) {
    return intInput / 100000;
  }
  return (Math.floor(intInput / 10000) + 1) / 10;
}

export function cvssBaseScore(vector: string): number {
  const m = parseVector(vector);
  const scopeChanged = m.S === 'C';

  const av = AV[m.AV];
  const ac = AC[m.AC];
  const ui = UI[m.UI];
  const pr = (scopeChanged ? PR_CHANGED : PR_UNCHANGED)[m.PR];
  const c = CIA[m.C];
  const i = CIA[m.I];
  const a = CIA[m.A];

  if (av === undefined || ac === undefined || ui === undefined || pr === undefined ||
      c === undefined || i === undefined || a === undefined) {
    throw new Error(`Invalid CVSS metric value in vector: ${vector}`);
  }

  const iss = 1 - (1 - c) * (1 - i) * (1 - a);

  let impact: number;
  if (scopeChanged) {
    impact = 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
  } else {
    impact = 6.42 * iss;
  }

  const exploitability = 8.22 * av * ac * pr * ui;

  if (impact <= 0) return 0.0;

  const raw = scopeChanged
    ? Math.min(1.08 * (impact + exploitability), 10)
    : Math.min(impact + exploitability, 10);

  return roundup(raw);
}

export function severityFromScore(score: number): Severity {
  if (score >= 9.0) return 'Critical';
  if (score >= 7.0) return 'High';
  if (score >= 4.0) return 'Medium';
  if (score >= 0.1) return 'Low';
  return 'Informational';
}

/** Representative score used when no valid CVSS vector is available. */
export function scoreFromSeverity(severity: Severity): number {
  switch (severity) {
    case 'Critical':
      return 9.5;
    case 'High':
      return 8.0;
    case 'Medium':
      return 5.5;
    case 'Low':
      return 2.5;
    case 'Informational':
    default:
      return 0.0;
  }
}
