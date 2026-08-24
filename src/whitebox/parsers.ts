// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Pure parsers: raw scanner JSON -> normalized white-box findings.
 *
 * Every parser is defensive (tolerates version drift and malformed input) and
 * total (returns [] rather than throwing). No side effects, no Node imports —
 * these are the unit-testable core of the white-box subsystem.
 */

import type {
  CveFinding,
  SecretFinding,
  SastFinding,
  TaintFinding,
  AuthzRoute,
  WhiteboxSeverity,
  DataflowStep,
} from './types.js';
import { classifyTaintSource } from './reachability.js';
import { buildAuthzRoute } from './authz-graph.js';

// ---------------------------------------------------------------------------
// small, total helpers
// ---------------------------------------------------------------------------

function safeJsonParse(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}
function asRecord(v: unknown): Record<string, unknown> | null {
  return v !== null && typeof v === 'object' && !Array.isArray(v)
    ? (v as Record<string, unknown>)
    : null;
}
function asArray(v: unknown): unknown[] {
  return Array.isArray(v) ? v : [];
}
function asString(v: unknown): string {
  return typeof v === 'string' ? v : '';
}
function asNumber(v: unknown): number {
  return typeof v === 'number' && Number.isFinite(v) ? v : 0;
}

// ---------------------------------------------------------------------------
// severity mapping
// ---------------------------------------------------------------------------

/** Map an OSV / GHSA severity string OR a CVSS numeric score to a band. */
export function mapOsvSeverity(s: string): WhiteboxSeverity {
  const u = (s || '').toUpperCase().trim();
  if (u.startsWith('CRIT')) return 'critical';
  if (u.startsWith('HIGH')) return 'high';
  if (u.startsWith('MOD') || u.startsWith('MED')) return 'medium';
  if (u.startsWith('LOW')) return 'low';
  const n = parseFloat(s);
  if (!Number.isNaN(n)) {
    if (n >= 9) return 'critical';
    if (n >= 7) return 'high';
    if (n >= 4) return 'medium';
    if (n > 0) return 'low';
  }
  return 'info';
}

/** Map a semgrep severity (ERROR/WARNING/INFO) to a band. */
export function mapSemgrepSeverity(s: string): WhiteboxSeverity {
  switch ((s || '').toUpperCase()) {
    case 'ERROR':
      return 'high';
    case 'WARNING':
      return 'medium';
    case 'INFO':
      return 'info';
    default:
      return 'low';
  }
}

/**
 * Normalize a semgrep check_id. When rules come from a local file config,
 * semgrep prefixes the id with the (dot-joined) file path, e.g.
 * "var.folders.tmp.dapper-....yaml.dapper-taint-sqli-js". Recover the clean id.
 */
export function normalizeRuleId(checkId: string): string {
  if (!checkId) return '';
  const m = checkId.match(/dapper-[a-z0-9-]+$/);
  if (m) return m[0];
  const idx = checkId.lastIndexOf('.');
  return idx >= 0 ? checkId.slice(idx + 1) : checkId;
}

/** Derive a vuln category from a `dapper-<mode>-<category>-<lang>` rule id. */
export function inferCategory(checkId: string): string {
  const parts = (checkId || '').split('-');
  // dapper-taint-sqli-js -> sqli ; dapper-sink-weak-hash-js -> weak-hash
  if (parts.length >= 4 && parts[0] === 'dapper') {
    return parts.slice(2, parts.length - 1).join('-') || 'sast';
  }
  return 'sast';
}

// ---------------------------------------------------------------------------
// osv-scanner (dependency CVE / SCA) — capability 1.5
// ---------------------------------------------------------------------------

function extractOsvFixed(vuln: Record<string, unknown>): string | undefined {
  for (const aff of asArray(vuln['affected'])) {
    const a = asRecord(aff);
    if (!a) continue;
    for (const range of asArray(a['ranges'])) {
      const r = asRecord(range);
      if (!r) continue;
      for (const ev of asArray(r['events'])) {
        const e = asRecord(ev);
        if (!e) continue;
        const fixed = asString(e['fixed']);
        if (fixed) return fixed;
      }
    }
  }
  return undefined;
}

function extractOsvRef(vuln: Record<string, unknown>, id: string): string | undefined {
  for (const ref of asArray(vuln['references'])) {
    const r = asRecord(ref);
    const url = r ? asString(r['url']) : '';
    if (url) return url;
  }
  return id ? `https://osv.dev/vulnerability/${id}` : undefined;
}

export function parseOsvScanner(jsonText: string): CveFinding[] {
  const root = asRecord(safeJsonParse(jsonText));
  if (!root) return [];
  const out: CveFinding[] = [];

  for (const res of asArray(root['results'])) {
    const r = asRecord(res);
    if (!r) continue;
    const src = asRecord(r['source']);
    const manifestPath = src ? asString(src['path']) : '';

    for (const pkg of asArray(r['packages'])) {
      const p = asRecord(pkg);
      if (!p) continue;
      const packageObj = asRecord(p['package']);
      const name = packageObj ? asString(packageObj['name']) : '';
      const version = packageObj ? asString(packageObj['version']) : '';
      const ecosystem = packageObj ? asString(packageObj['ecosystem']) : '';

      // group max_severity (CVSS number) as a severity fallback, keyed by vuln id
      const groupSevById = new Map<string, string>();
      for (const g of asArray(p['groups'])) {
        const gr = asRecord(g);
        if (!gr) continue;
        const maxSev = asString(gr['max_severity']);
        for (const idv of asArray(gr['ids'])) {
          const s = asString(idv);
          if (s && maxSev) groupSevById.set(s, maxSev);
        }
      }

      for (const vuln of asArray(p['vulnerabilities'])) {
        const v = asRecord(vuln);
        if (!v) continue;
        const id = asString(v['id']);
        const aliases = asArray(v['aliases']).map(asString).filter(Boolean);
        const summary =
          asString(v['summary']) || asString(v['details']).slice(0, 240) || 'Known vulnerability';
        const dbSpec = asRecord(v['database_specific']);
        let sevStr = dbSpec ? asString(dbSpec['severity']) : '';
        if (!sevStr) sevStr = groupSevById.get(id) || '';
        const severity = mapOsvSeverity(sevStr);
        const fixedVersion = extractOsvFixed(v);
        const referenceUrl = extractOsvRef(v, id);

        out.push({
          packageName: name,
          ecosystem,
          installedVersion: version,
          vulnId: id,
          aliases,
          summary,
          severity,
          ...(fixedVersion !== undefined && { fixedVersion }),
          ...(referenceUrl !== undefined && { referenceUrl }),
          ...(manifestPath !== '' && { manifestPath }),
        });
      }
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// gitleaks (hardcoded secrets) — capability 1.1 (secrets)
// ---------------------------------------------------------------------------

/** Never emit a full secret. Keep a short, non-reversible preview. */
export function redactSecret(secret: string): string {
  const s = secret || '';
  if (s.length === 0) return '(hidden)';
  const head = s.slice(0, 3);
  return `${head}…(${s.length} chars, redacted)`;
}

export function parseGitleaks(jsonText: string): SecretFinding[] {
  const parsed = safeJsonParse(jsonText);
  // gitleaks emits a top-level array; some wrappers nest under `findings`.
  const arr = Array.isArray(parsed) ? parsed : asArray(asRecord(parsed)?.['findings']);
  const out: SecretFinding[] = [];

  for (const item of arr) {
    const f = asRecord(item);
    if (!f) continue;
    const ruleId = asString(f['RuleID']) || asString(f['rule_id']) || asString(f['ruleID']) || 'secret';
    const description =
      asString(f['Description']) || asString(f['description']) || 'Potential hardcoded secret';
    const file = asString(f['File']) || asString(f['file']);
    const startLine = asNumber(f['StartLine']) || asNumber(f['startLine']);
    const secret = asString(f['Secret']) || asString(f['secret']);
    const entropyRaw = f['Entropy'];
    const entropy = typeof entropyRaw === 'number' ? entropyRaw : undefined;

    out.push({
      ruleId,
      description,
      file,
      startLine,
      secretPreview: redactSecret(secret),
      ...(entropy !== undefined && { entropy }),
    });
  }
  return out;
}

// ---------------------------------------------------------------------------
// semgrep (SAST 1.1, taint 1.2, reachability 1.3, authz 1.4)
// ---------------------------------------------------------------------------

export interface SemgrepParseResult {
  sast: SastFinding[];
  taint: TaintFinding[];
  authz: AuthzRoute[];
}

/** Recursively locate the first {path, start.line} location in a value. */
function deepFindLocation(v: unknown, depth = 0): { file: string; line: number } | null {
  if (depth > 6 || v === null || typeof v !== 'object') return null;
  if (Array.isArray(v)) {
    for (const el of v) {
      const found = deepFindLocation(el, depth + 1);
      if (found) return found;
    }
    return null;
  }
  const obj = v as Record<string, unknown>;
  const path = asString(obj['path']);
  const start = asRecord(obj['start']);
  const line = start ? asNumber(start['line']) : 0;
  if (path && line > 0) return { file: path, line };
  for (const key of Object.keys(obj)) {
    const found = deepFindLocation(obj[key], depth + 1);
    if (found) return found;
  }
  return null;
}

/** Recursively locate the first `content` string in a value. */
function deepFindContent(v: unknown, depth = 0): string {
  if (depth > 6 || v === null || typeof v !== 'object') return '';
  if (Array.isArray(v)) {
    for (const el of v) {
      const found = deepFindContent(el, depth + 1);
      if (found) return found;
    }
    return '';
  }
  const obj = v as Record<string, unknown>;
  const direct = asString(obj['content']);
  if (direct) return direct;
  for (const key of Object.keys(obj)) {
    const found = deepFindContent(obj[key], depth + 1);
    if (found) return found;
  }
  return '';
}

function extractIntermediates(v: unknown): DataflowStep[] {
  const steps: DataflowStep[] = [];
  for (const el of asArray(v)) {
    const loc = deepFindLocation(el);
    if (loc) {
      const content = deepFindContent(el);
      steps.push({ file: loc.file, line: loc.line, ...(content !== '' && { content }) });
    }
  }
  return steps;
}

export function parseSemgrep(jsonText: string): SemgrepParseResult {
  const root = asRecord(safeJsonParse(jsonText));
  const result: SemgrepParseResult = { sast: [], taint: [], authz: [] };
  if (!root) return result;

  for (const res of asArray(root['results'])) {
    const r = asRecord(res);
    if (!r) continue;
    const checkId = normalizeRuleId(asString(r['check_id']));
    const file = asString(r['path']);
    const start = asRecord(r['start']);
    const line = start ? asNumber(start['line']) : 0;
    const extra = asRecord(r['extra']) ?? {};
    const message = asString(extra['message']);
    const metadata = asRecord(extra['metadata']) ?? {};
    const category = asString(metadata['category']) || inferCategory(checkId);
    const severity = mapSemgrepSeverity(asString(extra['severity']));
    const cwe = asArray(metadata['cwe']).map(asString).filter(Boolean);
    const owasp = asArray(metadata['owasp']).map(asString).filter(Boolean);
    const lines = asString(extra['lines']);

    // 1.4 — authorization surface
    if (category === 'authz') {
      result.authz.push(buildAuthzRoute(file, line, lines));
      continue;
    }

    // A finding is a tainted flow when it comes from a taint-mode rule. semgrep OSS
    // does not always emit `dataflow_trace`, so we route by rule metadata/id rather
    // than trace presence: `source-kind` on the rule, or a `dapper-taint-*` id.
    const dft = asRecord(extra['dataflow_trace']);
    const sourceKind = asString(metadata['source-kind']);
    const isTaint = dft !== null || sourceKind !== '' || /(?:^|-)taint(?:-|$)/.test(checkId);

    if (isTaint) {
      // 1.2 taint + 1.3 reachability
      const sink: DataflowStep = { file, line, ...(lines !== '' && { content: lines }) };
      // With a dataflow trace, recover the precise source; otherwise the sink match
      // is the anchor and reachability comes from the rule's declared source-kind.
      const srcLoc = dft ? deepFindLocation(dft['taint_source']) : null;
      const srcContent = dft ? deepFindContent(dft['taint_source']) : '';
      const source: DataflowStep = srcLoc
        ? { file: srcLoc.file, line: srcLoc.line, ...(srcContent !== '' && { content: srcContent }) }
        : { file, line, ...(lines !== '' && { content: lines }) };
      const cls = classifyTaintSource(metadata, srcContent || lines);
      const intermediate = dft ? extractIntermediates(dft['intermediate_vars']) : [];

      result.taint.push({
        ruleId: checkId,
        category,
        severity,
        message,
        source,
        sink,
        intermediate,
        reachableFromInternet: cls.reachableFromInternet,
        sourceKind: cls.sourceKind,
        cwe,
        owasp,
      });
    } else {
      // 1.1 dangerous sink / SAST
      result.sast.push({
        ruleId: checkId,
        category,
        severity,
        message,
        location: { file, line },
        cwe,
        owasp,
      });
    }
  }
  return result;
}
