// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Pure parsers: raw scanner output -> normalized DAST findings.
 * Every parser is defensive (tolerates version drift / malformed input) and
 * total (returns [] rather than throwing). No side effects, no Node imports.
 */

import type { DastFinding, DastSeverity } from './types.js';

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
  return v !== null && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
}
function asArray(v: unknown): unknown[] {
  return Array.isArray(v) ? v : [];
}
function asString(v: unknown): string {
  return typeof v === 'string' ? v : '';
}
function truncate(s: string, n: number): string {
  const t = (s || '').replace(/\s+/g, ' ').trim();
  return t.length > n ? `${t.slice(0, n)}…` : t;
}
function extractCves(text: string): string[] {
  const m = (text || '').match(/CVE-\d{4}-\d{4,7}/gi);
  return m ? Array.from(new Set(m.map((x) => x.toUpperCase()))) : [];
}

// ---------------------------------------------------------------------------
// nuclei (JSONL: one JSON object per line)  — XXE/SSTI/CORS/redirect/headers/
// exposures/graphql/file-upload/CVEs
// ---------------------------------------------------------------------------

/** Map a nuclei severity string to our band. */
export function mapNucleiSeverity(s: string): DastSeverity {
  switch ((s || '').toLowerCase()) {
    case 'critical':
      return 'critical';
    case 'high':
      return 'high';
    case 'medium':
      return 'medium';
    case 'low':
      return 'low';
    default:
      return 'info'; // info / unknown
  }
}

/** Derive our category bucket from nuclei tags + template id. */
export function categorizeNuclei(tags: string[], templateId: string): string {
  const hay = `${tags.join(' ')} ${templateId}`.toLowerCase();
  const has = (...keys: string[]): boolean => keys.some((k) => hay.includes(k));
  if (has('cors')) return 'cors';
  if (has('redirect')) return 'open-redirect';
  if (has('ssti')) return 'ssti';
  if (has('xxe')) return 'xxe';
  if (has('graphql')) return 'graphql';
  if (has('fileupload', 'file-upload', 'upload')) return 'file-upload';
  if (has('ssl', 'tls')) return 'tls';
  if (has('missing-header', 'headers', 'hsts', 'csp')) return 'security-headers';
  if (has('exposure', 'exposures', 'files', 'config', 'backup', 'disclosure', 'listing')) return 'exposure';
  return 'other';
}

export function parseNuclei(jsonlText: string): DastFinding[] {
  const out: DastFinding[] = [];
  for (const rawLine of (jsonlText || '').split('\n')) {
    const line = rawLine.trim();
    if (!line) continue;
    const r = asRecord(safeJsonParse(line));
    if (!r) continue; // nuclei prints only JSON lines with -silent; skip anything else
    const templateId = asString(r['template-id']) || asString(r['templateID']);
    if (!templateId) continue;
    const info = asRecord(r['info']) ?? {};
    const tags = asArray(info['tags']).map(asString).filter(Boolean);
    const name = asString(info['name']) || templateId;
    const severity = mapNucleiSeverity(asString(info['severity']));
    const description = truncate(asString(info['description']), 300);
    const reference = asArray(info['reference']).map(asString).filter(Boolean);
    const classification = asRecord(info['classification']) ?? {};
    // nuclei emits ids lowercase (e.g. "cwe-200"); normalize to canonical uppercase.
    const cve = asArray(classification['cve-id']).map(asString).filter(Boolean).map((s) => s.toUpperCase());
    const cwe = asArray(classification['cwe-id']).map(asString).filter(Boolean).map((s) => s.toUpperCase());
    const matchedAt = asString(r['matched-at']) || asString(r['matched']) || asString(r['host']);
    const extracted = asArray(r['extracted-results']).map(asString).filter(Boolean);
    const evidence = truncate(extracted.join(', ') || asString(r['matcher-name']), 200);

    out.push({
      tool: 'nuclei',
      id: templateId,
      category: categorizeNuclei(tags, templateId),
      name,
      severity,
      matchedAt,
      description,
      cve,
      cwe,
      reference,
      evidence,
    });
  }
  return out;
}

// ---------------------------------------------------------------------------
// testssl.sh (JSON array)  — deep TLS/SSL
// ---------------------------------------------------------------------------

/** Map a testssl.sh severity to our band. Returns null for non-actionable noise. */
export function mapTestsslSeverity(s: string): DastSeverity | null {
  switch ((s || '').toUpperCase()) {
    case 'CRITICAL':
      return 'critical';
    case 'HIGH':
      return 'high';
    case 'MEDIUM':
      return 'medium';
    case 'LOW':
      return 'low';
    case 'WARN':
      return 'low';
    default:
      return null; // OK / INFO / DEBUG — drop the noise
  }
}

export function parseTestssl(jsonText: string, hostPort: string): DastFinding[] {
  const parsed = safeJsonParse(jsonText);
  // testssl emits a top-level array; some builds wrap under { scanResult: [...] }.
  let rows = asArray(parsed);
  if (rows.length === 0) {
    const wrap = asRecord(parsed);
    if (wrap) rows = asArray(wrap['scanResult']).length ? asArray(wrap['scanResult']) : asArray(wrap['findings']);
  }
  const out: DastFinding[] = [];
  for (const row of rows) {
    const r = asRecord(row);
    if (!r) continue;
    const severity = mapTestsslSeverity(asString(r['severity']));
    if (!severity) continue; // skip OK/INFO/DEBUG
    const id = asString(r['id']) || 'tls_finding';
    const finding = asString(r['finding']);
    const ipPort = [asString(r['ip']), asString(r['port'])].filter(Boolean).join(':');
    out.push({
      tool: 'testssl',
      id,
      category: 'tls',
      name: truncate(`${id}: ${finding}`, 120),
      severity,
      matchedAt: ipPort || hostPort,
      description: truncate(finding, 300),
      cve: extractCves(finding),
      cwe: [],
      reference: [],
      evidence: truncate(finding, 200),
    });
  }
  return out;
}

// ---------------------------------------------------------------------------
// retire.js (JSON)  — vulnerable client-side JS libraries
// ---------------------------------------------------------------------------

/** Map a retire.js severity string to our band. */
export function mapRetireSeverity(s: string): DastSeverity {
  switch ((s || '').toLowerCase()) {
    case 'critical':
      return 'critical';
    case 'high':
      return 'high';
    case 'medium':
      return 'medium';
    case 'low':
      return 'low';
    default:
      return 'medium'; // retire often omits severity; a known-vuln dep is at least medium
  }
}

/**
 * @param resolveUrl optional: map a scanned local file path back to its source URL,
 *                   so findings point at the served asset rather than a temp path.
 */
export function parseRetire(jsonText: string, resolveUrl?: (file: string) => string): DastFinding[] {
  const root = asRecord(safeJsonParse(jsonText));
  if (!root) return [];
  const out: DastFinding[] = [];
  for (const entry of asArray(root['data'])) {
    const e = asRecord(entry);
    if (!e) continue;
    const file = asString(e['file']);
    const matchedAt = (resolveUrl && file ? resolveUrl(file) : '') || file;
    for (const res of asArray(e['results'])) {
      const rr = asRecord(res);
      if (!rr) continue;
      const component = asString(rr['component']);
      const version = asString(rr['version']);
      for (const vuln of asArray(rr['vulnerabilities'])) {
        const v = asRecord(vuln);
        if (!v) continue;
        const idents = asRecord(v['identifiers']) ?? {};
        const cve = asArray(idents['CVE']).map(asString).filter(Boolean);
        const summary = asString(idents['summary']) || asArray(v['info']).map(asString).filter(Boolean)[0] || 'Known vulnerability in a client-side library';
        const reference = asArray(v['info']).map(asString).filter(Boolean);
        out.push({
          tool: 'retire',
          id: `${component}@${version}`,
          category: 'js-lib-cve',
          name: truncate(`${component} ${version}: ${summary}`, 120),
          severity: mapRetireSeverity(asString(v['severity'])),
          matchedAt,
          description: truncate(summary, 300),
          cve,
          cwe: [],
          reference,
          evidence: `${component}@${version}`,
        });
      }
    }
  }
  return out;
}
