// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Modern Security Firm theme — the CSS + small HTML helpers shared by the HTML
 * renderer. Light, navy-headed, corporate, with CVSS badges and severity
 * colors. Self-contained (inline CSS, no external assets, prints cleanly).
 */

import type { Severity } from './types.js';

export function escapeHtml(value: unknown): string {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

const SEVERITY_HEX: Record<Severity, string> = {
  Critical: '#b91c1c',
  High: '#c2410c',
  Medium: '#a16207',
  Low: '#0369a1',
  Informational: '#475569',
};

export function severityColor(severity: Severity): string {
  return SEVERITY_HEX[severity];
}

export function severityBadge(severity: Severity, score?: number): string {
  const label = score !== undefined ? `${escapeHtml(severity)} · ${score.toFixed(1)}` : escapeHtml(severity);
  return `<span class="badge" style="background:${SEVERITY_HEX[severity]}">${label}</span>`;
}

/** Conic-gradient stops for the severity donut, in fixed severity order. */
export function donutGradient(counts: Record<Severity, number>): string {
  const order: Severity[] = ['Critical', 'High', 'Medium', 'Low', 'Informational'];
  const total = order.reduce((sum, s) => sum + counts[s], 0);
  if (total === 0) return '#e2e8f0';
  let acc = 0;
  const stops: string[] = [];
  for (const s of order) {
    if (counts[s] === 0) continue;
    const start = (acc / total) * 100;
    acc += counts[s];
    const end = (acc / total) * 100;
    stops.push(`${SEVERITY_HEX[s]} ${start.toFixed(2)}% ${end.toFixed(2)}%`);
  }
  return `conic-gradient(${stops.join(',')})`;
}

export const THEME_CSS = `
  :root { --navy:#0f2740; --navy2:#1e4976; --ink:#0f172a; --muted:#64748b; --line:#e2e8f0; --bg:#fff; }
  * { box-sizing:border-box; }
  body { font-family:-apple-system,BlinkMacSystemFont,system-ui,'Segoe UI',sans-serif; color:var(--ink); background:#f1f5f9; margin:0; padding:24px; }
  .doc { background:var(--bg); border:1px solid var(--line); border-radius:10px; overflow:hidden; max-width:900px; margin:0 auto; box-shadow:0 8px 30px rgba(15,39,64,.10); }
  .cover { background:linear-gradient(135deg,var(--navy),var(--navy2)); color:#fff; padding:32px 36px; }
  .cover .eyebrow { font-size:11px; letter-spacing:2px; text-transform:uppercase; opacity:.6; }
  .cover h1 { font-size:28px; margin:8px 0 6px; font-weight:800; }
  .cover .meta { font-size:13px; opacity:.85; line-height:1.6; }
  .cover .meta b { opacity:1; }
  .sec { padding:24px 36px; border-bottom:1px solid #eef2f6; }
  .seclabel { font-size:11px; letter-spacing:1.5px; text-transform:uppercase; color:var(--navy2); font-weight:700; border-left:3px solid var(--navy2); padding-left:10px; margin:0 0 16px; }
  .posture { font-size:14px; line-height:1.6; color:#334155; background:#f8fafc; border:1px solid var(--line); border-radius:8px; padding:16px; }
  .grade { display:inline-block; color:#fff; font-weight:800; font-size:13px; padding:4px 12px; border-radius:6px; margin-right:8px; }
  .row { display:flex; gap:20px; align-items:center; flex-wrap:wrap; }
  .stat { flex:1; min-width:72px; text-align:center; background:#f1f5f9; border-radius:8px; padding:12px 6px; }
  .stat .n { font-size:26px; font-weight:800; line-height:1; }
  .stat .l { font-size:9px; text-transform:uppercase; letter-spacing:.5px; color:var(--muted); margin-top:5px; }
  .donut { width:128px; height:128px; border-radius:50%; display:flex; align-items:center; justify-content:center; flex-shrink:0; }
  .donut .hole { width:80px; height:80px; background:#fff; border-radius:50%; display:flex; flex-direction:column; align-items:center; justify-content:center; }
  .donut .hole .tot { font-size:24px; font-weight:800; color:var(--navy); }
  .donut .hole .lab { font-size:9px; color:var(--muted); text-transform:uppercase; }
  .bars { margin-top:4px; }
  .barrow { display:flex; align-items:center; gap:10px; font-size:12px; margin:6px 0; }
  .barrow .cat { width:140px; color:#334155; text-align:right; }
  .barrow .track { flex:1; background:#f1f5f9; border-radius:4px; height:16px; overflow:hidden; }
  .barrow .fill { height:100%; background:var(--navy2); border-radius:4px; }
  .barrow .ct { width:24px; font-weight:700; color:var(--navy); }
  table { width:100%; border-collapse:collapse; font-size:12px; margin-top:6px; }
  th { background:var(--navy); color:#fff; text-align:left; padding:8px 10px; font-size:10px; text-transform:uppercase; letter-spacing:.5px; }
  td { padding:8px 10px; border-bottom:1px solid #eef2f6; vertical-align:top; }
  .badge { font-size:10px; font-weight:700; padding:3px 8px; border-radius:99px; color:#fff; white-space:nowrap; }
  .tag { display:inline-block; font-size:10px; background:#e0e7ef; color:var(--navy2); border-radius:4px; padding:2px 7px; margin:2px 2px; font-family:ui-monospace,SFMono-Regular,Menlo,monospace; }
  .chain { display:flex; align-items:center; gap:8px; flex-wrap:wrap; font-size:12px; margin-top:8px; }
  .node { background:#fff; border:1.5px solid var(--navy2); color:var(--navy2); border-radius:6px; padding:6px 11px; font-weight:600; }
  .node.end { background:#b91c1c; border-color:#b91c1c; color:#fff; }
  .arrow { color:#94a3b8; font-weight:700; }
  .cov { display:flex; flex-wrap:wrap; gap:7px; margin-top:6px; }
  .chip { font-size:11px; border-radius:6px; padding:5px 10px; border:1px solid var(--line); background:#f8fafc; }
  .chip.hit { border-color:#fecaca; background:#fef2f2; color:#991b1b; font-weight:600; }
  .chip.clean { border-color:#bbf7d0; background:#f0fdf4; color:#166534; }
  .road { display:flex; gap:12px; margin-top:6px; flex-wrap:wrap; }
  .lane { flex:1; min-width:200px; border-radius:8px; padding:12px; font-size:12px; }
  .lane h5 { margin:0 0 8px; font-size:11px; text-transform:uppercase; letter-spacing:.5px; }
  .lane.now { background:#fef2f2; border:1px solid #fecaca; } .lane.now h5 { color:#991b1b; }
  .lane.soon { background:#fff7ed; border:1px solid #fed7aa; } .lane.soon h5 { color:#9a3412; }
  .lane.later { background:#eff6ff; border:1px solid #bfdbfe; } .lane.later h5 { color:#1e40af; }
  .lane ul { margin:0; padding-left:16px; color:#334155; } .lane li { margin:3px 0; }
  .finding { border:1px solid var(--line); border-radius:9px; overflow:hidden; margin-top:16px; scroll-margin-top:20px; }
  .fhead { background:#f8fafc; padding:14px 16px; border-bottom:1px solid var(--line); display:flex; justify-content:space-between; align-items:flex-start; gap:12px; }
  .fhead .id { font-family:ui-monospace,monospace; font-size:11px; color:var(--muted); }
  .fhead h4 { margin:3px 0 6px; font-size:16px; }
  .cvss { text-align:center; color:#fff; border-radius:8px; padding:8px 12px; min-width:60px; flex-shrink:0; }
  .cvss .score { font-size:20px; font-weight:800; line-height:1; }
  .cvss .sev { font-size:9px; text-transform:uppercase; letter-spacing:.5px; }
  .fbody { padding:14px 16px; font-size:12px; line-height:1.6; color:#334155; }
  .vector { font-family:ui-monospace,monospace; font-size:10px; color:var(--muted); background:#f1f5f9; padding:5px 8px; border-radius:5px; display:inline-block; margin-top:6px; word-break:break-all; }
  .block { margin-top:12px; }
  .block .h { font-size:10px; text-transform:uppercase; letter-spacing:.5px; color:var(--navy2); font-weight:700; margin-bottom:5px; }
  .impact { background:#fffbeb; border:1px solid #fde68a; border-radius:6px; padding:10px; color:#92400e; }
  pre { background:#0f172a; color:#e2e8f0; font-size:11px; padding:12px; border-radius:6px; overflow:auto; margin:0; font-family:ui-monospace,monospace; white-space:pre-wrap; word-break:break-word; }
  .remedy { background:#f0fdf4; border:1px solid #bbf7d0; border-radius:6px; padding:10px; }
  .empty { color:var(--muted); font-style:italic; font-size:13px; }
  .footer { padding:20px 36px; font-size:11px; color:var(--muted); }
  @media print { body { background:#fff; padding:0; } .doc { box-shadow:none; border:none; max-width:none; } }
`;
