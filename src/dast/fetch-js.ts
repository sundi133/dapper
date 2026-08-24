// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Fetch the target's served JavaScript so retire.js can scan it for known-
 * vulnerable client-side libraries (capability 2.19). Best-effort and bounded:
 * caps the number and size of scripts, times each request out, and never throws.
 */

import { fs, path } from 'zx';
import * as os from 'node:os';

export interface FetchedScript {
  url: string;
  localPath: string;
}

const MAX_SCRIPTS = 30;
const MAX_BYTES = 5_000_000; // 5 MB per script
const FETCH_TIMEOUT_MS = 10_000;

async function fetchText(url: string): Promise<string | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  try {
    const res = await fetch(url, { signal: controller.signal, redirect: 'follow' });
    if (!res.ok) return null;
    const buf = await res.arrayBuffer();
    if (buf.byteLength > MAX_BYTES) return null;
    return new TextDecoder().decode(buf);
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

/** Extract external `<script src>` URLs from HTML, resolved against the base. */
export function extractScriptUrls(html: string, baseUrl: string): string[] {
  const urls = new Set<string>();
  const re = /<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["']/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(html)) !== null) {
    const raw = (m[1] ?? '').trim();
    if (!raw || raw.startsWith('data:')) continue;
    try {
      const resolved = new URL(raw, baseUrl).toString();
      if (/^https?:/i.test(resolved)) urls.add(resolved);
    } catch {
      /* skip malformed */
    }
  }
  return Array.from(urls);
}

function safeBasename(url: string, index: number): string {
  let base = 'script';
  try {
    const p = new URL(url).pathname;
    base = p.split('/').filter(Boolean).pop() || 'script';
  } catch {
    /* keep default */
  }
  base = base.replace(/[^a-zA-Z0-9._-]/g, '_');
  if (!/\.js$/i.test(base)) base += '.js';
  return `${index}_${base}`;
}

/**
 * Download the target's served scripts into a fresh temp dir.
 * Returns the dir and a manifest mapping each local file to its source URL.
 * Returns null if nothing could be fetched.
 */
export async function fetchServedScripts(
  targetUrl: string
): Promise<{ dir: string; manifest: FetchedScript[] } | null> {
  const html = await fetchText(targetUrl);
  if (html === null) return null;

  const scriptUrls = extractScriptUrls(html, targetUrl).slice(0, MAX_SCRIPTS);
  if (scriptUrls.length === 0) return null;

  const dir = path.join(os.tmpdir(), `dapper-dast-js-${process.pid}-${scriptUrls.length}`);
  await fs.ensureDir(dir);

  const manifest: FetchedScript[] = [];
  let index = 0;
  for (const url of scriptUrls) {
    const body = await fetchText(url);
    index += 1;
    if (body === null) continue;
    const localPath = path.join(dir, safeBasename(url, index));
    try {
      await fs.writeFile(localPath, body, 'utf8');
      manifest.push({ url, localPath });
    } catch {
      /* skip write failures */
    }
  }

  if (manifest.length === 0) {
    await fs.remove(dir).catch(() => undefined);
    return null;
  }
  return { dir, manifest };
}
