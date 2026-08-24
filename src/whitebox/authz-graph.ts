// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Authorization surface mapping (capability 1.4).
 *
 * From semgrep route-handler matches, build a per-route row so authorization
 * can be verified. This is a heuristic *surface map* (which internet-facing
 * handlers exist), not a proof of missing auth — named honestly as such.
 * Pure — no side effects, no Node imports.
 */

import type { AuthzRoute } from './types.js';

const HTTP_METHODS = ['get', 'post', 'put', 'delete', 'patch', 'options', 'head'] as const;

/** Extract an HTTP method from a matched route snippet, if present. */
export function extractHttpMethod(matchedText: string): string | undefined {
  const text = (matchedText || '').toLowerCase();

  // express/koa/router: `.get(` `.post(` ...
  const dotCall = text.match(/\.\s*(get|post|put|delete|patch|options|head)\s*\(/);
  if (dotCall && dotCall[1]) return dotCall[1].toUpperCase();

  // flask: `methods=['POST', 'GET']`
  const methodsArr = text.match(/methods\s*=\s*\[([^\]]*)\]/);
  if (methodsArr && methodsArr[1]) {
    for (const m of HTTP_METHODS) {
      if (methodsArr[1].includes(m)) return m.toUpperCase();
    }
  }

  return undefined;
}

/** Extract the first route path (string literal) from a matched snippet. */
export function extractRoutePath(matchedText: string): string | undefined {
  const m = (matchedText || '').match(/['"`]([^'"`]*)['"`]/);
  if (m && typeof m[1] === 'string' && m[1].length > 0) return m[1];
  return undefined;
}

/**
 * Build an authorization-surface row for a route handler surfaced by semgrep.
 * `guarded` is conservatively false ("not verified") — the note tells the
 * downstream reviewer to confirm auth is enforced.
 */
export function buildAuthzRoute(file: string, line: number, matchedText: string): AuthzRoute {
  const method = extractHttpMethod(matchedText);
  const route = extractRoutePath(matchedText);
  return {
    file,
    line,
    ...(method !== undefined && { method }),
    ...(route !== undefined && { route }),
    guarded: false,
    note: 'Internet-facing route handler surfaced by static analysis — verify authentication / ownership / role checks are enforced.',
  };
}

/** Summary counts for reporting. */
export function summarizeAuthz(routes: AuthzRoute[]): { total: number; unverified: number } {
  return {
    total: routes.length,
    unverified: routes.filter((r) => !r.guarded).length,
  };
}
