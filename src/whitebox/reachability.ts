// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Reachability signal (capability 1.3).
 *
 * A taint finding is "reachable from the internet" when its source is untrusted
 * HTTP input. Primary signal: the rule tagged its source with
 * `metadata.source-kind: http-input`. Fallback: the matched source text looks
 * like an HTTP request accessor. Pure — no side effects, no Node imports.
 */

const HTTP_SOURCE_PATTERNS: RegExp[] = [
  /\breq(uest)?\s*\.\s*(body|query|params|headers|cookies|param)\b/i,
  /\brequest\s*\.\s*(args|form|values|data|json|get_json|files)\b/i,
  /\bctx\s*\.\s*(request|query|params|body)\b/i, // koa-style
  /\bevent\s*\.\s*(queryStringParameters|body|headers|pathParameters)\b/i, // lambda-style
];

export interface SourceClassification {
  reachableFromInternet: boolean;
  sourceKind: string; // 'http-input' | 'unknown'
}

/**
 * Decide whether a taint source is untrusted HTTP input.
 * @param metadata   the rule's metadata object (may carry `source-kind`)
 * @param sourceText the matched source snippet (may be empty)
 */
export function classifyTaintSource(
  metadata: Record<string, unknown> | null | undefined,
  sourceText: string
): SourceClassification {
  const declaredKind =
    metadata && typeof metadata['source-kind'] === 'string'
      ? (metadata['source-kind'] as string).trim().toLowerCase()
      : '';

  if (declaredKind === 'http-input') {
    return { reachableFromInternet: true, sourceKind: 'http-input' };
  }

  const text = sourceText || '';
  if (HTTP_SOURCE_PATTERNS.some((re) => re.test(text))) {
    return { reachableFromInternet: true, sourceKind: 'http-input' };
  }

  return { reachableFromInternet: false, sourceKind: 'unknown' };
}
