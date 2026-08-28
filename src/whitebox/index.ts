// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Deterministic white-box analysis subsystem (capabilities 1.1–1.7).
 *
 * Public entry points used by the Temporal activity layer:
 *   - runWhiteboxAnalysis(opts)            -> WhiteboxAnalysis | null
 *   - writeWhiteboxDeliverables(analysis)  -> void
 *
 * Everything degrades gracefully: absent tools are skipped, and failures are
 * non-fatal, so this can never break the existing pipeline.
 */

export * from './types.js';
export { runWhiteboxAnalysis, writeWhiteboxDeliverables } from './orchestrate.js';
export type { WhiteboxRunOptions } from './orchestrate.js';
export { detectWhiteboxTools } from './availability.js';
export {
  parseOsvScanner,
  parseGitleaks,
  parseSemgrep,
  mapOsvSeverity,
  mapSemgrepSeverity,
  redactSecret,
  inferCategory,
  normalizeRuleId,
} from './parsers.js';
export { classifyTaintSource } from './reachability.js';
export { buildAuthzRoute, extractHttpMethod, extractRoutePath, summarizeAuthz } from './authz-graph.js';
export { renderWhiteboxMarkdown, renderPreReconSection, WHITEBOX_SECTION_MARKER } from './render.js';
