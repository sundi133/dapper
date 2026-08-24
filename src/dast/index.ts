// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Deterministic DAST probe subsystem (Tier-2 ADD group: XXE, SSTI, CORS,
 * open-redirect, GraphQL, file-upload, TLS, security-headers, sensitive-files,
 * JS-lib CVE) via nuclei + testssl.sh + retire.js.
 *
 * Public entry points used by the Temporal activity layer:
 *   - runDastAnalysis(opts)            -> DastAnalysis | null
 *   - writeDastDeliverables(analysis)  -> void
 *
 * Everything degrades gracefully: absent tools are skipped, failures are
 * non-fatal, so this can never break the existing pipeline.
 */

export * from './types.js';
export { runDastAnalysis, writeDastDeliverables } from './orchestrate.js';
export type { DastRunOptions } from './orchestrate.js';
export { detectDastTools } from './availability.js';
export {
  parseNuclei,
  parseTestssl,
  parseRetire,
  mapNucleiSeverity,
  mapTestsslSeverity,
  mapRetireSeverity,
  categorizeNuclei,
} from './parsers.js';
export { extractScriptUrls, fetchServedScripts } from './fetch-js.js';
export { renderDastMarkdown, renderReconSection, DAST_SECTION_MARKER } from './render.js';
