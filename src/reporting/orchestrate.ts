// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Orchestration for the enriched reporting pipeline. Owns all file IO:
 *
 *  - `enrichFindings` runs one Claude pass that writes `deliverables/findings.json`,
 *    then validates it (retrying once with the validation errors appended).
 *  - `renderAllReports` reads `findings.json`, builds the report model, and writes
 *    `report.html`, `comprehensive_security_assessment_report.md` (enhanced
 *    Markdown — legacy filename preserved), `findings.csv`, and `report.pdf`.
 *
 * Every renderer is isolated so one failure (e.g. PDF) never blocks the others.
 */

import { fs, path } from 'zx';
import chalk from 'chalk';
import { runClaudePrompt } from '../ai/claude-executor.js';
import { validateFindingsDocument } from './findings-schema.js';
import { buildReportModel } from './model.js';
import { renderHtml } from './render-html.js';
import { renderMarkdown } from './render-md.js';
import { renderCsv } from './render-csv.js';
import { renderPdf } from './render-pdf.js';
import type { FindingsDocument } from './types.js';

const FINDINGS_FILE = 'findings.json';
const HTML_FILE = 'report.html';
const PDF_FILE = 'report.pdf';
const CSV_FILE = 'findings.csv';
const MARKDOWN_FILE = 'comprehensive_security_assessment_report.md';

function deliverablesDir(repoPath: string): string {
  return path.join(repoPath, 'deliverables');
}

/**
 * Run the enrichment agent and return the validated findings document.
 * The agent is instructed to write deliverables/findings.json itself.
 */
export async function enrichFindings(prompt: string, repoPath: string): Promise<FindingsDocument> {
  const findingsPath = path.join(deliverablesDir(repoPath), FINDINGS_FILE);

  // Clear any findings.json left over from a previous run BEFORE enriching.
  // Otherwise a failed enrichment this run would leave the stale file in place,
  // and renderAllReports would silently render reports from old data.
  if (await fs.pathExists(findingsPath)) {
    await fs.remove(findingsPath);
    console.log(chalk.gray('    🧹 Cleared stale findings.json from a previous run'));
  }

  const runOnce = async (p: string): Promise<FindingsDocument | { errors: string[] }> => {
    const result = await runClaudePrompt(p, repoPath, '', 'findings enrichment', 'report');
    if (!result.success) {
      throw new Error(result.error || 'Enrichment agent execution failed');
    }
    if (!(await fs.pathExists(findingsPath))) {
      return { errors: [`Agent did not write ${FINDINGS_FILE}.`] };
    }
    let parsed: unknown;
    try {
      parsed = await fs.readJson(findingsPath);
    } catch (err) {
      return { errors: [`${FINDINGS_FILE} is not valid JSON: ${err instanceof Error ? err.message : String(err)}`] };
    }
    const validation = validateFindingsDocument(parsed);
    if (validation.ok) return validation.doc;
    return { errors: validation.errors };
  };

  let outcome = await runOnce(prompt);
  if ('errors' in outcome) {
    console.log(chalk.yellow(`⚠️ findings.json invalid, retrying enrichment once:\n  - ${outcome.errors.slice(0, 10).join('\n  - ')}`));
    const retryPrompt = `${prompt}\n\n<previous-attempt-errors>\nYour previous findings.json failed validation. Fix exactly these issues and rewrite the file:\n- ${outcome.errors.join('\n- ')}\n</previous-attempt-errors>`;
    outcome = await runOnce(retryPrompt);
  }

  if ('errors' in outcome) {
    throw new Error(`findings.json failed validation after retry: ${outcome.errors.slice(0, 10).join('; ')}`);
  }
  console.log(chalk.green(`✅ Enriched ${outcome.findings.length} findings into ${FINDINGS_FILE}`));
  return outcome;
}

/** Populate assessment.models from the run's session.json, if available. */
async function fillModels(doc: FindingsDocument, outputPath?: string): Promise<void> {
  if (!outputPath) return;
  try {
    const sessionJsonPath = path.join(outputPath, 'session.json');
    if (!(await fs.pathExists(sessionJsonPath))) return;
    const sessionData = (await fs.readJson(sessionJsonPath)) as {
      metrics?: { agents?: Record<string, { model?: string }> };
    };
    const models = new Set<string>();
    for (const agent of Object.values(sessionData.metrics?.agents ?? {})) {
      if (agent.model) models.add(agent.model);
    }
    if (models.size > 0) doc.assessment.models = [...models];
  } catch (err) {
    console.log(chalk.yellow(`⚠️ Could not read models from session.json: ${err instanceof Error ? err.message : String(err)}`));
  }
}

/**
 * Render findings.json into all report formats. Reads findings.json from
 * deliverables/; each output is written independently so one failure does not
 * block the rest.
 */
export async function renderAllReports(repoPath: string, outputPath?: string): Promise<void> {
  const dir = deliverablesDir(repoPath);
  const findingsPath = path.join(dir, FINDINGS_FILE);

  if (!(await fs.pathExists(findingsPath))) {
    throw new Error(`${FINDINGS_FILE} not found — cannot render reports.`);
  }

  const parsed = await fs.readJson(findingsPath);
  const validation = validateFindingsDocument(parsed);
  if (!validation.ok) {
    throw new Error(`${FINDINGS_FILE} failed validation: ${validation.errors.slice(0, 10).join('; ')}`);
  }

  const doc = validation.doc;
  await fillModels(doc, outputPath);
  const model = buildReportModel(doc);

  const write = async (label: string, file: string, produce: () => string): Promise<void> => {
    try {
      await fs.writeFile(path.join(dir, file), produce());
      console.log(chalk.green(`✅ Wrote ${label}: ${file}`));
    } catch (err) {
      console.log(chalk.yellow(`⚠️ Failed to write ${label} (${file}): ${err instanceof Error ? err.message : String(err)}`));
    }
  };

  const generatedAt = new Date().toISOString();
  const html = renderHtml(model, generatedAt);
  await write('HTML report', HTML_FILE, () => html);
  await write('Markdown report', MARKDOWN_FILE, () => renderMarkdown(model, generatedAt));
  await write('findings CSV', CSV_FILE, () => renderCsv(model));

  // PDF last and isolated — a missing browser must not fail the phase.
  try {
    await renderPdf(html, path.join(dir, PDF_FILE));
  } catch (err) {
    console.log(chalk.yellow(`⚠️ PDF rendering skipped/failed (non-fatal): ${err instanceof Error ? err.message : String(err)}`));
  }
}
