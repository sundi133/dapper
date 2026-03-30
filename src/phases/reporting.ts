// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

import { fs, path } from 'zx';
import chalk from 'chalk';
import { PentestError } from '../error-handling.js';
import { generateComplianceMetadata, type ComplianceFinding } from '../compliance/index.js';

type DeliverableSection = 'context' | 'exploitation' | 'analysis';

interface DeliverableFile {
  name: string;
  path: string;
  required: boolean;
  section: DeliverableSection;
}

interface AssemblyStats {
  totalFiles: number;
  includedFiles: number;
  missingFiles: string[];
  duplicateVulnIds: string[];
  emptySections: string[];
}

const CONTEXT_DELIVERABLES: DeliverableFile[] = [
  { name: 'Threat Model', path: 'threat_model_deliverable.md', required: false, section: 'context' },
  { name: 'Code Analysis', path: 'code_analysis_deliverable.md', required: false, section: 'context' },
];

const EXPLOITATION_DELIVERABLES: DeliverableFile[] = [
  { name: 'Injection', path: 'injection_exploitation_evidence.md', required: false, section: 'exploitation' },
  { name: 'XSS', path: 'xss_exploitation_evidence.md', required: false, section: 'exploitation' },
  { name: 'Authentication', path: 'auth_exploitation_evidence.md', required: false, section: 'exploitation' },
  { name: 'SSRF', path: 'ssrf_exploitation_evidence.md', required: false, section: 'exploitation' },
  { name: 'Authorization', path: 'authz_exploitation_evidence.md', required: false, section: 'exploitation' },
  { name: 'Web Attacks', path: 'web_attacks_exploitation_evidence.md', required: false, section: 'exploitation' },
  { name: 'Session & Auth', path: 'session_auth_exploitation_evidence.md', required: false, section: 'exploitation' },
  { name: 'Business Logic', path: 'business_logic_exploitation_evidence.md', required: false, section: 'exploitation' },
  { name: 'Client-Side', path: 'client_side_exploitation_evidence.md', required: false, section: 'exploitation' },
  { name: 'Info Gathering', path: 'info_gathering_exploitation_evidence.md', required: false, section: 'exploitation' },
  { name: 'Config & Deploy', path: 'config_deploy_exploitation_evidence.md', required: false, section: 'exploitation' },
  { name: 'Session Management', path: 'session_mgmt_exploitation_evidence.md', required: false, section: 'exploitation' },
  { name: 'Error Handling', path: 'error_handling_exploitation_evidence.md', required: false, section: 'exploitation' },
  { name: 'Cryptography', path: 'crypto_exploitation_evidence.md', required: false, section: 'exploitation' },
  { name: 'API Testing', path: 'api_testing_exploitation_evidence.md', required: false, section: 'exploitation' },
];

const ANALYSIS_DELIVERABLES: DeliverableFile[] = [
  { name: 'Web Hardening', path: 'web_hardening_analysis_deliverable.md', required: false, section: 'analysis' },
];

function extractVulnIds(content: string): string[] {
  const pattern = /###\s+([A-Z]+-VULN-\d+)/g;
  const ids: string[] = [];
  let match;
  while ((match = pattern.exec(content)) !== null) {
    ids.push(match[1]!);
  }
  return ids;
}

function extractCweIds(content: string): string[] {
  const pattern = /CWE-(\d+)/gi;
  const ids = new Set<string>();
  let match;
  while ((match = pattern.exec(content)) !== null) {
    ids.add(`CWE-${match[1]}`);
  }
  return Array.from(ids);
}

/**
 * Parse per-finding CWE associations by scanning each vulnerability heading section
 * for CWE references. Returns ComplianceFinding[] for the compliance module.
 */
function buildFindingsWithCwes(content: string): ComplianceFinding[] {
  const findingPattern = /###\s+([A-Z]+-VULN-\d+)[^\n]*/g;
  const findings: ComplianceFinding[] = [];
  const matches: Array<{ id: string; startIdx: number }> = [];

  let match;
  while ((match = findingPattern.exec(content)) !== null) {
    matches.push({ id: match[1]!, startIdx: match.index });
  }

  for (let i = 0; i < matches.length; i++) {
    const start = matches[i]!.startIdx;
    const end = i + 1 < matches.length ? matches[i + 1]!.startIdx : content.length;
    const section = content.slice(start, end);
    const cweIds = extractCweIds(section);
    findings.push({ id: matches[i]!.id, cweIds });
  }

  return findings;
}

function findDuplicateVulnIds(allIds: string[]): string[] {
  const seen = new Set<string>();
  const dupes = new Set<string>();
  for (const id of allIds) {
    if (seen.has(id)) dupes.add(id);
    seen.add(id);
  }
  return Array.from(dupes);
}

function detectEmptySections(content: string): string[] {
  const sectionPattern = /^(#{1,3}\s+.+)$/gm;
  const sections: { heading: string; startIdx: number }[] = [];
  let match;
  while ((match = sectionPattern.exec(content)) !== null) {
    sections.push({ heading: match[1]!, startIdx: match.index + match[0].length });
  }

  const empty: string[] = [];
  for (let i = 0; i < sections.length; i++) {
    const start = sections[i]!.startIdx;
    const end = i + 1 < sections.length ? sections[i + 1]!.startIdx - sections[i + 1]!.heading.length : content.length;
    const body = content.slice(start, end).trim();
    if (body.length === 0 || body === '---') {
      empty.push(sections[i]!.heading);
    }
  }
  return empty;
}

function scrubInternalPaths(content: string): string {
  return content
    .replace(/\/app\/repos\/[^\s)>]+/g, '[REPO_PATH]')
    .replace(/\/Users\/[^\s)>]+/g, '[LOCAL_PATH]')
    .replace(/\/home\/[^\s)>]+/g, '[LOCAL_PATH]')
    .replace(/\/tmp\/[^\s)>]+/g, '[TMP_PATH]');
}

// Pure function: Assemble final report from specialist deliverables
export async function assembleFinalReport(sourceDir: string): Promise<string> {
  const allDeliverables = [
    ...CONTEXT_DELIVERABLES,
    ...EXPLOITATION_DELIVERABLES,
    ...ANALYSIS_DELIVERABLES,
  ];

  const stats: AssemblyStats = {
    totalFiles: allDeliverables.length,
    includedFiles: 0,
    missingFiles: [],
    duplicateVulnIds: [],
    emptySections: [],
  };

  const contextSections: string[] = [];
  const exploitationSections: string[] = [];
  const analysisSections: string[] = [];
  const allVulnIds: string[] = [];

  for (const file of allDeliverables) {
    const filePath = path.join(sourceDir, 'deliverables', file.path);
    try {
      if (await fs.pathExists(filePath)) {
        let content = await fs.readFile(filePath, 'utf8');
        if (content.trim().length === 0) {
          console.log(chalk.yellow(`⚠️ Empty file: ${file.path}`));
          stats.missingFiles.push(file.path);
          continue;
        }

        content = scrubInternalPaths(content);
        const vulnIds = extractVulnIds(content);
        allVulnIds.push(...vulnIds);

        const markedContent = `<!-- BEGIN:${file.name.toUpperCase().replace(/[^A-Z0-9]/g, '_')} -->\n${content}\n<!-- END:${file.name.toUpperCase().replace(/[^A-Z0-9]/g, '_')} -->`;

        if (file.section === 'context') contextSections.push(markedContent);
        else if (file.section === 'exploitation') exploitationSections.push(markedContent);
        else analysisSections.push(markedContent);

        stats.includedFiles++;
        console.log(chalk.green(`✅ Added ${file.name} (${vulnIds.length} vuln IDs)`));
      } else if (file.required) {
        throw new Error(`Required file ${file.path} not found`);
      } else {
        stats.missingFiles.push(file.path);
        console.log(chalk.gray(`⏭️  No ${file.name} deliverable found`));
      }
    } catch (error) {
      if (file.required) throw error;
      const err = error as Error;
      console.log(chalk.yellow(`⚠️ Could not read ${file.path}: ${err.message}`));
    }
  }

  stats.duplicateVulnIds = findDuplicateVulnIds(allVulnIds);
  if (stats.duplicateVulnIds.length > 0) {
    console.log(chalk.yellow(`⚠️ Duplicate vulnerability IDs found: ${stats.duplicateVulnIds.join(', ')}`));
  }

  const assemblyMeta = [
    `<!-- ASSEMBLY_METADATA`,
    `  files_included: ${stats.includedFiles}/${stats.totalFiles}`,
    `  vuln_ids_total: ${allVulnIds.length}`,
    `  duplicate_ids: ${stats.duplicateVulnIds.length > 0 ? stats.duplicateVulnIds.join(', ') : 'none'}`,
    `  missing_files: ${stats.missingFiles.length > 0 ? stats.missingFiles.join(', ') : 'none'}`,
    `  assembled_at: ${new Date().toISOString()}`,
    `-->`,
  ].join('\n');

  const parts: string[] = [assemblyMeta];

  if (contextSections.length > 0) {
    parts.push('<!-- SECTION:CONTEXT -->', ...contextSections);
  }
  if (exploitationSections.length > 0) {
    parts.push('<!-- SECTION:EXPLOITATION_EVIDENCE -->', ...exploitationSections);
  }
  if (analysisSections.length > 0) {
    parts.push('<!-- SECTION:ANALYSIS -->', ...analysisSections);
  }

  let finalContent = parts.join('\n\n');

  // Build compliance mapping from CWE references found in deliverables
  const complianceFindings = buildFindingsWithCwes(finalContent);
  const globalCweIds = extractCweIds(finalContent);
  if (globalCweIds.length > 0) {
    const complianceMeta = generateComplianceMetadata(complianceFindings);
    if (complianceMeta) {
      finalContent = assemblyMeta + '\n\n' + complianceMeta + '\n\n' + finalContent.slice(assemblyMeta.length);
      console.log(chalk.blue(`📋 Compliance mapping: ${globalCweIds.length} CWEs mapped across ${complianceFindings.length} findings`));
    }
  }

  const emptySections = detectEmptySections(finalContent);
  if (emptySections.length > 0) {
    stats.emptySections = emptySections;
    console.log(chalk.yellow(`⚠️ Empty sections detected: ${emptySections.length}`));
    for (const heading of emptySections) {
      console.log(chalk.yellow(`   - ${heading}`));
    }
  }

  const deliverablesDir = path.join(sourceDir, 'deliverables');
  const finalReportPath = path.join(deliverablesDir, 'comprehensive_security_assessment_report.md');

  try {
    await fs.ensureDir(deliverablesDir);
    await fs.writeFile(finalReportPath, finalContent);
    console.log(chalk.green(`✅ Final report assembled at ${finalReportPath}`));
    console.log(chalk.blue(`📊 Assembly stats: ${stats.includedFiles} files, ${allVulnIds.length} vuln IDs, ${stats.duplicateVulnIds.length} duplicates, ${stats.emptySections.length} empty sections`));
  } catch (error) {
    const err = error as Error;
    throw new PentestError(
      `Failed to write final report: ${err.message}`,
      'filesystem',
      false,
      { finalReportPath, originalError: err.message }
    );
  }

  return finalContent;
}

/**
 * Inject model information into the final security report.
 * Reads session.json to get the model(s) used, then injects a "Model:" line
 * into the Executive Summary section of the report.
 */
export async function injectModelIntoReport(
  repoPath: string,
  outputPath: string
): Promise<void> {
  // 1. Read session.json to get model information
  const sessionJsonPath = path.join(outputPath, 'session.json');

  if (!(await fs.pathExists(sessionJsonPath))) {
    console.log(chalk.yellow('⚠️ session.json not found, skipping model injection'));
    return;
  }

  interface SessionData {
    metrics: {
      agents: Record<string, { model?: string }>;
    };
  }

  const sessionData: SessionData = await fs.readJson(sessionJsonPath);

  // 2. Extract unique models from all agents
  const models = new Set<string>();
  for (const agent of Object.values(sessionData.metrics.agents)) {
    if (agent.model) {
      models.add(agent.model);
    }
  }

  if (models.size === 0) {
    console.log(chalk.yellow('⚠️ No model information found in session.json'));
    return;
  }

  const modelStr = Array.from(models).join(', ');
  console.log(chalk.blue(`📝 Injecting model info into report: ${modelStr}`));

  // 3. Read the final report
  const reportPath = path.join(repoPath, 'deliverables', 'comprehensive_security_assessment_report.md');

  if (!(await fs.pathExists(reportPath))) {
    console.log(chalk.yellow('⚠️ Final report not found, skipping model injection'));
    return;
  }

  let reportContent = await fs.readFile(reportPath, 'utf8');

  // 4. Find and inject model line after "Assessment Date" or "Assessment Type" in Document Control
  const assessmentDatePattern = /^(\*?\*?Assessment Date\*?\*?:?\s*.+)$/m;
  const assessmentTypePattern = /^(\*?\*?Assessment Type\*?\*?:?\s*.+)$/m;
  const modelLine = `- **Model:** ${modelStr}`;

  const dateMatch = reportContent.match(assessmentDatePattern);
  const typeMatch = reportContent.match(assessmentTypePattern);

  if (dateMatch) {
    reportContent = reportContent.replace(assessmentDatePattern, `$1\n${modelLine}`);
    console.log(chalk.green('✅ Model info injected after Assessment Date'));
  } else if (typeMatch) {
    reportContent = reportContent.replace(assessmentTypePattern, `$1\n${modelLine}`);
    console.log(chalk.green('✅ Model info injected after Assessment Type'));
  } else {
    const docControlPattern = /^##\s+\d*\.?\s*Document Control$/m;
    const execSummaryPattern = /^##\s+\d*\.?\s*Executive Summary$/m;
    const target = reportContent.match(docControlPattern) || reportContent.match(execSummaryPattern);
    if (target) {
      reportContent = reportContent.replace(target[0], `${target[0]}\n${modelLine}`);
      console.log(chalk.green('✅ Model info added to report header section'));
    } else {
      console.log(chalk.yellow('⚠️ Could not find Document Control or Executive Summary section'));
      return;
    }
  }

  // 5. Write modified report back
  await fs.writeFile(reportPath, reportContent);
}
