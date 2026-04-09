// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

import {
  getComplianceControlsForCwes,
  groupControlsByFramework,
  getCweComplianceEntry,
  type ComplianceControl,
  type ComplianceFramework,
} from './mappings.js';

export interface ComplianceFinding {
  id: string;
  cweIds: string[];
}

interface FrameworkSection {
  framework: ComplianceFramework;
  title: string;
  description: string;
}

const FRAMEWORK_SECTIONS: FrameworkSection[] = [
  {
    framework: 'OWASP',
    title: 'OWASP Top 10 (2021)',
    description: 'Findings mapped to the OWASP Top 10 Web Application Security Risks.',
  },
  {
    framework: 'PCI-DSS',
    title: 'PCI-DSS 4.0',
    description: 'Findings impacting Payment Card Industry Data Security Standard requirements.',
  },
  {
    framework: 'SOC2',
    title: 'SOC 2 Trust Service Criteria',
    description: 'Findings impacting Service Organization Control 2 trust service criteria.',
  },
  {
    framework: 'NIST-800-53',
    title: 'NIST SP 800-53 Rev. 5',
    description: 'Findings mapped to NIST security and privacy controls for information systems.',
  },
];

/**
 * Build a reverse index: controlId -> list of findings that violate it.
 */
function buildControlToFindingsIndex(
  findings: ComplianceFinding[]
): Map<string, { control: ComplianceControl; findingRefs: Array<{ id: string; cweIds: string[] }> }> {
  const index = new Map<string, { control: ComplianceControl; findingRefs: Array<{ id: string; cweIds: string[] }> }>();

  for (const finding of findings) {
    const controls = getComplianceControlsForCwes(finding.cweIds);
    for (const control of controls) {
      const key = `${control.framework}:${control.controlId}`;
      if (!index.has(key)) {
        index.set(key, { control, findingRefs: [] });
      }

      const relevantCwes = finding.cweIds.filter(cweId => {
        const entry = getCweComplianceEntry(cweId);
        return entry?.controls.some(
          c => c.framework === control.framework && c.controlId === control.controlId
        );
      });

      index.get(key)!.findingRefs.push({
        id: finding.id,
        cweIds: relevantCwes,
      });
    }
  }

  return index;
}

/**
 * Generate a complete compliance report section as markdown.
 *
 * Groups findings by compliance framework, then by control ID,
 * listing which vulnerability findings violate each control.
 */
export function generateComplianceReport(findings: ComplianceFinding[]): string {
  if (findings.length === 0) {
    return 'No vulnerability findings available for compliance mapping.';
  }

  const controlIndex = buildControlToFindingsIndex(findings);

  const allControls = getComplianceControlsForCwes(
    findings.flatMap(f => f.cweIds)
  );
  const grouped = groupControlsByFramework(allControls);

  const sections: string[] = [];

  for (const { framework, title, description } of FRAMEWORK_SECTIONS) {
    const frameworkControls = grouped[framework];
    if (frameworkControls.length === 0) continue;

    const lines: string[] = [];
    lines.push(`### ${title}`);
    lines.push('');
    lines.push(description);
    lines.push('');
    lines.push('| Control ID | Control Name | Impacted Findings |');
    lines.push('|------------|-------------|-------------------|');

    const seen = new Set<string>();
    for (const control of frameworkControls) {
      if (seen.has(control.controlId)) continue;
      seen.add(control.controlId);

      const key = `${framework}:${control.controlId}`;
      const entry = controlIndex.get(key);
      const findingList = entry
        ? entry.findingRefs
            .map(ref => {
              const cwePart = ref.cweIds.length > 0
                ? ` (${ref.cweIds.join(', ')})`
                : '';
              return `${ref.id}${cwePart}`;
            })
            .join(', ')
        : '';

      lines.push(`| ${control.controlId} | ${control.controlName} | ${findingList} |`);
    }

    sections.push(lines.join('\n'));
  }

  if (sections.length === 0) {
    return 'No compliance framework mappings could be determined from the identified vulnerabilities.';
  }

  return sections.join('\n\n');
}

/**
 * Generate a compact compliance summary as an HTML comment block
 * suitable for injection into the assembled report.
 *
 * The report agent uses this structured data to build the compliance section.
 */
export function generateComplianceMetadata(findings: ComplianceFinding[]): string {
  if (findings.length === 0) return '';

  const controlIndex = buildControlToFindingsIndex(findings);
  const lines: string[] = ['<!-- COMPLIANCE_MAPPING'];

  for (const { framework } of FRAMEWORK_SECTIONS) {
    const frameworkEntries = Array.from(controlIndex.entries())
      .filter(([, v]) => v.control.framework === framework);

    if (frameworkEntries.length === 0) continue;

    lines.push(`  ${framework}:`);
    for (const [, { control, findingRefs }] of frameworkEntries) {
      const ids = findingRefs.map(r => r.id).join(', ');
      lines.push(`    ${control.controlId} (${control.controlName}): ${ids}`);
    }
  }

  lines.push('-->');
  return lines.join('\n');
}
