/**
 * Lightweight verification test for the compliance control ID mappings.
 *
 * Tests:
 *  1. Single-CWE lookup returns correct controls for all 4 frameworks
 *  2. Multi-CWE lookup deduplicates controls
 *  3. Unknown CWE returns empty
 *  4. CWE extraction from sample report content
 *  5. Per-finding CWE association and compliance metadata generation
 *  6. Full markdown compliance report generation
 *  7. CSV-side resolveComplianceControls parity (inline re-implementation)
 *
 * Run:  npx tsx scripts/test-compliance-mappings.ts
 */

import {
  getComplianceControlsForCwe,
  getComplianceControlsForCwes,
  groupControlsByFramework,
  getCweComplianceEntry,
  getAllMappedCweIds,
  generateComplianceReport,
  generateComplianceMetadata,
  type ComplianceFinding,
} from '../src/compliance/index.js';

let passed = 0;
let failed = 0;

function assert(condition: boolean, label: string, detail?: string) {
  if (condition) {
    console.log(`  \x1b[32m✓\x1b[0m ${label}`);
    passed++;
  } else {
    console.log(`  \x1b[31m✗\x1b[0m ${label}${detail ? ` — ${detail}` : ''}`);
    failed++;
  }
}

// ─── Test 1: Single-CWE lookup ──────────────────────────────────────────────

console.log('\n\x1b[1m[1] Single-CWE lookup\x1b[0m');

const sqlInjControls = getComplianceControlsForCwe('CWE-89');
assert(sqlInjControls.length === 4, 'CWE-89 returns 4 controls (one per framework)', `got ${sqlInjControls.length}`);

const frameworks = sqlInjControls.map(c => c.framework);
assert(frameworks.includes('OWASP'), 'CWE-89 includes OWASP');
assert(frameworks.includes('PCI-DSS'), 'CWE-89 includes PCI-DSS');
assert(frameworks.includes('SOC2'), 'CWE-89 includes SOC2');
assert(frameworks.includes('NIST-800-53'), 'CWE-89 includes NIST-800-53');

const owaspControl = sqlInjControls.find(c => c.framework === 'OWASP');
assert(owaspControl?.controlId === 'A03:2021', 'CWE-89 OWASP = A03:2021 (Injection)', `got ${owaspControl?.controlId}`);

const pciControl = sqlInjControls.find(c => c.framework === 'PCI-DSS');
assert(pciControl?.controlId === '6.2.4', 'CWE-89 PCI-DSS = 6.2.4', `got ${pciControl?.controlId}`);

const nistControl = sqlInjControls.find(c => c.framework === 'NIST-800-53');
assert(nistControl?.controlId === 'SI-10', 'CWE-89 NIST = SI-10', `got ${nistControl?.controlId}`);

// ─── Test 2: Multi-CWE deduplication ────────────────────────────────────────

console.log('\n\x1b[1m[2] Multi-CWE deduplication\x1b[0m');

// CWE-89 and CWE-79 both map to OWASP A03:2021 — should appear only once
const multiControls = getComplianceControlsForCwes(['CWE-89', 'CWE-79']);
const owaspA03Count = multiControls.filter(c => c.framework === 'OWASP' && c.controlId === 'A03:2021').length;
assert(owaspA03Count === 1, 'OWASP A03:2021 appears only once for CWE-89+CWE-79', `got ${owaspA03Count}`);
assert(multiControls.length === 4, 'CWE-89+CWE-79 produce 4 unique controls (identical mappings)', `got ${multiControls.length}`);

// CWE-89 (injection) + CWE-639 (IDOR) — different OWASP categories
const mixedControls = getComplianceControlsForCwes(['CWE-89', 'CWE-639']);
const owaspIds = mixedControls.filter(c => c.framework === 'OWASP').map(c => c.controlId);
assert(owaspIds.includes('A03:2021'), 'Mixed: includes A03:2021');
assert(owaspIds.includes('A01:2021'), 'Mixed: includes A01:2021');
assert(mixedControls.length === 7, 'CWE-89+CWE-639 produce 7 unique controls (SOC2 CC6.1 shared)', `got ${mixedControls.length}`);

// ─── Test 3: Unknown CWE ────────────────────────────────────────────────────

console.log('\n\x1b[1m[3] Unknown CWE returns empty\x1b[0m');

const unknownControls = getComplianceControlsForCwe('CWE-9999');
assert(unknownControls.length === 0, 'CWE-9999 returns empty array');

// ─── Test 4: Normalization ──────────────────────────────────────────────────

console.log('\n\x1b[1m[4] CWE ID normalization\x1b[0m');

const lowercaseControls = getComplianceControlsForCwe('cwe-89');
assert(lowercaseControls.length === 4, 'Lowercase "cwe-89" normalizes correctly', `got ${lowercaseControls.length}`);

const bareNumberControls = getComplianceControlsForCwe('89');
assert(bareNumberControls.length === 4, 'Bare "89" normalizes to CWE-89', `got ${bareNumberControls.length}`);

// ─── Test 5: All 27 CWEs are mapped ────────────────────────────────────────

console.log('\n\x1b[1m[5] Coverage: all 27 CWEs have mappings\x1b[0m');

const allCweIds = getAllMappedCweIds();
assert(allCweIds.length === 27, `Map contains 27 CWEs`, `got ${allCweIds.length}`);

const expectedCwes = [
  'CWE-89', 'CWE-79', 'CWE-918', 'CWE-639', 'CWE-862', 'CWE-287',
  'CWE-321', 'CWE-798', 'CWE-256', 'CWE-306', 'CWE-915', 'CWE-489',
  'CWE-209', 'CWE-703', 'CWE-307', 'CWE-799', 'CWE-613', 'CWE-294',
  'CWE-525', 'CWE-208', 'CWE-367', 'CWE-1021', 'CWE-319', 'CWE-312',
  'CWE-200', 'CWE-204', 'CWE-650',
];
for (const cwe of expectedCwes) {
  const entry = getCweComplianceEntry(cwe);
  assert(entry !== null, `${cwe} has a compliance entry`);
}

// ─── Test 6: groupControlsByFramework ───────────────────────────────────────

console.log('\n\x1b[1m[6] groupControlsByFramework\x1b[0m');

const grouped = groupControlsByFramework(mixedControls);
assert(grouped['OWASP'].length === 2, 'OWASP group has 2 controls', `got ${grouped['OWASP'].length}`);
assert(grouped['PCI-DSS'].length === 2, 'PCI-DSS group has 2 controls', `got ${grouped['PCI-DSS'].length}`);
assert(grouped['SOC2'].length === 1, 'SOC2 group has 1 control (CC6.1 shared by CWE-89 and CWE-639)', `got ${grouped['SOC2'].length}`);
assert(grouped['NIST-800-53'].length === 2, 'NIST group has 2 controls', `got ${grouped['NIST-800-53'].length}`);

// ─── Test 7: generateComplianceMetadata ─────────────────────────────────────

console.log('\n\x1b[1m[7] Compliance metadata generation (HTML comment)\x1b[0m');

const sampleFindings: ComplianceFinding[] = [
  { id: 'INJ-VULN-01', cweIds: ['CWE-89'] },
  { id: 'XSS-VULN-01', cweIds: ['CWE-79'] },
  { id: 'AUTHZ-VULN-01', cweIds: ['CWE-639', 'CWE-862'] },
  { id: 'AUTH-VULN-01', cweIds: ['CWE-287'] },
];

const metadata = generateComplianceMetadata(sampleFindings);
assert(metadata.startsWith('<!-- COMPLIANCE_MAPPING'), 'Metadata starts with COMPLIANCE_MAPPING comment');
assert(metadata.endsWith('-->'), 'Metadata ends with -->');
assert(metadata.includes('OWASP:'), 'Metadata contains OWASP section');
assert(metadata.includes('PCI-DSS:'), 'Metadata contains PCI-DSS section');
assert(metadata.includes('SOC2:'), 'Metadata contains SOC2 section');
assert(metadata.includes('NIST-800-53:'), 'Metadata contains NIST section');
assert(metadata.includes('INJ-VULN-01'), 'Metadata references INJ-VULN-01');
assert(metadata.includes('AUTHZ-VULN-01'), 'Metadata references AUTHZ-VULN-01');
assert(metadata.includes('A03:2021'), 'Metadata includes OWASP A03:2021');
assert(metadata.includes('A01:2021'), 'Metadata includes OWASP A01:2021');
assert(metadata.includes('A07:2021'), 'Metadata includes OWASP A07:2021 (from CWE-287)');

// ─── Test 8: generateComplianceReport (full markdown) ───────────────────────

console.log('\n\x1b[1m[8] Full markdown compliance report generation\x1b[0m');

const report = generateComplianceReport(sampleFindings);
assert(report.includes('### OWASP Top 10 (2021)'), 'Report has OWASP section');
assert(report.includes('### PCI-DSS 4.0'), 'Report has PCI-DSS section');
assert(report.includes('### SOC 2 Trust Service Criteria'), 'Report has SOC 2 section');
assert(report.includes('### NIST SP 800-53 Rev. 5'), 'Report has NIST section');
assert(report.includes('| Control ID |'), 'Report has table headers');
assert(report.includes('A03:2021'), 'Report maps A03:2021');
assert(report.includes('INJ-VULN-01'), 'Report lists INJ-VULN-01 under a control');
assert(report.includes('AUTHZ-VULN-01'), 'Report lists AUTHZ-VULN-01');

// ─── Test 9: Empty findings edge case ───────────────────────────────────────

console.log('\n\x1b[1m[9] Edge cases\x1b[0m');

const emptyMeta = generateComplianceMetadata([]);
assert(emptyMeta === '', 'Empty findings produce empty metadata');

const emptyReport = generateComplianceReport([]);
assert(emptyReport.includes('No vulnerability findings'), 'Empty findings produce fallback text');

const noMappingFindings: ComplianceFinding[] = [
  { id: 'UNKNOWN-VULN-01', cweIds: ['CWE-9999'] },
];
const noMappingReport = generateComplianceReport(noMappingFindings);
assert(noMappingReport.includes('No compliance framework mappings'), 'Unmapped CWEs produce fallback text');

// ─── Test 10: CSV-side compliance resolution parity ─────────────────────────

console.log('\n\x1b[1m[10] CSV compliance mapping parity check\x1b[0m');

// Re-implement the CSV script's resolveComplianceControls logic to verify parity
const CSV_CWE_COMPLIANCE_MAP: Record<string, { owasp: string; pci_dss: string; soc2: string; nist: string }> = {
  'CWE-89':  { owasp: 'A03:2021', pci_dss: '6.2.4', soc2: 'CC6.1', nist: 'SI-10' },
  'CWE-639': { owasp: 'A01:2021', pci_dss: '7.2.2', soc2: 'CC6.1', nist: 'AC-3' },
  'CWE-287': { owasp: 'A07:2021', pci_dss: '8.3.1', soc2: 'CC6.1', nist: 'IA-2' },
};

for (const [cweId, expected] of Object.entries(CSV_CWE_COMPLIANCE_MAP)) {
  const tsControls = getComplianceControlsForCwe(cweId);
  const tsOwasp = tsControls.find(c => c.framework === 'OWASP')?.controlId;
  const tsPci = tsControls.find(c => c.framework === 'PCI-DSS')?.controlId;
  const tsSoc2 = tsControls.find(c => c.framework === 'SOC2')?.controlId;
  const tsNist = tsControls.find(c => c.framework === 'NIST-800-53')?.controlId;

  assert(tsOwasp === expected.owasp, `${cweId} OWASP parity: TS=${tsOwasp} CSV=${expected.owasp}`);
  assert(tsPci === expected.pci_dss, `${cweId} PCI-DSS parity: TS=${tsPci} CSV=${expected.pci_dss}`);
  assert(tsSoc2 === expected.soc2, `${cweId} SOC2 parity: TS=${tsSoc2} CSV=${expected.soc2}`);
  assert(tsNist === expected.nist, `${cweId} NIST parity: TS=${tsNist} CSV=${expected.nist}`);
}

// ─── Summary ────────────────────────────────────────────────────────────────

console.log('\n' + '═'.repeat(50));
console.log(`\x1b[1m  Results: ${passed} passed, ${failed} failed\x1b[0m`);
console.log('═'.repeat(50) + '\n');

if (failed > 0) {
  process.exit(1);
}
