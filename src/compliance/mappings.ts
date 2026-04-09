// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

export type ComplianceFramework = 'OWASP' | 'PCI-DSS' | 'SOC2' | 'NIST-800-53';

export interface ComplianceControl {
  framework: ComplianceFramework;
  controlId: string;
  controlName: string;
}

export interface CweComplianceEntry {
  cweId: string;
  cweName: string;
  controls: ComplianceControl[];
}

// Static mapping of CWE IDs to compliance framework controls.
// Covers all CWEs from CWE_RULES in export-findings-csv.js.
const CWE_COMPLIANCE_MAP: ReadonlyMap<string, CweComplianceEntry> = new Map([
  ['CWE-89', {
    cweId: 'CWE-89',
    cweName: 'SQL Injection',
    controls: [
      { framework: 'OWASP', controlId: 'A03:2021', controlName: 'Injection' },
      { framework: 'PCI-DSS', controlId: '6.2.4', controlName: 'Software Engineering Techniques to Prevent Injection Attacks' },
      { framework: 'SOC2', controlId: 'CC6.1', controlName: 'Logical and Physical Access Controls' },
      { framework: 'NIST-800-53', controlId: 'SI-10', controlName: 'Information Input Validation' },
    ],
  }],
  ['CWE-79', {
    cweId: 'CWE-79',
    cweName: 'Cross-Site Scripting (XSS)',
    controls: [
      { framework: 'OWASP', controlId: 'A03:2021', controlName: 'Injection' },
      { framework: 'PCI-DSS', controlId: '6.2.4', controlName: 'Software Engineering Techniques to Prevent Injection Attacks' },
      { framework: 'SOC2', controlId: 'CC6.1', controlName: 'Logical and Physical Access Controls' },
      { framework: 'NIST-800-53', controlId: 'SI-10', controlName: 'Information Input Validation' },
    ],
  }],
  ['CWE-918', {
    cweId: 'CWE-918',
    cweName: 'Server-Side Request Forgery (SSRF)',
    controls: [
      { framework: 'OWASP', controlId: 'A10:2021', controlName: 'Server-Side Request Forgery' },
      { framework: 'PCI-DSS', controlId: '6.2.4', controlName: 'Software Engineering Techniques to Prevent Injection Attacks' },
      { framework: 'SOC2', controlId: 'CC6.6', controlName: 'Security Measures Against Threats Outside System Boundaries' },
      { framework: 'NIST-800-53', controlId: 'SC-7', controlName: 'Boundary Protection' },
    ],
  }],
  ['CWE-639', {
    cweId: 'CWE-639',
    cweName: 'Authorization Bypass Through User-Controlled Key',
    controls: [
      { framework: 'OWASP', controlId: 'A01:2021', controlName: 'Broken Access Control' },
      { framework: 'PCI-DSS', controlId: '7.2.2', controlName: 'Access Control Based on Job Classification and Function' },
      { framework: 'SOC2', controlId: 'CC6.1', controlName: 'Logical and Physical Access Controls' },
      { framework: 'NIST-800-53', controlId: 'AC-3', controlName: 'Access Enforcement' },
    ],
  }],
  ['CWE-862', {
    cweId: 'CWE-862',
    cweName: 'Missing Authorization',
    controls: [
      { framework: 'OWASP', controlId: 'A01:2021', controlName: 'Broken Access Control' },
      { framework: 'PCI-DSS', controlId: '7.2.1', controlName: 'Access Control Model Covers All System Components' },
      { framework: 'SOC2', controlId: 'CC6.1', controlName: 'Logical and Physical Access Controls' },
      { framework: 'NIST-800-53', controlId: 'AC-3', controlName: 'Access Enforcement' },
    ],
  }],
  ['CWE-287', {
    cweId: 'CWE-287',
    cweName: 'Improper Authentication',
    controls: [
      { framework: 'OWASP', controlId: 'A07:2021', controlName: 'Identification and Authentication Failures' },
      { framework: 'PCI-DSS', controlId: '8.3.1', controlName: 'Authentication for Users and Administrators' },
      { framework: 'SOC2', controlId: 'CC6.1', controlName: 'Logical and Physical Access Controls' },
      { framework: 'NIST-800-53', controlId: 'IA-2', controlName: 'Identification and Authentication' },
    ],
  }],
  ['CWE-321', {
    cweId: 'CWE-321',
    cweName: 'Use of Hard-coded Cryptographic Key',
    controls: [
      { framework: 'OWASP', controlId: 'A02:2021', controlName: 'Cryptographic Failures' },
      { framework: 'PCI-DSS', controlId: '3.6.1', controlName: 'Cryptographic Key Management Processes and Procedures' },
      { framework: 'SOC2', controlId: 'CC6.1', controlName: 'Logical and Physical Access Controls' },
      { framework: 'NIST-800-53', controlId: 'SC-12', controlName: 'Cryptographic Key Establishment and Management' },
    ],
  }],
  ['CWE-798', {
    cweId: 'CWE-798',
    cweName: 'Use of Hard-coded Credentials',
    controls: [
      { framework: 'OWASP', controlId: 'A07:2021', controlName: 'Identification and Authentication Failures' },
      { framework: 'PCI-DSS', controlId: '8.6.2', controlName: 'Hard-coded Passwords/Passphrases Prohibited for System Accounts' },
      { framework: 'SOC2', controlId: 'CC6.1', controlName: 'Logical and Physical Access Controls' },
      { framework: 'NIST-800-53', controlId: 'IA-5', controlName: 'Authenticator Management' },
    ],
  }],
  ['CWE-256', {
    cweId: 'CWE-256',
    cweName: 'Plaintext Storage of a Password',
    controls: [
      { framework: 'OWASP', controlId: 'A02:2021', controlName: 'Cryptographic Failures' },
      { framework: 'PCI-DSS', controlId: '8.3.2', controlName: 'Strong Cryptography for Authentication Credentials' },
      { framework: 'SOC2', controlId: 'CC6.1', controlName: 'Logical and Physical Access Controls' },
      { framework: 'NIST-800-53', controlId: 'IA-5', controlName: 'Authenticator Management' },
    ],
  }],
  ['CWE-306', {
    cweId: 'CWE-306',
    cweName: 'Missing Authentication for Critical Function',
    controls: [
      { framework: 'OWASP', controlId: 'A07:2021', controlName: 'Identification and Authentication Failures' },
      { framework: 'PCI-DSS', controlId: '8.3.1', controlName: 'Authentication for Users and Administrators' },
      { framework: 'SOC2', controlId: 'CC6.1', controlName: 'Logical and Physical Access Controls' },
      { framework: 'NIST-800-53', controlId: 'IA-2', controlName: 'Identification and Authentication' },
    ],
  }],
  ['CWE-915', {
    cweId: 'CWE-915',
    cweName: 'Improperly Controlled Modification of Dynamically-Determined Object Attributes',
    controls: [
      { framework: 'OWASP', controlId: 'A01:2021', controlName: 'Broken Access Control' },
      { framework: 'PCI-DSS', controlId: '6.2.4', controlName: 'Software Engineering Techniques to Prevent Injection Attacks' },
      { framework: 'SOC2', controlId: 'CC6.1', controlName: 'Logical and Physical Access Controls' },
      { framework: 'NIST-800-53', controlId: 'SI-10', controlName: 'Information Input Validation' },
    ],
  }],
  ['CWE-489', {
    cweId: 'CWE-489',
    cweName: 'Active Debug Code',
    controls: [
      { framework: 'OWASP', controlId: 'A05:2021', controlName: 'Security Misconfiguration' },
      { framework: 'PCI-DSS', controlId: '6.3.1', controlName: 'Remove Development and Test Artifacts Before Production' },
      { framework: 'SOC2', controlId: 'CC8.1', controlName: 'Change Management' },
      { framework: 'NIST-800-53', controlId: 'CM-7', controlName: 'Least Functionality' },
    ],
  }],
  ['CWE-209', {
    cweId: 'CWE-209',
    cweName: 'Generation of Error Message Containing Sensitive Information',
    controls: [
      { framework: 'OWASP', controlId: 'A05:2021', controlName: 'Security Misconfiguration' },
      { framework: 'PCI-DSS', controlId: '6.2.4', controlName: 'Software Engineering Techniques to Prevent Injection Attacks' },
      { framework: 'SOC2', controlId: 'CC7.2', controlName: 'Monitoring of System Components' },
      { framework: 'NIST-800-53', controlId: 'SI-11', controlName: 'Error Handling' },
    ],
  }],
  ['CWE-703', {
    cweId: 'CWE-703',
    cweName: 'Improper Check or Handling of Exceptional Conditions',
    controls: [
      { framework: 'OWASP', controlId: 'A05:2021', controlName: 'Security Misconfiguration' },
      { framework: 'PCI-DSS', controlId: '6.2.4', controlName: 'Software Engineering Techniques to Prevent Injection Attacks' },
      { framework: 'SOC2', controlId: 'CC7.2', controlName: 'Monitoring of System Components' },
      { framework: 'NIST-800-53', controlId: 'SI-11', controlName: 'Error Handling' },
    ],
  }],
  ['CWE-307', {
    cweId: 'CWE-307',
    cweName: 'Improper Restriction of Excessive Authentication Attempts',
    controls: [
      { framework: 'OWASP', controlId: 'A07:2021', controlName: 'Identification and Authentication Failures' },
      { framework: 'PCI-DSS', controlId: '8.3.4', controlName: 'Account Lockout After Invalid Authentication Attempts' },
      { framework: 'SOC2', controlId: 'CC6.1', controlName: 'Logical and Physical Access Controls' },
      { framework: 'NIST-800-53', controlId: 'AC-7', controlName: 'Unsuccessful Logon Attempts' },
    ],
  }],
  ['CWE-799', {
    cweId: 'CWE-799',
    cweName: 'Improper Control of Interaction Frequency',
    controls: [
      { framework: 'OWASP', controlId: 'A07:2021', controlName: 'Identification and Authentication Failures' },
      { framework: 'PCI-DSS', controlId: '8.3.4', controlName: 'Account Lockout After Invalid Authentication Attempts' },
      { framework: 'SOC2', controlId: 'CC6.1', controlName: 'Logical and Physical Access Controls' },
      { framework: 'NIST-800-53', controlId: 'SC-5', controlName: 'Denial-of-Service Protection' },
    ],
  }],
  ['CWE-613', {
    cweId: 'CWE-613',
    cweName: 'Insufficient Session Expiration',
    controls: [
      { framework: 'OWASP', controlId: 'A07:2021', controlName: 'Identification and Authentication Failures' },
      { framework: 'PCI-DSS', controlId: '8.2.8', controlName: 'Session Timeout After Period of Inactivity' },
      { framework: 'SOC2', controlId: 'CC6.1', controlName: 'Logical and Physical Access Controls' },
      { framework: 'NIST-800-53', controlId: 'AC-12', controlName: 'Session Termination' },
    ],
  }],
  ['CWE-294', {
    cweId: 'CWE-294',
    cweName: 'Authentication Bypass by Capture-replay',
    controls: [
      { framework: 'OWASP', controlId: 'A07:2021', controlName: 'Identification and Authentication Failures' },
      { framework: 'PCI-DSS', controlId: '8.3.1', controlName: 'Authentication for Users and Administrators' },
      { framework: 'SOC2', controlId: 'CC6.1', controlName: 'Logical and Physical Access Controls' },
      { framework: 'NIST-800-53', controlId: 'IA-2', controlName: 'Identification and Authentication' },
    ],
  }],
  ['CWE-525', {
    cweId: 'CWE-525',
    cweName: 'Information Exposure Through Browser Caching',
    controls: [
      { framework: 'OWASP', controlId: 'A04:2021', controlName: 'Insecure Design' },
      { framework: 'PCI-DSS', controlId: '6.2.4', controlName: 'Software Engineering Techniques to Prevent Injection Attacks' },
      { framework: 'SOC2', controlId: 'CC6.7', controlName: 'Restriction and Management of Data Transmission' },
      { framework: 'NIST-800-53', controlId: 'SC-28', controlName: 'Protection of Information at Rest' },
    ],
  }],
  ['CWE-208', {
    cweId: 'CWE-208',
    cweName: 'Observable Timing Discrepancy',
    controls: [
      { framework: 'OWASP', controlId: 'A02:2021', controlName: 'Cryptographic Failures' },
      { framework: 'PCI-DSS', controlId: '6.2.4', controlName: 'Software Engineering Techniques to Prevent Injection Attacks' },
      { framework: 'SOC2', controlId: 'CC6.1', controlName: 'Logical and Physical Access Controls' },
      { framework: 'NIST-800-53', controlId: 'SC-13', controlName: 'Cryptographic Protection' },
    ],
  }],
  ['CWE-367', {
    cweId: 'CWE-367',
    cweName: 'Time-of-check Time-of-use (TOCTOU) Race Condition',
    controls: [
      { framework: 'OWASP', controlId: 'A04:2021', controlName: 'Insecure Design' },
      { framework: 'PCI-DSS', controlId: '6.2.4', controlName: 'Software Engineering Techniques to Prevent Injection Attacks' },
      { framework: 'SOC2', controlId: 'CC8.1', controlName: 'Change Management' },
      { framework: 'NIST-800-53', controlId: 'SI-7', controlName: 'Software, Firmware, and Information Integrity' },
    ],
  }],
  ['CWE-1021', {
    cweId: 'CWE-1021',
    cweName: 'Improper Restriction of Rendered UI Layers or Frames',
    controls: [
      { framework: 'OWASP', controlId: 'A05:2021', controlName: 'Security Misconfiguration' },
      { framework: 'PCI-DSS', controlId: '6.2.4', controlName: 'Software Engineering Techniques to Prevent Injection Attacks' },
      { framework: 'SOC2', controlId: 'CC6.1', controlName: 'Logical and Physical Access Controls' },
      { framework: 'NIST-800-53', controlId: 'SI-10', controlName: 'Information Input Validation' },
    ],
  }],
  ['CWE-319', {
    cweId: 'CWE-319',
    cweName: 'Cleartext Transmission of Sensitive Information',
    controls: [
      { framework: 'OWASP', controlId: 'A02:2021', controlName: 'Cryptographic Failures' },
      { framework: 'PCI-DSS', controlId: '4.2.1', controlName: 'Strong Cryptography for Transmission of Cardholder Data' },
      { framework: 'SOC2', controlId: 'CC6.7', controlName: 'Restriction and Management of Data Transmission' },
      { framework: 'NIST-800-53', controlId: 'SC-8', controlName: 'Transmission Confidentiality and Integrity' },
    ],
  }],
  ['CWE-312', {
    cweId: 'CWE-312',
    cweName: 'Cleartext Storage of Sensitive Information',
    controls: [
      { framework: 'OWASP', controlId: 'A02:2021', controlName: 'Cryptographic Failures' },
      { framework: 'PCI-DSS', controlId: '3.5.1', controlName: 'Protect Stored Account Data' },
      { framework: 'SOC2', controlId: 'CC6.1', controlName: 'Logical and Physical Access Controls' },
      { framework: 'NIST-800-53', controlId: 'SC-28', controlName: 'Protection of Information at Rest' },
    ],
  }],
  ['CWE-200', {
    cweId: 'CWE-200',
    cweName: 'Exposure of Sensitive Information to an Unauthorized Actor',
    controls: [
      { framework: 'OWASP', controlId: 'A01:2021', controlName: 'Broken Access Control' },
      { framework: 'PCI-DSS', controlId: '6.2.4', controlName: 'Software Engineering Techniques to Prevent Injection Attacks' },
      { framework: 'SOC2', controlId: 'CC6.1', controlName: 'Logical and Physical Access Controls' },
      { framework: 'NIST-800-53', controlId: 'AC-4', controlName: 'Information Flow Enforcement' },
    ],
  }],
  ['CWE-204', {
    cweId: 'CWE-204',
    cweName: 'Observable Response Discrepancy',
    controls: [
      { framework: 'OWASP', controlId: 'A07:2021', controlName: 'Identification and Authentication Failures' },
      { framework: 'PCI-DSS', controlId: '6.2.4', controlName: 'Software Engineering Techniques to Prevent Injection Attacks' },
      { framework: 'SOC2', controlId: 'CC6.1', controlName: 'Logical and Physical Access Controls' },
      { framework: 'NIST-800-53', controlId: 'SI-11', controlName: 'Error Handling' },
    ],
  }],
  ['CWE-650', {
    cweId: 'CWE-650',
    cweName: 'Trusting HTTP Permission Methods on the Server Side',
    controls: [
      { framework: 'OWASP', controlId: 'A05:2021', controlName: 'Security Misconfiguration' },
      { framework: 'PCI-DSS', controlId: '6.2.4', controlName: 'Software Engineering Techniques to Prevent Injection Attacks' },
      { framework: 'SOC2', controlId: 'CC6.1', controlName: 'Logical and Physical Access Controls' },
      { framework: 'NIST-800-53', controlId: 'AC-3', controlName: 'Access Enforcement' },
    ],
  }],
]);

/**
 * Normalize a CWE identifier to the canonical "CWE-NNN" form.
 * Accepts "CWE-89", "cwe-89", "89", etc.
 */
function normalizeCweId(raw: string): string {
  const trimmed = raw.trim().toUpperCase();
  if (trimmed.startsWith('CWE-')) return trimmed;
  return `CWE-${trimmed}`;
}

/**
 * Look up compliance controls for a single CWE ID.
 * Returns an empty array if the CWE is not in the mapping.
 */
export function getComplianceControlsForCwe(cweId: string): ComplianceControl[] {
  const entry = CWE_COMPLIANCE_MAP.get(normalizeCweId(cweId));
  return entry ? [...entry.controls] : [];
}

/**
 * Look up compliance controls for multiple CWE IDs, deduplicated by controlId.
 */
export function getComplianceControlsForCwes(cweIds: string[]): ComplianceControl[] {
  const seen = new Set<string>();
  const result: ComplianceControl[] = [];

  for (const cweId of cweIds) {
    for (const control of getComplianceControlsForCwe(cweId)) {
      const key = `${control.framework}:${control.controlId}`;
      if (!seen.has(key)) {
        seen.add(key);
        result.push(control);
      }
    }
  }

  return result;
}

/**
 * Group compliance controls by framework.
 */
export function groupControlsByFramework(
  controls: ComplianceControl[]
): Record<ComplianceFramework, ComplianceControl[]> {
  const grouped: Record<ComplianceFramework, ComplianceControl[]> = {
    'OWASP': [],
    'PCI-DSS': [],
    'SOC2': [],
    'NIST-800-53': [],
  };

  for (const control of controls) {
    grouped[control.framework].push(control);
  }

  return grouped;
}

/**
 * Get the full CWE compliance entry (including CWE name) for a given CWE ID.
 */
export function getCweComplianceEntry(cweId: string): CweComplianceEntry | null {
  return CWE_COMPLIANCE_MAP.get(normalizeCweId(cweId)) ?? null;
}

/**
 * Return all CWE IDs that have compliance mappings.
 */
export function getAllMappedCweIds(): string[] {
  return Array.from(CWE_COMPLIANCE_MAP.keys());
}
