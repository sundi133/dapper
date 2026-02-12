// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Deliverable Type Definitions
 *
 * Maps deliverable types to their filenames and defines validation requirements.
 * Must match the exact mappings from tools/save_deliverable.js.
 */

export enum DeliverableType {
  // Pre-recon agent
  CODE_ANALYSIS = 'CODE_ANALYSIS',

  // Threat modeling agent
  THREAT_MODEL = 'THREAT_MODEL',

  // Recon agent
  RECON = 'RECON',

  // Vulnerability analysis agents
  INJECTION_ANALYSIS = 'INJECTION_ANALYSIS',
  INJECTION_QUEUE = 'INJECTION_QUEUE',

  XSS_ANALYSIS = 'XSS_ANALYSIS',
  XSS_QUEUE = 'XSS_QUEUE',

  AUTH_ANALYSIS = 'AUTH_ANALYSIS',
  AUTH_QUEUE = 'AUTH_QUEUE',

  AUTHZ_ANALYSIS = 'AUTHZ_ANALYSIS',
  AUTHZ_QUEUE = 'AUTHZ_QUEUE',

  SSRF_ANALYSIS = 'SSRF_ANALYSIS',
  SSRF_QUEUE = 'SSRF_QUEUE',

  WEB_ATTACKS_ANALYSIS = 'WEB_ATTACKS_ANALYSIS',
  WEB_ATTACKS_QUEUE = 'WEB_ATTACKS_QUEUE',

  SESSION_AUTH_ANALYSIS = 'SESSION_AUTH_ANALYSIS',
  SESSION_AUTH_QUEUE = 'SESSION_AUTH_QUEUE',

  BUSINESS_LOGIC_ANALYSIS = 'BUSINESS_LOGIC_ANALYSIS',
  BUSINESS_LOGIC_QUEUE = 'BUSINESS_LOGIC_QUEUE',

  CLIENT_SIDE_ANALYSIS = 'CLIENT_SIDE_ANALYSIS',
  CLIENT_SIDE_QUEUE = 'CLIENT_SIDE_QUEUE',

  WEB_HARDENING_ANALYSIS = 'WEB_HARDENING_ANALYSIS',

  // Exploitation agents
  INJECTION_EVIDENCE = 'INJECTION_EVIDENCE',
  XSS_EVIDENCE = 'XSS_EVIDENCE',
  AUTH_EVIDENCE = 'AUTH_EVIDENCE',
  AUTHZ_EVIDENCE = 'AUTHZ_EVIDENCE',
  SSRF_EVIDENCE = 'SSRF_EVIDENCE',
  WEB_ATTACKS_EVIDENCE = 'WEB_ATTACKS_EVIDENCE',
  SESSION_AUTH_EVIDENCE = 'SESSION_AUTH_EVIDENCE',
  BUSINESS_LOGIC_EVIDENCE = 'BUSINESS_LOGIC_EVIDENCE',
  CLIENT_SIDE_EVIDENCE = 'CLIENT_SIDE_EVIDENCE',
}

/**
 * Hard-coded filename mappings from agent prompts
 * Must match tools/save_deliverable.js exactly
 */
export const DELIVERABLE_FILENAMES: Record<DeliverableType, string> = {
  [DeliverableType.CODE_ANALYSIS]: 'code_analysis_deliverable.md',
  [DeliverableType.THREAT_MODEL]: 'threat_model_deliverable.md',
  [DeliverableType.RECON]: 'recon_deliverable.md',
  [DeliverableType.INJECTION_ANALYSIS]: 'injection_analysis_deliverable.md',
  [DeliverableType.INJECTION_QUEUE]: 'injection_exploitation_queue.json',
  [DeliverableType.XSS_ANALYSIS]: 'xss_analysis_deliverable.md',
  [DeliverableType.XSS_QUEUE]: 'xss_exploitation_queue.json',
  [DeliverableType.AUTH_ANALYSIS]: 'auth_analysis_deliverable.md',
  [DeliverableType.AUTH_QUEUE]: 'auth_exploitation_queue.json',
  [DeliverableType.AUTHZ_ANALYSIS]: 'authz_analysis_deliverable.md',
  [DeliverableType.AUTHZ_QUEUE]: 'authz_exploitation_queue.json',
  [DeliverableType.SSRF_ANALYSIS]: 'ssrf_analysis_deliverable.md',
  [DeliverableType.SSRF_QUEUE]: 'ssrf_exploitation_queue.json',
  [DeliverableType.WEB_ATTACKS_ANALYSIS]: 'web_attacks_analysis_deliverable.md',
  [DeliverableType.WEB_ATTACKS_QUEUE]: 'web_attacks_exploitation_queue.json',
  [DeliverableType.SESSION_AUTH_ANALYSIS]: 'session_auth_analysis_deliverable.md',
  [DeliverableType.SESSION_AUTH_QUEUE]: 'session_auth_exploitation_queue.json',
  [DeliverableType.BUSINESS_LOGIC_ANALYSIS]: 'business_logic_analysis_deliverable.md',
  [DeliverableType.BUSINESS_LOGIC_QUEUE]: 'business_logic_exploitation_queue.json',
  [DeliverableType.CLIENT_SIDE_ANALYSIS]: 'client_side_analysis_deliverable.md',
  [DeliverableType.CLIENT_SIDE_QUEUE]: 'client_side_exploitation_queue.json',
  [DeliverableType.WEB_HARDENING_ANALYSIS]: 'web_hardening_analysis_deliverable.md',
  [DeliverableType.INJECTION_EVIDENCE]: 'injection_exploitation_evidence.md',
  [DeliverableType.XSS_EVIDENCE]: 'xss_exploitation_evidence.md',
  [DeliverableType.AUTH_EVIDENCE]: 'auth_exploitation_evidence.md',
  [DeliverableType.AUTHZ_EVIDENCE]: 'authz_exploitation_evidence.md',
  [DeliverableType.SSRF_EVIDENCE]: 'ssrf_exploitation_evidence.md',
  [DeliverableType.WEB_ATTACKS_EVIDENCE]: 'web_attacks_exploitation_evidence.md',
  [DeliverableType.SESSION_AUTH_EVIDENCE]: 'session_auth_exploitation_evidence.md',
  [DeliverableType.BUSINESS_LOGIC_EVIDENCE]: 'business_logic_exploitation_evidence.md',
  [DeliverableType.CLIENT_SIDE_EVIDENCE]: 'client_side_exploitation_evidence.md',
};

/**
 * Queue types that require JSON validation
 */
export const QUEUE_TYPES: DeliverableType[] = [
  DeliverableType.INJECTION_QUEUE,
  DeliverableType.XSS_QUEUE,
  DeliverableType.AUTH_QUEUE,
  DeliverableType.AUTHZ_QUEUE,
  DeliverableType.SSRF_QUEUE,
  DeliverableType.WEB_ATTACKS_QUEUE,
  DeliverableType.SESSION_AUTH_QUEUE,
  DeliverableType.BUSINESS_LOGIC_QUEUE,
  DeliverableType.CLIENT_SIDE_QUEUE,
];

/**
 * Type guard to check if a deliverable type is a queue
 */
export function isQueueType(type: string): boolean {
  return QUEUE_TYPES.includes(type as DeliverableType);
}

/**
 * Vulnerability queue structure
 */
export interface VulnerabilityQueue {
  vulnerabilities: VulnerabilityItem[];
}

export interface VulnerabilityItem {
  [key: string]: unknown;
}
