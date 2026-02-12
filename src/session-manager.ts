// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

import { path } from 'zx';
import type { AgentName } from './types/index.js';

// Agent definition interface
export interface AgentDefinition {
  name: AgentName;
  displayName: string;
  prerequisites: AgentName[];
}

// Agent definitions according to PRD
export const AGENTS: Readonly<Record<AgentName, AgentDefinition>> = Object.freeze({
  'pre-recon': {
    name: 'pre-recon',
    displayName: 'Pre-recon agent',
    prerequisites: []
  },
  'threat-model': {
    name: 'threat-model',
    displayName: 'Threat model agent',
    prerequisites: ['pre-recon']
  },
  'recon': {
    name: 'recon',
    displayName: 'Recon agent',
    prerequisites: ['threat-model']
  },
  'injection-vuln': {
    name: 'injection-vuln',
    displayName: 'Injection vuln agent',
    prerequisites: ['recon']
  },
  'xss-vuln': {
    name: 'xss-vuln',
    displayName: 'XSS vuln agent',
    prerequisites: ['recon']
  },
  'auth-vuln': {
    name: 'auth-vuln',
    displayName: 'Auth vuln agent',
    prerequisites: ['recon']
  },
  'ssrf-vuln': {
    name: 'ssrf-vuln',
    displayName: 'SSRF vuln agent',
    prerequisites: ['recon']
  },
  'authz-vuln': {
    name: 'authz-vuln',
    displayName: 'Authz vuln agent',
    prerequisites: ['recon']
  },
  'web-attacks-vuln': {
    name: 'web-attacks-vuln',
    displayName: 'Web attacks vuln agent',
    prerequisites: ['recon']
  },
  'session-auth-vuln': {
    name: 'session-auth-vuln',
    displayName: 'Session & auth vuln agent',
    prerequisites: ['recon']
  },
  'business-logic-vuln': {
    name: 'business-logic-vuln',
    displayName: 'Business logic vuln agent',
    prerequisites: ['recon']
  },
  'client-side-vuln': {
    name: 'client-side-vuln',
    displayName: 'Client-side vuln agent',
    prerequisites: ['recon']
  },
  'web-hardening': {
    name: 'web-hardening',
    displayName: 'Web hardening vuln agent',
    prerequisites: ['recon']
  },
  'info-gathering-vuln': {
    name: 'info-gathering-vuln',
    displayName: 'Info gathering vuln agent',
    prerequisites: ['recon']
  },
  'config-deploy-vuln': {
    name: 'config-deploy-vuln',
    displayName: 'Config/deploy vuln agent',
    prerequisites: ['recon']
  },
  'session-mgmt-vuln': {
    name: 'session-mgmt-vuln',
    displayName: 'Session mgmt vuln agent',
    prerequisites: ['recon']
  },
  'error-handling-vuln': {
    name: 'error-handling-vuln',
    displayName: 'Error handling vuln agent',
    prerequisites: ['recon']
  },
  'crypto-vuln': {
    name: 'crypto-vuln',
    displayName: 'Crypto vuln agent',
    prerequisites: ['recon']
  },
  'api-testing-vuln': {
    name: 'api-testing-vuln',
    displayName: 'API testing vuln agent',
    prerequisites: ['recon']
  },
  'info-gathering-exploit': {
    name: 'info-gathering-exploit',
    displayName: 'Info gathering exploit agent',
    prerequisites: ['info-gathering-vuln']
  },
  'config-deploy-exploit': {
    name: 'config-deploy-exploit',
    displayName: 'Config/deploy exploit agent',
    prerequisites: ['config-deploy-vuln']
  },
  'session-mgmt-exploit': {
    name: 'session-mgmt-exploit',
    displayName: 'Session mgmt exploit agent',
    prerequisites: ['session-mgmt-vuln']
  },
  'error-handling-exploit': {
    name: 'error-handling-exploit',
    displayName: 'Error handling exploit agent',
    prerequisites: ['error-handling-vuln']
  },
  'crypto-exploit': {
    name: 'crypto-exploit',
    displayName: 'Crypto exploit agent',
    prerequisites: ['crypto-vuln']
  },
  'api-testing-exploit': {
    name: 'api-testing-exploit',
    displayName: 'API testing exploit agent',
    prerequisites: ['api-testing-vuln']
  },
  'injection-exploit': {
    name: 'injection-exploit',
    displayName: 'Injection exploit agent',
    prerequisites: ['injection-vuln']
  },
  'xss-exploit': {
    name: 'xss-exploit',
    displayName: 'XSS exploit agent',
    prerequisites: ['xss-vuln']
  },
  'auth-exploit': {
    name: 'auth-exploit',
    displayName: 'Auth exploit agent',
    prerequisites: ['auth-vuln']
  },
  'ssrf-exploit': {
    name: 'ssrf-exploit',
    displayName: 'SSRF exploit agent',
    prerequisites: ['ssrf-vuln']
  },
  'authz-exploit': {
    name: 'authz-exploit',
    displayName: 'Authz exploit agent',
    prerequisites: ['authz-vuln']
  },
  'web-attacks-exploit': {
    name: 'web-attacks-exploit',
    displayName: 'Web attacks exploit agent',
    prerequisites: ['web-attacks-vuln']
  },
  'session-auth-exploit': {
    name: 'session-auth-exploit',
    displayName: 'Session & auth exploit agent',
    prerequisites: ['session-auth-vuln']
  },
  'business-logic-exploit': {
    name: 'business-logic-exploit',
    displayName: 'Business logic exploit agent',
    prerequisites: ['business-logic-vuln']
  },
  'client-side-exploit': {
    name: 'client-side-exploit',
    displayName: 'Client-side exploit agent',
    prerequisites: ['client-side-vuln']
  },
  'report': {
    name: 'report',
    displayName: 'Report agent',
    prerequisites: [
      'injection-exploit',
      'xss-exploit',
      'auth-exploit',
      'ssrf-exploit',
      'authz-exploit',
      'web-attacks-exploit',
      'session-auth-exploit',
      'business-logic-exploit',
      'client-side-exploit',
      'web-hardening',
      'info-gathering-exploit',
      'config-deploy-exploit',
      'session-mgmt-exploit',
      'error-handling-exploit',
      'crypto-exploit',
      'api-testing-exploit'
    ]
  }
});

// Agent execution order
export const AGENT_ORDER: readonly AgentName[] = Object.freeze([
  'pre-recon',
  'threat-model',
  'recon',
  'injection-vuln',
  'xss-vuln',
  'auth-vuln',
  'ssrf-vuln',
  'authz-vuln',
  'web-attacks-vuln',
  'session-auth-vuln',
  'business-logic-vuln',
  'client-side-vuln',
  'web-hardening',
  'info-gathering-vuln',
  'config-deploy-vuln',
  'session-mgmt-vuln',
  'error-handling-vuln',
  'crypto-vuln',
  'api-testing-vuln',
  'injection-exploit',
  'xss-exploit',
  'auth-exploit',
  'ssrf-exploit',
  'authz-exploit',
  'web-attacks-exploit',
  'session-auth-exploit',
  'business-logic-exploit',
  'client-side-exploit',
  'info-gathering-exploit',
  'config-deploy-exploit',
  'session-mgmt-exploit',
  'error-handling-exploit',
  'crypto-exploit',
  'api-testing-exploit',
  'report'
] as const);

// Parallel execution groups
export const getParallelGroups = (): Readonly<{ vuln: AgentName[]; exploit: AgentName[] }> => Object.freeze({
  vuln: [
    'injection-vuln',
    'xss-vuln',
    'auth-vuln',
    'ssrf-vuln',
    'authz-vuln',
    'web-attacks-vuln',
    'session-auth-vuln',
    'business-logic-vuln',
    'client-side-vuln',
    'web-hardening',
    'info-gathering-vuln',
    'config-deploy-vuln',
    'session-mgmt-vuln',
    'error-handling-vuln',
    'crypto-vuln',
    'api-testing-vuln'
  ],
  exploit: [
    'injection-exploit',
    'xss-exploit',
    'auth-exploit',
    'ssrf-exploit',
    'authz-exploit',
    'web-attacks-exploit',
    'session-auth-exploit',
    'business-logic-exploit',
    'client-side-exploit',
    'info-gathering-exploit',
    'config-deploy-exploit',
    'session-mgmt-exploit',
    'error-handling-exploit',
    'crypto-exploit',
    'api-testing-exploit'
  ]
});

// Phase names for metrics aggregation
export type PhaseName = 'pre-recon' | 'recon' | 'vulnerability-analysis' | 'exploitation' | 'reporting';

// Map agents to their corresponding phases (single source of truth)
export const AGENT_PHASE_MAP: Readonly<Record<AgentName, PhaseName>> = Object.freeze({
  'pre-recon': 'pre-recon',
  'threat-model': 'pre-recon',
  'recon': 'recon',
  'injection-vuln': 'vulnerability-analysis',
  'xss-vuln': 'vulnerability-analysis',
  'auth-vuln': 'vulnerability-analysis',
  'authz-vuln': 'vulnerability-analysis',
  'ssrf-vuln': 'vulnerability-analysis',
  'web-attacks-vuln': 'vulnerability-analysis',
  'session-auth-vuln': 'vulnerability-analysis',
  'business-logic-vuln': 'vulnerability-analysis',
  'client-side-vuln': 'vulnerability-analysis',
  'web-hardening': 'vulnerability-analysis',
  'info-gathering-vuln': 'vulnerability-analysis',
  'config-deploy-vuln': 'vulnerability-analysis',
  'session-mgmt-vuln': 'vulnerability-analysis',
  'error-handling-vuln': 'vulnerability-analysis',
  'crypto-vuln': 'vulnerability-analysis',
  'api-testing-vuln': 'vulnerability-analysis',
  'injection-exploit': 'exploitation',
  'xss-exploit': 'exploitation',
  'auth-exploit': 'exploitation',
  'authz-exploit': 'exploitation',
  'ssrf-exploit': 'exploitation',
  'web-attacks-exploit': 'exploitation',
  'session-auth-exploit': 'exploitation',
  'business-logic-exploit': 'exploitation',
  'client-side-exploit': 'exploitation',
  'info-gathering-exploit': 'exploitation',
  'config-deploy-exploit': 'exploitation',
  'session-mgmt-exploit': 'exploitation',
  'error-handling-exploit': 'exploitation',
  'crypto-exploit': 'exploitation',
  'api-testing-exploit': 'exploitation',
  'report': 'reporting',
});
