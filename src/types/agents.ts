// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Agent type definitions
 */

export type AgentName =
  | 'pre-recon'
  | 'threat-model'
  | 'recon'
  | 'injection-vuln'
  | 'xss-vuln'
  | 'auth-vuln'
  | 'ssrf-vuln'
  | 'authz-vuln'
  | 'web-attacks-vuln'
  | 'session-auth-vuln'
  | 'business-logic-vuln'
  | 'client-side-vuln'
  | 'web-hardening'
  | 'info-gathering-vuln'
  | 'config-deploy-vuln'
  | 'session-mgmt-vuln'
  | 'error-handling-vuln'
  | 'crypto-vuln'
  | 'api-testing-vuln'
  | 'info-gathering-exploit'
  | 'config-deploy-exploit'
  | 'session-mgmt-exploit'
  | 'error-handling-exploit'
  | 'crypto-exploit'
  | 'api-testing-exploit'
  | 'injection-exploit'
  | 'xss-exploit'
  | 'auth-exploit'
  | 'ssrf-exploit'
  | 'authz-exploit'
  | 'web-attacks-exploit'
  | 'session-auth-exploit'
  | 'business-logic-exploit'
  | 'client-side-exploit'
  | 'report';

export type PromptName =
  | 'pre-recon-code'
  | 'threat-model'
  | 'recon'
  | 'vuln-injection'
  | 'vuln-xss'
  | 'vuln-auth'
  | 'vuln-ssrf'
  | 'vuln-authz'
  | 'vuln-web-attacks'
  | 'vuln-session-auth'
  | 'vuln-business-logic'
  | 'vuln-client-side'
  | 'vuln-web-hardening'
  | 'vuln-info-gathering'
  | 'vuln-config-deploy'
  | 'vuln-session-mgmt'
  | 'vuln-error-handling'
  | 'vuln-crypto'
  | 'vuln-api-testing'
  | 'exploit-info-gathering'
  | 'exploit-config-deploy'
  | 'exploit-session-mgmt'
  | 'exploit-error-handling'
  | 'exploit-crypto'
  | 'exploit-api-testing'
  | 'exploit-injection'
  | 'exploit-xss'
  | 'exploit-auth'
  | 'exploit-ssrf'
  | 'exploit-authz'
  | 'exploit-web-attacks'
  | 'exploit-session-auth'
  | 'exploit-business-logic'
  | 'exploit-client-side'
  | 'report-executive';

export type PlaywrightAgent =
  | 'playwright-agent1'
  | 'playwright-agent2'
  | 'playwright-agent3'
  | 'playwright-agent4'
  | 'playwright-agent5';

export type AgentValidator = (sourceDir: string) => Promise<boolean>;

export type AgentStatus =
  | 'pending'
  | 'in_progress'
  | 'completed'
  | 'failed'
  | 'rolled-back';

export interface AgentDefinition {
  name: AgentName;
  displayName: string;
  prerequisites: AgentName[];
}

/**
 * Maps an agent name to its corresponding prompt file name.
 */
export function getPromptNameForAgent(agentName: AgentName): PromptName {
  const mappings: Record<AgentName, PromptName> = {
    'pre-recon': 'pre-recon-code',
    'threat-model': 'threat-model',
    'recon': 'recon',
    'injection-vuln': 'vuln-injection',
    'xss-vuln': 'vuln-xss',
    'auth-vuln': 'vuln-auth',
    'ssrf-vuln': 'vuln-ssrf',
    'authz-vuln': 'vuln-authz',
    'web-attacks-vuln': 'vuln-web-attacks',
    'session-auth-vuln': 'vuln-session-auth',
    'business-logic-vuln': 'vuln-business-logic',
    'client-side-vuln': 'vuln-client-side',
    'web-hardening': 'vuln-web-hardening',
    'info-gathering-vuln': 'vuln-info-gathering',
    'config-deploy-vuln': 'vuln-config-deploy',
    'session-mgmt-vuln': 'vuln-session-mgmt',
    'error-handling-vuln': 'vuln-error-handling',
    'crypto-vuln': 'vuln-crypto',
    'api-testing-vuln': 'vuln-api-testing',
    'info-gathering-exploit': 'exploit-info-gathering',
    'config-deploy-exploit': 'exploit-config-deploy',
    'session-mgmt-exploit': 'exploit-session-mgmt',
    'error-handling-exploit': 'exploit-error-handling',
    'crypto-exploit': 'exploit-crypto',
    'api-testing-exploit': 'exploit-api-testing',
    'injection-exploit': 'exploit-injection',
    'xss-exploit': 'exploit-xss',
    'auth-exploit': 'exploit-auth',
    'ssrf-exploit': 'exploit-ssrf',
    'authz-exploit': 'exploit-authz',
    'web-attacks-exploit': 'exploit-web-attacks',
    'session-auth-exploit': 'exploit-session-auth',
    'business-logic-exploit': 'exploit-business-logic',
    'client-side-exploit': 'exploit-client-side',
    'report': 'report-executive',
  };

  return mappings[agentName];
}
