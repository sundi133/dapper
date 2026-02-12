// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Configuration type definitions
 */

export type RuleType =
  | 'path'
  | 'subdomain'
  | 'domain'
  | 'method'
  | 'header'
  | 'parameter';

export interface Rule {
  description: string;
  type: RuleType;
  url_path: string;
}

export interface Rules {
  avoid?: Rule[];
  focus?: Rule[];
}

export type LoginType = 'form' | 'sso' | 'api' | 'basic';

export type SuccessConditionType = 'url' | 'cookie' | 'element' | 'redirect';

export interface SuccessCondition {
  type: SuccessConditionType;
  value: string;
}

export interface Credentials {
  username: string;
  password: string;
  totp_secret?: string;
}

export interface Authentication {
  login_type: LoginType;
  login_url: string;
  credentials: Credentials;
  login_flow: string[];
  success_condition: SuccessCondition;
}

export interface Config {
  rules?: Rules;
  authentication?: Authentication;
  coverage?: CoverageConfig;
  targets?: string[];
  accounts?: Account[];
  seed_data?: string[];
  exploration?: ExplorationConfig;
  schemas?: SchemaConfig;
  login?: unknown; // Deprecated
}

export interface Account {
  role: string;
  username: string;
  password: string;
  totp_secret?: string;
}

export interface CoverageConfig {
  mode?: 'precision' | 'coverage';
  include_potential?: boolean;
  include_headers_tls?: boolean;
  include_sast_sca?: boolean;
  max_findings?: number;
}

export interface ExplorationConfig {
  max_depth?: number;
  max_requests?: number;
  recon_minutes?: number;
  exploit_minutes?: number;
}

export interface SchemaConfig {
  openapi_urls?: string[];
  graphql_endpoints?: string[];
}

export interface DistributedConfig {
  avoid: Rule[];
  focus: Rule[];
  authentication: Authentication | null;
  coverage: CoverageConfig;
  targets: string[];
  accounts: Account[];
  seed_data: string[];
  exploration: ExplorationConfig;
  schemas: SchemaConfig;
}
