// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

import { fs, path } from 'zx';
import chalk from 'chalk';
import { PentestError, handlePromptError } from '../error-handling.js';
import { MCP_AGENT_MAPPING } from '../constants.js';
import type { Authentication, DistributedConfig } from '../types/config.js';

interface PromptVariables {
  webUrl: string;
  repoPath: string;
  subDir?: string;
  MCP_SERVER?: string;
}

interface IncludeReplacement {
  placeholder: string;
  content: string;
}

// Pure function: Build complete login instructions from config
async function buildLoginInstructions(authentication: Authentication): Promise<string> {
  try {
    // Load the login instructions template
    const loginInstructionsPath = path.join(import.meta.dirname, '..', '..', 'prompts', 'shared', 'login-instructions.txt');

    if (!await fs.pathExists(loginInstructionsPath)) {
      throw new PentestError(
        'Login instructions template not found',
        'filesystem',
        false,
        { loginInstructionsPath }
      );
    }

    const fullTemplate = await fs.readFile(loginInstructionsPath, 'utf8');

    // Helper function to extract sections based on markers
    const getSection = (content: string, sectionName: string): string => {
      const regex = new RegExp(`<!-- BEGIN:${sectionName} -->([\\s\\S]*?)<!-- END:${sectionName} -->`, 'g');
      const match = regex.exec(content);
      return match ? match[1]!.trim() : '';
    };

    // Extract sections based on login type
    const loginType = authentication.login_type?.toUpperCase();
    let loginInstructions = '';

    // Build instructions with only relevant sections
    const commonSection = getSection(fullTemplate, 'COMMON');
    const authSection = loginType ? getSection(fullTemplate, loginType) : ''; // FORM or SSO
    const verificationSection = getSection(fullTemplate, 'VERIFICATION');

    // Fallback to full template if markers are missing (backward compatibility)
    if (!commonSection && !authSection && !verificationSection) {
      console.log(chalk.yellow('⚠️ Section markers not found, using full login instructions template'));
      loginInstructions = fullTemplate;
    } else {
      // Combine relevant sections
      loginInstructions = [commonSection, authSection, verificationSection]
        .filter(section => section) // Remove empty sections
        .join('\n\n');
    }

    // Replace the user instructions placeholder with the login flow from config
    let userInstructions = (authentication.login_flow ?? []).join('\n');

    // Replace credential placeholders within the user instructions
    if (authentication.credentials) {
      if (authentication.credentials.username) {
        userInstructions = userInstructions.replace(/\$username/g, authentication.credentials.username);
      }
      if (authentication.credentials.password) {
        userInstructions = userInstructions.replace(/\$password/g, authentication.credentials.password);
      }
      if (authentication.credentials.totp_secret) {
        userInstructions = userInstructions.replace(/\$totp/g, `generated TOTP code using secret "${authentication.credentials.totp_secret}"`);
      }
    }

    loginInstructions = loginInstructions.replace(/{{user_instructions}}/g, userInstructions);

    // Replace TOTP secret placeholder if present in template
    if (authentication.credentials?.totp_secret) {
      loginInstructions = loginInstructions.replace(/{{totp_secret}}/g, authentication.credentials.totp_secret);
    }

    return loginInstructions;
  } catch (error) {
    if (error instanceof PentestError) {
      throw error;
    }
    const errMsg = error instanceof Error ? error.message : String(error);
    throw new PentestError(
      `Failed to build login instructions: ${errMsg}`,
      'config',
      false,
      { authentication, originalError: errMsg }
    );
  }
}

// Pure function: Process @include() directives
async function processIncludes(content: string, baseDir: string): Promise<string> {
  const includeRegex = /@include\(([^)]+)\)/g;
  // Use a Promise.all to handle all includes concurrently
  const replacements: IncludeReplacement[] = await Promise.all(
    Array.from(content.matchAll(includeRegex)).map(async (match) => {
      const includePath = path.join(baseDir, match[1]!);
      const sharedContent = await fs.readFile(includePath, 'utf8');
      return {
        placeholder: match[0],
        content: sharedContent,
      };
    })
  );

  for (const replacement of replacements) {
    content = content.replace(replacement.placeholder, replacement.content);
  }
  return content;
}

// Pure function: Variable interpolation
async function interpolateVariables(
  template: string,
  variables: PromptVariables,
  config: DistributedConfig | null = null
): Promise<string> {
  try {
    if (!template || typeof template !== 'string') {
      throw new PentestError(
        'Template must be a non-empty string',
        'validation',
        false,
        { templateType: typeof template, templateLength: template?.length }
      );
    }

    if (!variables || !variables.webUrl || !variables.repoPath) {
      throw new PentestError(
        'Variables must include webUrl and repoPath',
        'validation',
        false,
        { variables: Object.keys(variables || {}) }
      );
    }

    let result = template
      .replace(/{{WEB_URL}}/g, variables.webUrl)
      .replace(/{{REPO_PATH}}/g, variables.repoPath)
      .replace(/{{MCP_SERVER}}/g, variables.MCP_SERVER || 'playwright-agent1');

    if (config) {
      // Handle rules section - if both are empty, use cleaner messaging
      const hasAvoidRules = config.avoid && config.avoid.length > 0;
      const hasFocusRules = config.focus && config.focus.length > 0;

      if (!hasAvoidRules && !hasFocusRules) {
        // Replace the entire rules section with a clean message
        const cleanRulesSection = '<rules>\nNo specific rules or focus areas provided for this test.\n</rules>';
        result = result.replace(/<rules>[\s\S]*?<\/rules>/g, cleanRulesSection);
      } else {
        const avoidRules = hasAvoidRules ? config.avoid!.map(r => `- ${r.description}`).join('\n') : 'None';
        const focusRules = hasFocusRules ? config.focus!.map(r => `- ${r.description}`).join('\n') : 'None';

        result = result
          .replace(/{{RULES_AVOID}}/g, avoidRules)
          .replace(/{{RULES_FOCUS}}/g, focusRules);
      }

      // Extract and inject login instructions from config
      if (config.authentication?.login_flow) {
        const loginInstructions = await buildLoginInstructions(config.authentication);
        result = result.replace(/{{LOGIN_INSTRUCTIONS}}/g, loginInstructions);
      } else {
        result = result.replace(/{{LOGIN_INSTRUCTIONS}}/g, '');
      }

      // Inject coverage mode instructions (default to precision)
      const coverageMode = config.coverage?.mode || 'precision';
      const includePotential = config.coverage?.include_potential ?? (coverageMode === 'coverage');
      const includeHeadersTls = config.coverage?.include_headers_tls ?? (coverageMode === 'coverage');
      const includeSastSca = config.coverage?.include_sast_sca ?? (coverageMode === 'coverage');
      const maxFindings = config.coverage?.max_findings;

      const coveragePolicyParts = [
        includePotential ? 'include potential (non-exploit-verified) findings' : 'exclude potential findings',
        includeHeadersTls ? 'include header/TLS/HSTS checks' : 'exclude header/TLS/HSTS checks',
        includeSastSca ? 'include SAST/SCA notes if observed' : 'exclude SAST/SCA notes',
        typeof maxFindings === 'number' ? `cap findings at ${maxFindings}` : 'no findings cap',
      ];

      const additionalTargets =
        config.targets && config.targets.length > 0 ? config.targets.map((t) => `- ${t}`).join('\n') : 'None';
      const accounts =
        config.accounts && config.accounts.length > 0
          ? config.accounts.map((a) => `- ${a.role}: ${a.username}${a.totp_secret ? ' (TOTP)' : ''}`).join('\n')
          : 'None';
      const seedData =
        config.seed_data && config.seed_data.length > 0 ? config.seed_data.map((s) => `- ${s}`).join('\n') : 'None';
      const explorationLimits =
        config.exploration && Object.keys(config.exploration).length > 0
          ? `max_depth=${config.exploration.max_depth ?? 'n/a'}, max_requests=${config.exploration.max_requests ?? 'n/a'}, recon_minutes=${config.exploration.recon_minutes ?? 'n/a'}, exploit_minutes=${config.exploration.exploit_minutes ?? 'n/a'}`
          : 'None';
      const apiSchemas =
        config.schemas && (config.schemas.openapi_urls?.length || config.schemas.graphql_endpoints?.length)
          ? [
              ...(config.schemas.openapi_urls?.map((u) => `- OpenAPI: ${u}`) ?? []),
              ...(config.schemas.graphql_endpoints?.map((u) => `- GraphQL: ${u}`) ?? []),
            ].join('\n')
          : 'None';

      result = result
        .replace(/{{COVERAGE_MODE}}/g, coverageMode)
        .replace(/{{COVERAGE_POLICY}}/g, coveragePolicyParts.join('; '))
        .replace(/{{ADDITIONAL_TARGETS}}/g, additionalTargets)
        .replace(/{{ACCOUNTS}}/g, accounts)
        .replace(/{{SEED_DATA}}/g, seedData)
        .replace(/{{EXPLORATION_LIMITS}}/g, explorationLimits)
        .replace(/{{API_SCHEMAS}}/g, apiSchemas);
    } else {
      // Replace the entire rules section with a clean message when no config provided
      const cleanRulesSection = '<rules>\nNo specific rules or focus areas provided for this test.\n</rules>';
      result = result.replace(/<rules>[\s\S]*?<\/rules>/g, cleanRulesSection);
      result = result.replace(/{{LOGIN_INSTRUCTIONS}}/g, '');
      result = result
        .replace(/{{COVERAGE_MODE}}/g, 'precision')
        .replace(
          /{{COVERAGE_POLICY}}/g,
          'exclude potential findings; exclude header/TLS/HSTS checks; exclude SAST/SCA notes; no findings cap'
        )
        .replace(/{{ADDITIONAL_TARGETS}}/g, 'None')
        .replace(/{{ACCOUNTS}}/g, 'None')
        .replace(/{{SEED_DATA}}/g, 'None')
        .replace(/{{EXPLORATION_LIMITS}}/g, 'None')
        .replace(/{{API_SCHEMAS}}/g, 'None');
    }

    // Inject subdirectory focus instruction if provided
    if (variables.subDir) {
      const subDirInstruction = `\n\n<subdirectory-focus>\nIMPORTANT: Focus your source code analysis ONLY on the "${variables.subDir}" subdirectory within the repository at ${variables.repoPath}. When reading, searching, or analyzing source code, restrict your scope to files under "${variables.repoPath}/${variables.subDir}". You may still perform full-scope web/network testing against the target URL, but all code review and static analysis must be limited to this subdirectory.\n</subdirectory-focus>`;
      result = subDirInstruction + '\n' + result;
    }

    // Validate that all placeholders have been replaced (excluding instructional text)
    const remainingPlaceholders = result.match(/\{\{[^}]+\}\}/g);
    if (remainingPlaceholders) {
      console.log(chalk.yellow(`⚠️ Warning: Found unresolved placeholders in prompt: ${remainingPlaceholders.join(', ')}`));
    }

    return result;
  } catch (error) {
    if (error instanceof PentestError) {
      throw error;
    }
    const errMsg = error instanceof Error ? error.message : String(error);
    throw new PentestError(
      `Variable interpolation failed: ${errMsg}`,
      'prompt',
      false,
      { originalError: errMsg }
    );
  }
}

// Pure function: Load and interpolate prompt template
export async function loadPrompt(
  promptName: string,
  variables: PromptVariables,
  config: DistributedConfig | null = null,
  pipelineTestingMode: boolean = false
): Promise<string> {
  try {
    // Use pipeline testing prompts if pipeline testing mode is enabled
    const baseDir = pipelineTestingMode ? 'prompts/pipeline-testing' : 'prompts';
    const promptsDir = path.join(import.meta.dirname, '..', '..', baseDir);
    const promptPath = path.join(promptsDir, `${promptName}.txt`);

    // Debug message for pipeline testing mode
    if (pipelineTestingMode) {
      console.log(chalk.yellow(`⚡ Using pipeline testing prompt: ${promptPath}`));
    }

    // Check if file exists first
    if (!await fs.pathExists(promptPath)) {
      throw new PentestError(
        `Prompt file not found: ${promptPath}`,
        'prompt',
        false,
        { promptName, promptPath }
      );
    }

    // Add MCP server assignment to variables
    const enhancedVariables: PromptVariables = { ...variables };

    // Assign MCP server based on prompt name (agent name)
    const mcpServer = MCP_AGENT_MAPPING[promptName as keyof typeof MCP_AGENT_MAPPING];
    if (mcpServer) {
      enhancedVariables.MCP_SERVER = mcpServer;
      console.log(chalk.gray(`    🎭 Assigned ${promptName} → ${enhancedVariables.MCP_SERVER}`));
    } else {
      // Fallback for unknown agents
      enhancedVariables.MCP_SERVER = 'playwright-agent1';
      console.log(chalk.yellow(`    🎭 Unknown agent ${promptName}, using fallback → ${enhancedVariables.MCP_SERVER}`));
    }

    let template = await fs.readFile(promptPath, 'utf8');

    // Pre-process the template to handle @include directives
    template = await processIncludes(template, promptsDir);

    return await interpolateVariables(template, enhancedVariables, config);
  } catch (error) {
    if (error instanceof PentestError) {
      throw error;
    }
    const promptError = handlePromptError(promptName, error as Error);
    throw promptError.error;
  }
}
