#!/usr/bin/env node
/**
 * export-findings-csv.js
 *
 * Fully agentic security findings exporter.
 * Uses Claude Agent SDK to read, reason about, and extract structured
 * findings from ANY deliverables folder — no hardcoded parsing, regex,
 * or assumptions about file format.
 *
 * Usage:
 *   node export-findings-csv.js <deliverables-dir> [output.csv] [--model <model>] [--max-turns <n>] [--reuse-json]
 *
 * Env:
 *   ANTHROPIC_API_KEY or CLAUDE_CODE_OAUTH_TOKEN must be set.
 */

import fs from 'fs';
import path from 'path';
import { query } from '@anthropic-ai/claude-agent-sdk';

// ── Logging helpers ─────────────────────────────────────────────────────────

const CYAN = '\x1b[36m';
const GREEN = '\x1b[32m';
const YELLOW = '\x1b[33m';
const RED = '\x1b[31m';
const DIM = '\x1b[2m';
const BOLD = '\x1b[1m';
const RESET = '\x1b[0m';

const timestamp = () => {
  const now = new Date();
  return `${DIM}[${now.toLocaleTimeString()}]${RESET}`;
};

const log = (icon, color, ...args) => {
  console.log(`${timestamp()} ${color}${icon}${RESET}`, ...args);
};

const logInfo = (...args) => log('ℹ', CYAN, ...args);
const logSuccess = (...args) => log('✓', GREEN, ...args);
const logWarn = (...args) => log('⚠', YELLOW, ...args);
const logError = (...args) => log('✗', RED, ...args);
const logTool = (...args) => log('🔧', YELLOW, ...args);
const logAgent = (...args) => log('🤖', CYAN, ...args);
const logFile = (...args) => log('📄', DIM, ...args);

// ── CLI args ────────────────────────────────────────────────────────────────

const args = process.argv.slice(2);

const flag = (name) => {
  const idx = args.indexOf(`--${name}`);
  if (idx === -1) return undefined;
  return args[idx + 1];
};

const positional = args.filter((a, i) => !a.startsWith('--') && !(i > 0 && args[i - 1]?.startsWith('--')));
const deliverablesDir = positional[0] || 'deliverables';
const outputPath = positional[1] || path.join(deliverablesDir, 'findings.csv');
const model = flag('model') || 'claude-sonnet-4-5-20250929';
const maxTurns = parseInt(flag('max-turns') || '120', 10);
const reuseJson = args.includes('--reuse-json');

// ── Validation ──────────────────────────────────────────────────────────────

if (!fs.existsSync(deliverablesDir)) {
  logError(`Deliverables directory not found: ${deliverablesDir}`);
  process.exit(1);
}

if (!reuseJson && !process.env.ANTHROPIC_API_KEY && !process.env.CLAUDE_CODE_OAUTH_TOKEN) {
  logError('Missing ANTHROPIC_API_KEY or CLAUDE_CODE_OAUTH_TOKEN.');
  process.exit(1);
}

const absDeliverables = path.resolve(deliverablesDir);
const absOutput = path.resolve(outputPath);
const jsonOutputPath = absOutput.replace(/\.csv$/, '') + '_findings.json';

console.log('');
console.log(`${BOLD}═══════════════════════════════════════════════════════════${RESET}`);
console.log(`${BOLD}  Agentic Security Findings Exporter${RESET}`);
console.log(`${BOLD}═══════════════════════════════════════════════════════════${RESET}`);
console.log('');
logInfo(`Deliverables : ${absDeliverables}`);
logInfo(`Output CSV   : ${absOutput}`);
logInfo(`JSON interim : ${jsonOutputPath}`);
logInfo(`Model        : ${model}`);
logInfo(`Max turns    : ${maxTurns}`);
logInfo(`Reuse JSON   : ${reuseJson ? 'yes' : 'no'}`);
console.log('');

// ── Agent instructions (appended to claude_code preset) ─────────────────────

const APPEND_INSTRUCTIONS = `
## YOUR ROLE
You are a senior penetration-testing report analyst.

## YOUR TASK
1. Read every file in the deliverables directory: ${absDeliverables}
2. Identify ALL discrete security findings / vulnerabilities across all files.
3. Cross-reference findings across files (e.g. an exploitation queue JSON may list a finding ID that also appears in an evidence markdown).
4. For each unique finding, extract as much structured detail as possible.
5. For each finding, generate a clear step-by-step developer verification guide.
6. Write the final result as a SINGLE valid JSON array to: ${jsonOutputPath}

## CRITICAL: BE EFFICIENT WITH TOOL CALLS
You have a limited turn budget. DO NOT waste turns reading one file at a time.
- Use bash to read multiple files at once: cat file1.json file2.md file3.md
- For large directories, use: for f in *.json *.md; do echo "=== $f ==="; cat "$f"; done
- Use bash head/tail to preview files first if needed, then batch-read
- Prioritize: list files → batch-read ALL files in 1-3 bash calls → analyze → write JSON
- DO NOT use the Read tool one file at a time. Use bash cat to read multiple files per turn.

## STEP-BY-STEP INSTRUCTIONS
1. First, run: ls -la "${absDeliverables}" to see all files and their sizes.
2. Batch-read files efficiently using bash:
   - For JSON files: for f in "${absDeliverables}"/*.json; do echo "=== $(basename $f) ==="; cat "$f"; done
   - For MD files: for f in "${absDeliverables}"/*.md; do echo "=== $(basename $f) ==="; cat "$f"; done
   - For other files: cat them similarly
3. Extract every discrete security finding across ALL files.
4. Cross-reference: if a finding ID (like "APP-VULN-001") appears in multiple files, merge the data into one record.
5. For each finding, extract whichever of these fields are available (use empty string "" for missing):

   CORE FIELDS:
   - id: The finding identifier
   - type: Vulnerability type/class (e.g. XSS, SQLi, SSRF, BOLA, etc.)
   - severity: Critical/High/Medium/Low/Info
   - status: exploited / blocked / false_positive / potential / unknown
   - source_endpoint: The affected URL/route/endpoint
   - parameter: The vulnerable parameter
   - code_location: File/line in source code
   - missing_defense: What security control is absent
   - attack_path: Full attack chain description
   - exploitation_hypothesis: How an attacker would exploit this
   - confidence: Confidence level of the finding
   - externally_exploitable: Whether externally exploitable (true/false/unknown)
   - cwe: Compact CWE summary, e.g. "CWE-89: SQL Injection" or "CWE-639: IDOR; CWE-862: Missing Authorization"
   - cwe_names: CWE short name(s) matching cwe_ids
   - remediation_suggestions: Actionable remediation guidance for engineers. If remediation is unavailable, synthesize concrete suggestions.
   - evidence_snippet: Key evidence text (max 300 chars)
   - exploit_result: What happened when exploited
   - affected_endpoint: Specific affected endpoint
   - attack_steps_summary: Summary of attack steps
   - report_section: Which report section this came from
   - source_file: Which file(s) this finding came from
   - notes: Any additional notes

   CYBER RISK QUANTIFICATION (CRQ) FIELDS — REQUIRED for every finding:
   - likelihood: How likely this vulnerability will be exploited. Use one of: "almost_certain" / "likely" / "possible" / "unlikely" / "rare"
     Base this on: attack complexity, public exploit availability, authentication required, exposure surface.
     Exploited findings should be "almost_certain" or "likely". Blocked findings should be "unlikely" or "rare".
   - impact_level: Business impact if exploited. Use one of: "critical" / "high" / "moderate" / "low" / "informational"
     Consider: data sensitivity, scope of access gained, regulatory consequences, service disruption potential.
   - risk_score: Numeric 1-10 risk score combining likelihood and impact. 10 = critical exploited vuln with massive business impact, 1 = informational finding.
   - estimated_annual_occurrence: Estimated number of times per year this could be exploited in the wild (e.g. "50-100" for common SQLi, "1-5" for complex chain attacks, "0" for false positives)
   - business_impact: Specific business consequences. Be concrete: "Full database extraction exposing 10K+ user records including PII" not "data breach".
     Include: what data/systems are affected, regulatory exposure, operational impact, reputational risk.
   - data_at_risk: What specific data or assets are exposed (e.g. "User PII (emails, passwords, addresses)", "Session tokens", "Financial records", "Source code", "Internal API keys")
   - compliance_impact: Which regulatory frameworks are affected. Use specific references: "GDPR Art. 32 (security of processing)", "PCI-DSS Req 6.5.1 (injection flaws)", "SOC2 CC6.1", "HIPAA 164.312(a)(1)", "OWASP Top 10 A03:2021". Use "" if no clear compliance impact.

   ATTACK CHAIN FIELDS — analyze how vulnerabilities connect:
   - attack_chain_id: If this finding can be chained with other findings for greater impact, assign a chain ID (e.g. "CHAIN-01", "CHAIN-02").
     Look for: authentication bypass → privilege escalation, information disclosure → targeted exploitation, injection → data extraction chains.
     Use "" if the finding is standalone and doesn't participate in any chain.
   - attack_chain_role: The role of this finding within its chain. Use one of: "entry_point" / "pivot" / "impact" / "standalone"
     - entry_point: Initial access vector (e.g. SQLi auth bypass, exposed endpoint)
     - pivot: Enables lateral movement or escalation (e.g. IDOR after auth bypass)
     - impact: Final payload / business damage (e.g. data extraction, account takeover)
     - standalone: Not part of a chain
   - attack_chain_description: Full narrative of the chain this finding participates in. Describe the complete attack flow from entry to impact.
     Example: "Attacker uses SQL injection (INJ-VULN-01) to bypass authentication and gain admin access, then leverages admin API (AUTHZ-VULN-03) to extract all user records including password hashes (INJ-VULN-02), enabling offline cracking and full account takeover."
   - chained_with: Comma-separated list of other finding IDs in the same chain (e.g. "INJ-VULN-01, AUTHZ-VULN-03")

   DEVELOPER VERIFICATION STEPS — REQUIRED for every finding:
   - developer_verification_steps: A clear, numbered, step-by-step guide that a developer can follow
     to reproduce and verify this vulnerability in their own environment.
     This must be actionable and specific to THIS finding, not generic advice.
     Format as a numbered list separated by " | " (pipe with spaces).
     Example: "1. Start the application locally | 2. Authenticate as a regular user (role: viewer) | 3. Send GET /api/v1/users/OTHER_USER_ID with your session token | 4. Observe that the response returns another user's PII without authorization check | 5. Compare with admin-only endpoint to confirm BOLA | 6. Expected: 403 Forbidden. Actual: 200 OK with full user object"
     Include: prerequisites/setup, exact request details (method, URL, headers, body),
     what to observe, expected vs actual behavior, and how to confirm the fix works.
     If the finding has exploit evidence or attack steps in the source data, base the
     verification steps on that real evidence. If not, synthesize reasonable steps
     from the vulnerability type, endpoint, parameter, and context available.

   If you discover additional relevant fields in the data, include them too.

6. Write the merged JSON array to: ${jsonOutputPath}
   The file must contain ONLY a valid JSON array — no markdown fences, no commentary, no extra text.
   Use the Write tool or bash to write the file.

## IMPORTANT RULES
- Be thorough. Read every file. Do not skip files.
- BE EFFICIENT. Batch file reads using bash. Do not read one file per turn.
- Merge information: if the same finding ID appears in multiple files, combine all fields into one record.
- Do NOT invent data. If a field is not present, use empty string "".
- When a CWE is reasonably inferable from the vulnerability type, exploit path, or missing defense, populate cwe_ids and cwe_names.
- The developer_verification_steps field is REQUIRED for every finding. Generate it based on available context.
- CRQ fields (likelihood, impact_level, risk_score, business_impact, data_at_risk, compliance_impact) are REQUIRED for every finding. Assess these based on the vulnerability evidence, severity, and exploitation status.
- Attack chain analysis is REQUIRED: look across ALL findings to identify multi-step attack paths. Assign matching attack_chain_id values to findings that chain together. A single assessment typically has 2-5 attack chains.
- After writing the JSON output file, output a brief summary of how many findings you found, including attack chain count.
`;

// ── Run agent ───────────────────────────────────────────────────────────────

const extractContent = (message) => {
  if (!message?.message?.content) return '';
  const content = message.message.content;
  if (Array.isArray(content)) {
    return content
      .filter((c) => c.type === 'text')
      .map((c) => c.text || '')
      .join('\n');
  }
  return String(content);
};

const extractToolCalls = (message) => {
  if (!message?.message?.content) return [];
  const content = message.message.content;
  if (!Array.isArray(content)) return [];
  return content.filter((c) => c.type === 'tool_use');
};

const formatToolInput = (tool) => {
  const name = tool.name || 'unknown';
  const input = tool.input || {};

  if (name === 'Bash' || name === 'bash') {
    const cmd = input.command || '';
    return `${YELLOW}bash${RESET} → ${DIM}${cmd.length > 150 ? cmd.slice(0, 150) + '...' : cmd}${RESET}`;
  }
  if (name === 'Read' || name === 'read') {
    const file = input.file_path || input.path || '';
    return `${CYAN}read${RESET} → ${DIM}${file}${RESET}`;
  }
  if (name === 'Write' || name === 'write') {
    const file = input.file_path || input.path || '';
    const size = (input.content || input.file_text || '').length;
    return `${GREEN}write${RESET} → ${DIM}${file} (${size} chars)${RESET}`;
  }
  if (name === 'Glob' || name === 'glob') {
    const pattern = input.pattern || input.glob || '';
    return `${DIM}glob${RESET} → ${DIM}${pattern}${RESET}`;
  }
  if (name === 'Grep' || name === 'grep') {
    const pattern = input.pattern || input.regex || '';
    return `${DIM}grep${RESET} → ${DIM}${pattern}${RESET}`;
  }
  return `${DIM}${name}${RESET} → ${DIM}${JSON.stringify(input).slice(0, 100)}${RESET}`;
};

const runAgent = async () => {
  const options = {
    model,
    maxTurns,
    permissionMode: 'bypassPermissions',
    allowDangerouslySkipPermissions: true,
    allowedTools: ['Bash', 'Read', 'Write', 'Glob', 'Grep'],
    systemPrompt: {
      type: 'preset',
      preset: 'claude_code',
      append: APPEND_INSTRUCTIONS,
    },
    cwd: absDeliverables,
  };

  const taskPrompt = `Analyze all security deliverables in ${absDeliverables} and extract every finding into a structured JSON file at ${jsonOutputPath}.

IMPORTANT: Be efficient with tool calls. Use bash to batch-read files (e.g. "for f in *.json; do echo '=== $f ==='; cat $f; done") instead of reading one file at a time. You have ${maxTurns} turns — use them wisely.

REQUIRED for every finding:
- "developer_verification_steps": numbered, actionable steps a developer can follow to reproduce and verify the vulnerability
- CRQ fields: "likelihood", "impact_level", "risk_score", "business_impact", "data_at_risk", "compliance_impact"
- Attack chain analysis: identify multi-step attack paths across findings and assign "attack_chain_id", "attack_chain_role", "attack_chain_description", "chained_with"

Base these on the actual evidence, endpoints, parameters, and exploit details found in the deliverables.

Start by listing the files, then batch-read them.`;

  let resultText = '';
  let gotResult = false;
  let turnNum = 0;
  let toolCallCount = 0;
  const startTime = Date.now();

  logInfo('Launching agent...');
  console.log('');

  try {
    for await (const message of query({ prompt: taskPrompt, options })) {
      // ── System init ──
      if (message.type === 'system' && message.subtype === 'init') {
        logSuccess(`Session started: ${DIM}${message.session_id}${RESET}`);
        console.log('');
      }

      // ── Assistant turn ──
      if (message.type === 'assistant') {
        turnNum++;
        const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
        const turnBudget = `${turnNum}/${maxTurns}`;
        const budgetColor = turnNum > maxTurns * 0.8 ? RED : turnNum > maxTurns * 0.5 ? YELLOW : GREEN;
        console.log(`${timestamp()} ${BOLD}── Turn ${budgetColor}${turnBudget}${RESET}${BOLD} ──${RESET} ${DIM}(${elapsed}s elapsed)${RESET}`);

        // Warn when running low on turns
        if (turnNum === Math.floor(maxTurns * 0.7)) {
          logWarn(`${YELLOW}70% of turn budget used (${turnNum}/${maxTurns}). Agent should start writing output soon.${RESET}`);
        }
        if (turnNum === Math.floor(maxTurns * 0.9)) {
          logWarn(`${RED}90% of turn budget used (${turnNum}/${maxTurns})! Agent must write output NOW.${RESET}`);
        }

        // Log tool calls
        const tools = extractToolCalls(message);
        for (const tool of tools) {
          toolCallCount++;
          logTool(`[${toolCallCount}] ${formatToolInput(tool)}`);
        }

        // Log assistant text (truncated)
        const text = extractContent(message);
        if (text) {
          resultText = text;
          const preview = text.replace(/\s+/g, ' ').trim();
          if (preview.length > 0) {
            const truncated = preview.length > 200 ? preview.slice(0, 200) + '...' : preview;
            logAgent(`${DIM}${truncated}${RESET}`);
          }
        }
        console.log('');
      }

      // ── User message (tool results flowing back) ──
      if (message.type === 'user') {
        const content = message.message?.content;
        if (Array.isArray(content)) {
          for (const block of content) {
            if (block.type === 'tool_result') {
              const resultPreview = typeof block.content === 'string'
                ? block.content
                : Array.isArray(block.content)
                  ? block.content.map(c => c.text || '').join(' ')
                  : '';
              if (resultPreview) {
                const lines = resultPreview.split('\n').length;
                const chars = resultPreview.length;
                logFile(`Tool result: ${DIM}${lines} lines, ${chars} chars${RESET}`);
              }
            }
          }
        }
      }

      // ── Final result ──
      if (message.type === 'result') {
        gotResult = true;
        const cost = message.total_cost_usd?.toFixed(4) || '?';
        const dur = ((message.duration_ms || 0) / 1000).toFixed(1);
        const totalElapsed = ((Date.now() - startTime) / 1000).toFixed(1);

        console.log('');
        console.log(`${BOLD}═══════════════════════════════════════════════════════════${RESET}`);
        console.log(`${BOLD}  Agent Summary${RESET}`);
        console.log(`${BOLD}═══════════════════════════════════════════════════════════${RESET}`);
        logSuccess(`Status     : ${message.is_error ? RED + 'ERROR' : GREEN + 'SUCCESS'}${RESET}`);
        logInfo(`Turns      : ${message.num_turns} / ${maxTurns}`);
        logInfo(`Tool calls : ${toolCallCount}`);
        logInfo(`Duration   : ${dur}s (wall: ${totalElapsed}s)`);
        logInfo(`Cost       : $${cost}`);

        if (message.is_error) {
          logError(`Error: ${message.result}`);
        }
        if (message.result) {
          resultText = message.result;
          const preview = resultText.replace(/\s+/g, ' ').trim();
          const truncated = preview.length > 300 ? preview.slice(0, 300) + '...' : preview;
          logAgent(`Final: ${DIM}${truncated}${RESET}`);
        }
        console.log('');
      }
    }
  } catch (err) {
    if (gotResult) {
      logWarn('Ignoring post-completion process exit signal (SDK quirk)');
      return resultText;
    }
    const details = err && typeof err === 'object'
      ? JSON.stringify(err, Object.getOwnPropertyNames(err), 2)
      : String(err);
    logError(`Agent error: ${details}`);
    process.exit(1);
  }

  return resultText;
};

// ── Parse agent output → CSV ────────────────────────────────────────────────

const csvEscape = (value) => {
  const v = value === null || value === undefined ? '' : String(value);
  if (v.includes('"') || v.includes(',') || v.includes('\n') || v.includes('\r')) {
    return `"${v.replace(/"/g, '""')}"`;
  }
  return v;
};

const tryLoadJson = (filePath) => {
  if (!fs.existsSync(filePath)) return null;
  try {
    const raw = fs.readFileSync(filePath, 'utf8').trim();
    const cleaned = raw.replace(/^```json\s*/i, '').replace(/\s*```$/i, '');
    const data = JSON.parse(cleaned);
    if (Array.isArray(data) && data.length > 0) return data;
  } catch { /* skip */ }
  return null;
};

const loadFindings = () => {
  logInfo('Loading agent output...');

  // Primary: where we told the agent to write
  const primary = tryLoadJson(jsonOutputPath);
  if (primary) {
    logSuccess(`Loaded ${primary.length} findings from ${jsonOutputPath}`);
    return primary;
  }

  // Fallback: scan for any JSON arrays
  logWarn('Primary JSON not found, scanning for agent output...');
  const candidates = [];

  for (const dir of [absDeliverables, path.dirname(absDeliverables), process.cwd()]) {
    try {
      for (const f of fs.readdirSync(dir)) {
        if (f.endsWith('.json')) {
          const fp = path.join(dir, f);
          if (!candidates.includes(fp)) {
            candidates.push(fp);
            logFile(`Candidate: ${DIM}${fp}${RESET}`);
          }
        }
      }
    } catch { /* ignore */ }
  }

  for (const candidate of candidates) {
    const data = tryLoadJson(candidate);
    if (data) {
      logSuccess(`Loaded ${data.length} findings from ${candidate}`);
      return data;
    }
  }

  return null;
};

const CWE_RULES = [
  {
    id: 'CWE-89',
    name: 'Improper Neutralization of Special Elements used in an SQL Command',
    patterns: ['sql_injection', 'sql injection', 'union select', 'sqlite', 'database error'],
    remediation:
      'Use parameterized queries or ORM-bound parameters for all database access. Reject or safely encode attacker-controlled input before it reaches SQL construction.',
    risk: { likelihood: 'likely', impact: 'critical', business: 'Database extraction, data breach, authentication bypass', compliance: 'PCI-DSS Req 6.5.1; OWASP A03:2021' },
  },
  {
    id: 'CWE-79',
    name: 'Improper Neutralization of Input During Web Page Generation',
    patterns: ['xss', 'cross-site scripting', 'cross site scripting', 'script injection'],
    remediation:
      'Apply context-aware output encoding, validate and sanitize untrusted input, and enforce a restrictive Content-Security-Policy to reduce script injection impact.',
    risk: { likelihood: 'likely', impact: 'high', business: 'Session hijacking, credential theft, defacement', compliance: 'PCI-DSS Req 6.5.7; OWASP A03:2021' },
  },
  {
    id: 'CWE-918',
    name: 'Server-Side Request Forgery (SSRF)',
    patterns: ['ssrf', 'server-side request forgery', 'server side request forgery'],
    remediation:
      'Strictly validate outbound destinations against an allowlist, block internal address ranges and metadata endpoints, and route outbound requests through a hardened proxy.',
    risk: { likelihood: 'possible', impact: 'critical', business: 'Internal network access, cloud metadata exposure, data exfiltration', compliance: 'OWASP A10:2021; SOC2 CC6.6' },
  },
  {
    id: 'CWE-639',
    name: 'Authorization Bypass Through User-Controlled Key',
    patterns: ['bola', 'idor', 'book_title', 'username (path parameter)', 'broken object level authorization'],
    remediation:
      'Authorize access using the authenticated user context on every object lookup. Never trust path, query, or body identifiers alone to decide ownership.',
    risk: { likelihood: 'likely', impact: 'high', business: 'Unauthorized data access, cross-user data leakage', compliance: 'GDPR Art. 32; OWASP A01:2021' },
  },
  {
    id: 'CWE-862',
    name: 'Missing Authorization',
    patterns: ['missing authorization', 'no ownership verification', 'authorization not checked', 'admin-only', 'privilege escalation'],
    remediation:
      'Add explicit authorization checks server-side for each privileged action and deny requests that are not permitted for the authenticated principal.',
    risk: { likelihood: 'likely', impact: 'critical', business: 'Privilege escalation, unauthorized administrative actions', compliance: 'SOC2 CC6.1; OWASP A01:2021' },
  },
  {
    id: 'CWE-287',
    name: 'Improper Authentication',
    patterns: ['authentication_bypass', 'auth bypass', 'improper authentication', 'forged token'],
    remediation:
      'Require robust authentication for protected operations, validate tokens securely, and reject forged or malformed credentials before business logic executes.',
    risk: { likelihood: 'likely', impact: 'critical', business: 'Complete authentication bypass, account takeover', compliance: 'PCI-DSS Req 8; OWASP A07:2021; SOC2 CC6.1' },
  },
  {
    id: 'CWE-321',
    name: 'Use of Hard-coded Cryptographic Key',
    patterns: ['hardcoded secret', 'hardcoded secret_key', 'hardcoded cryptographic', 'jwt secret key hardcoded', 'secret key hardcoded'],
    remediation:
      'Remove hard-coded cryptographic material from source control. Load high-entropy secrets from a secure secret manager or environment and support rotation.',
    risk: { likelihood: 'possible', impact: 'critical', business: 'Token forgery, cryptographic bypass, persistent compromise', compliance: 'PCI-DSS Req 3.5; OWASP A02:2021' },
  },
  {
    id: 'CWE-798',
    name: 'Use of Hard-coded Credentials',
    patterns: ['default_credentials', 'default credentials', 'hardcoded credentials', 'admin:pass1'],
    remediation:
      'Eliminate default or embedded credentials. Generate unique bootstrap credentials per environment and require immediate rotation on first use.',
    risk: { likelihood: 'almost_certain', impact: 'critical', business: 'Trivial unauthorized access via known credentials', compliance: 'PCI-DSS Req 2.1; OWASP A07:2021' },
  },
  {
    id: 'CWE-256',
    name: 'Plaintext Storage of a Password',
    patterns: ['plaintext_password_storage', 'plaintext passwords', 'password hashing', 'stored as plaintext'],
    remediation:
      'Hash passwords with a modern password hashing algorithm such as Argon2id or bcrypt, add per-password salt, and avoid storing recoverable plaintext passwords.',
    risk: { likelihood: 'possible', impact: 'critical', business: 'Mass credential compromise if database is breached', compliance: 'GDPR Art. 32; PCI-DSS Req 8.2.1; OWASP A02:2021' },
  },
  {
    id: 'CWE-306',
    name: 'Missing Authentication for Critical Function',
    patterns: ['unauthenticated_destructive_operation', 'no authentication required', 'without any authentication', 'createdb'],
    remediation:
      'Require strong authentication before invoking administrative or destructive actions, and remove development-only maintenance endpoints from production.',
    risk: { likelihood: 'likely', impact: 'critical', business: 'Unauthenticated access to destructive or administrative operations', compliance: 'OWASP A07:2021; SOC2 CC6.1' },
  },
  {
    id: 'CWE-915',
    name: 'Improperly Controlled Modification of Dynamically-Determined Object Attributes',
    patterns: ['mass_assignment', 'mass assignment', 'admin:true', 'improperly controlled modification'],
    remediation:
      'Use an explicit allowlist of writable fields for object creation and update operations. Ignore or reject privilege-bearing fields supplied by clients.',
    risk: { likelihood: 'possible', impact: 'high', business: 'Privilege escalation via parameter manipulation', compliance: 'OWASP A04:2021' },
  },
  {
    id: 'CWE-489',
    name: 'Active Debug Code',
    patterns: ['debug_mode_enabled', 'debug mode', 'werkzeug debugger', 'debug_endpoint'],
    remediation:
      'Disable debug tooling and developer-only endpoints in production builds. Gate any diagnostics behind secure environment checks and authentication.',
    risk: { likelihood: 'possible', impact: 'high', business: 'Remote code execution, internal information disclosure', compliance: 'OWASP A05:2021' },
  },
  {
    id: 'CWE-209',
    name: 'Generation of Error Message Containing Sensitive Information',
    patterns: ['verbose_error_messages', 'stack trace', 'schema_disclosure', 'debug_mode_stack_traces', 'validation errors', 'authentication_error_disclosure'],
    remediation:
      'Return generic client-facing errors and log detailed diagnostic context server-side only. Avoid exposing stack traces, schema details, and framework internals.',
    risk: { likelihood: 'likely', impact: 'low', business: 'Information leakage aiding targeted attacks', compliance: 'OWASP A05:2021' },
  },
  {
    id: 'CWE-703',
    name: 'Improper Check or Handling of Exceptional Conditions',
    patterns: ['missing_exception_handling', 'bare_except_block', 'bare except', 'try/except'],
    remediation:
      'Handle expected exceptions explicitly, fail closed on unexpected errors, and return correct HTTP status codes while preserving server-side logs for debugging.',
    risk: { likelihood: 'possible', impact: 'moderate', business: 'Unexpected application behavior, potential security bypass', compliance: 'OWASP A05:2021' },
  },
  {
    id: 'CWE-307',
    name: 'Improper Restriction of Excessive Authentication Attempts',
    patterns: ['missing_rate_limiting', 'brute force', 'rate limiting', 'credential stuffing'],
    remediation:
      'Apply rate limiting, lockout or progressive backoff controls on authentication and other abuse-prone endpoints, and alert on repeated failures.',
    risk: { likelihood: 'likely', impact: 'high', business: 'Brute force credential compromise, account takeover at scale', compliance: 'PCI-DSS Req 8.1.6; OWASP A07:2021' },
  },
  {
    id: 'CWE-799',
    name: 'Improper Control of Interaction Frequency',
    patterns: ['missing_rate_limiting_registration', 'unlimited', 'registration'],
    remediation:
      'Limit request rates for registration and other public workflows, add abuse detection, and require additional verification for suspicious activity.',
    risk: { likelihood: 'possible', impact: 'moderate', business: 'Abuse of registration, spam accounts, resource exhaustion', compliance: 'OWASP A04:2021' },
  },
  {
    id: 'CWE-613',
    name: 'Insufficient Session Expiration',
    patterns: ['missing_token_revocation', 'no_logout', 'unlimited_concurrent_sessions', 'missing_token_binding', 'token revocation', 'concurrent sessions'],
    remediation:
      'Track active sessions server-side, revoke tokens on logout or sensitive account changes, enforce session lifetimes, and limit concurrent active sessions.',
    risk: { likelihood: 'possible', impact: 'high', business: 'Persistent unauthorized access via stolen or stale tokens', compliance: 'OWASP A07:2021; SOC2 CC6.1' },
  },
  {
    id: 'CWE-294',
    name: 'Authentication Bypass by Capture-replay',
    patterns: ['token_replay', 'token replay'],
    remediation:
      'Bind tokens to strong session context where appropriate, shorten token lifetime, rotate refresh tokens, and detect replay of previously seen credentials.',
    risk: { likelihood: 'unlikely', impact: 'high', business: 'Session hijacking via replayed credentials', compliance: 'OWASP A07:2021' },
  },
  {
    id: 'CWE-525',
    name: 'Information Exposure Through Browser Caching',
    patterns: ['missing_cache_control_headers', 'cache-control', 'cache control'],
    remediation:
      'Set Cache-Control: no-store for sensitive responses and ensure downstream proxies and browsers do not persist authenticated content.',
    risk: { likelihood: 'unlikely', impact: 'low', business: 'Sensitive data cached on shared devices', compliance: 'OWASP A05:2021' },
  },
  {
    id: 'CWE-208',
    name: 'Observable Timing Discrepancy',
    patterns: ['timing_attack', 'timing attack', 'timing discrepancy'],
    remediation:
      'Use constant-time comparisons for sensitive values and make authentication failure paths perform equivalent work to reduce timing side channels.',
    risk: { likelihood: 'rare', impact: 'moderate', business: 'Credential enumeration via timing side-channel', compliance: 'OWASP A02:2021' },
  },
  {
    id: 'CWE-367',
    name: 'Time-of-check Time-of-use (TOCTOU) Race Condition',
    patterns: ['race_condition_toctou', 'race condition', 'toctou'],
    remediation:
      'Make state validation and mutation atomic using transactions, row-level locking, or idempotency controls so concurrent requests cannot bypass invariants.',
    risk: { likelihood: 'unlikely', impact: 'high', business: 'Business logic bypass, double-spend, inventory manipulation', compliance: 'OWASP A04:2021' },
  },
  {
    id: 'CWE-1021',
    name: 'Improper Restriction of Rendered UI Layers or Frames',
    patterns: ['clickjacking', 'frame-options', 'x-frame-options'],
    remediation:
      'Set X-Frame-Options or frame-ancestors in CSP and ensure sensitive pages cannot be embedded by untrusted origins.',
    risk: { likelihood: 'unlikely', impact: 'moderate', business: 'UI redress attacks tricking users into unintended actions', compliance: 'OWASP A05:2021' },
  },
  {
    id: 'CWE-319',
    name: 'Cleartext Transmission of Sensitive Information',
    patterns: ['weak_tls', 'missing_application_tls', 'insecure_token_delivery', 'http-only', 'unencrypted channel'],
    remediation:
      'Enforce TLS end to end for all sensitive traffic, redirect HTTP to HTTPS, and avoid transmitting secrets or tokens over cleartext channels.',
    risk: { likelihood: 'possible', impact: 'high', business: 'Credential interception, man-in-the-middle attacks', compliance: 'PCI-DSS Req 4.1; GDPR Art. 32; OWASP A02:2021' },
  },
  {
    id: 'CWE-312',
    name: 'Cleartext Storage of Sensitive Information',
    patterns: ['unencrypted_database_storage', 'encryption at rest', 'plaintext file', 'database.db'],
    remediation:
      'Encrypt sensitive data at rest, protect encryption keys separately from the data store, and minimize direct filesystem exposure to stored secrets.',
    risk: { likelihood: 'possible', impact: 'critical', business: 'Bulk data exposure if storage is compromised', compliance: 'GDPR Art. 32; PCI-DSS Req 3.4; HIPAA 164.312(a)(2)(iv)' },
  },
  {
    id: 'CWE-200',
    name: 'Exposure of Sensitive Information to an Unauthorized Actor',
    patterns: ['information_disclosure', 'sensitive_data_exposure', 'user_enumeration', 'api_spec_exposure', 'header_leakage', 'security_posture_leak'],
    remediation:
      'Limit sensitive data returned to unauthenticated or unauthorized users, remove unnecessary disclosure endpoints, and minimize metadata leaked in responses.',
    risk: { likelihood: 'likely', impact: 'moderate', business: 'Information leakage enabling targeted attacks', compliance: 'GDPR Art. 5(1)(f); OWASP A01:2021' },
  },
  {
    id: 'CWE-204',
    name: 'Observable Response Discrepancy',
    patterns: ['username_enumeration', 'authentication_error_disclosure', 'different error messages'],
    remediation:
      'Normalize authentication and validation error messages so success and failure cases do not disclose whether usernames, emails, or resources exist.',
    risk: { likelihood: 'likely', impact: 'low', business: 'User enumeration aiding credential attacks', compliance: 'OWASP A07:2021' },
  },
  {
    id: 'CWE-650',
    name: 'Trusting HTTP Permission Methods on the Server Side',
    patterns: ['http_verb_tampering', 'method override', 'x-http-method-override'],
    remediation:
      'Reject method-override headers unless explicitly required, and enforce authorization and routing based on the effective HTTP method server-side.',
    risk: { likelihood: 'unlikely', impact: 'high', business: 'Authorization bypass via HTTP method manipulation', compliance: 'OWASP A01:2021' },
  },
];

const collapseText = (...parts) =>
  parts
    .flat()
    .filter(Boolean)
    .map((part) => (Array.isArray(part) ? part.join(' ') : String(part)))
    .join(' ')
    .toLowerCase();

const hasValue = (value) =>
  value !== null &&
  value !== undefined &&
  !(typeof value === 'string' && value.trim() === '') &&
  !(Array.isArray(value) && value.length === 0);

const inferCweMappings = (finding) => {
  const text = collapseText(
    finding.type,
    finding.missing_defense,
    finding.attack_path,
    finding.exploitation_hypothesis,
    finding.notes,
    finding.report_section,
    finding.source_endpoint,
    finding.parameter
  );

  return CWE_RULES.filter((rule) =>
    rule.patterns.some((pattern) => text.includes(pattern.toLowerCase()))
  );
};

const buildRemediation = (finding, mappings) => {
  if (hasValue(finding.remediation)) {
    return String(finding.remediation).trim();
  }

  const snippets = [...new Set(mappings.map((mapping) => mapping.remediation).filter(Boolean))];
  if (snippets.length > 0) {
    return snippets.slice(0, 3).join(' ');
  }

  return 'Review the affected endpoint and code path, add missing authorization and validation checks, remove unsafe debug or disclosure behavior, and verify the fix with a targeted regression test.';
};

const normalizeMultiValueField = (value) => {
  if (!hasValue(value)) return '';
  if (Array.isArray(value)) {
    return value.map((item) => String(item).trim()).filter(Boolean).join('; ');
  }
  return String(value);
};

// ── CRQ enrichment helpers ──────────────────────────────────────────────────

const LIKELIHOOD_MAP = { almost_certain: 5, likely: 4, possible: 3, unlikely: 2, rare: 1 };
const IMPACT_MAP = { critical: 5, high: 4, moderate: 3, low: 2, informational: 1 };
const SEVERITY_TO_IMPACT = { critical: 'critical', high: 'high', medium: 'moderate', low: 'low', info: 'informational' };
const STATUS_LIKELIHOOD_BOOST = { exploited: 'almost_certain', blocked: 'unlikely', potential: 'possible', false_positive: 'rare' };

const inferCrqFields = (finding, mappings) => {
  const severity = (finding.severity || '').toLowerCase();
  const status = (finding.status || '').toLowerCase();

  // Likelihood: agent value > status-based > CWE rule default > severity fallback
  let likelihood = hasValue(finding.likelihood) ? finding.likelihood : '';
  if (!likelihood && STATUS_LIKELIHOOD_BOOST[status]) {
    likelihood = STATUS_LIKELIHOOD_BOOST[status];
  }
  if (!likelihood && mappings.length > 0 && mappings[0].risk) {
    likelihood = mappings[0].risk.likelihood;
  }
  if (!likelihood) {
    likelihood = severity === 'critical' ? 'likely' : severity === 'high' ? 'possible' : severity === 'medium' ? 'possible' : 'unlikely';
  }

  // Impact: agent value > CWE rule default > severity mapping
  let impact_level = hasValue(finding.impact_level) ? finding.impact_level : '';
  if (!impact_level && mappings.length > 0 && mappings[0].risk) {
    impact_level = mappings[0].risk.impact;
  }
  if (!impact_level) {
    impact_level = SEVERITY_TO_IMPACT[severity] || 'moderate';
  }

  // Risk score: agent value > computed from likelihood × impact
  let risk_score = hasValue(finding.risk_score) ? Number(finding.risk_score) : 0;
  if (!risk_score) {
    const l = LIKELIHOOD_MAP[likelihood] || 3;
    const i = IMPACT_MAP[impact_level] || 3;
    risk_score = Math.round((l * i) / 2.5);
    risk_score = Math.max(1, Math.min(10, risk_score));
  }

  // Business impact: agent value > CWE rule default
  let business_impact = hasValue(finding.business_impact) ? String(finding.business_impact) : '';
  if (!business_impact && mappings.length > 0 && mappings[0].risk) {
    business_impact = mappings[0].risk.business;
  }

  // Compliance: agent value > CWE rule default
  let compliance_impact = hasValue(finding.compliance_impact) ? String(finding.compliance_impact) : '';
  if (!compliance_impact && mappings.length > 0 && mappings[0].risk) {
    compliance_impact = mappings[0].risk.compliance;
  }

  // Data at risk: keep agent value
  const data_at_risk = hasValue(finding.data_at_risk) ? String(finding.data_at_risk) : '';

  // Estimated annual occurrence: keep agent value or infer
  let estimated_annual_occurrence = hasValue(finding.estimated_annual_occurrence) ? String(finding.estimated_annual_occurrence) : '';
  if (!estimated_annual_occurrence) {
    const l = LIKELIHOOD_MAP[likelihood] || 3;
    estimated_annual_occurrence = l >= 5 ? '50-100' : l >= 4 ? '20-50' : l >= 3 ? '5-20' : l >= 2 ? '1-5' : '<1';
  }

  return { likelihood, impact_level, risk_score, estimated_annual_occurrence, business_impact, data_at_risk, compliance_impact };
};

const enrichFindings = (findings) => findings.map((finding) => {
  const { remediation: _ignoredRemediation, cwe_ids: _ignoredCweIds, ...rest } = finding;
  const mappings = inferCweMappings(finding);
  const existingIds = hasValue(finding.cwe_ids)
    ? String(finding.cwe_ids).split(/[;,]/).map((part) => part.trim()).filter(Boolean)
    : [];
  const existingNames = hasValue(finding.cwe_names)
    ? String(finding.cwe_names).split(/[;,]/).map((part) => part.trim()).filter(Boolean)
    : [];

  const cweIds = existingIds.length > 0
    ? existingIds
    : mappings.map((mapping) => mapping.id);
  const cweNames = existingNames.length > 0
    ? existingNames
    : mappings.map((mapping) => mapping.name);
  const remediation = buildRemediation(finding, mappings);
  const compactCwe = [...new Set(
    cweIds.map((id, index) => {
      const name = cweNames[index] || '';
      return name ? `${id}: ${name}` : id;
    })
  )].join('; ');

  // CRQ enrichment
  const crq = inferCrqFields(finding, mappings);

  // Attack chain fields: pass through agent values
  const attack_chain_id = hasValue(finding.attack_chain_id) ? String(finding.attack_chain_id) : '';
  const attack_chain_role = hasValue(finding.attack_chain_role) ? String(finding.attack_chain_role) : 'standalone';
  const attack_chain_description = hasValue(finding.attack_chain_description) ? String(finding.attack_chain_description) : '';
  const chained_with = hasValue(finding.chained_with) ? normalizeMultiValueField(finding.chained_with) : '';

  return {
    ...rest,
    source_file: normalizeMultiValueField(finding.source_file),
    original_ids: normalizeMultiValueField(finding.original_ids),
    cwe: compactCwe,
    cwe_names: [...new Set(cweNames)].join('; '),
    remediation_suggestions: hasValue(finding.remediation_suggestions)
      ? String(finding.remediation_suggestions).trim()
      : remediation,
    // CRQ fields
    likelihood: crq.likelihood,
    impact_level: crq.impact_level,
    risk_score: crq.risk_score,
    estimated_annual_occurrence: crq.estimated_annual_occurrence,
    business_impact: crq.business_impact,
    data_at_risk: crq.data_at_risk,
    compliance_impact: crq.compliance_impact,
    // Attack chain fields
    attack_chain_id,
    attack_chain_role,
    attack_chain_description,
    chained_with,
  };
});

// ── Display + de-duplication helpers ────────────────────────────────────────

const titleCase = (s) =>
  hasValue(s) ? String(s).charAt(0).toUpperCase() + String(s).slice(1) : '';

// snake_case / lower → "Snake Case" for human-facing likelihood/impact labels
const humanize = (s) =>
  hasValue(s) ? String(s).replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase()) : '';

// Single source of truth for a finding's endpoint (collapses the two overlapping fields)
const getEndpoint = (f) => f.source_endpoint || f.affected_endpoint || '';

const SEVERITY_BADGE = {
  critical: '🔴 Critical', high: '🟠 High', medium: '🟡 Medium',
  low: '🔵 Low', info: '⚪ Info', informational: '⚪ Info',
};
const severityBadge = (s) =>
  SEVERITY_BADGE[(s || '').toLowerCase()] || (hasValue(s) ? titleCase(s) : '-');

// Merge two multi-value fields (arrays or ";"/","-joined strings) into a de-duplicated string
const mergeMulti = (a, b) => {
  const parts = [];
  for (const v of [a, b]) {
    if (!hasValue(v)) continue;
    const arr = Array.isArray(v) ? v : String(v).split(/[;,]/);
    for (const p of arr) {
      const t = String(p).trim();
      if (t) parts.push(t);
    }
  }
  return [...new Set(parts)].join('; ');
};

// Rough measure of how much evidence a finding carries, to pick the richer of two duplicates
const completenessScore = (f) => {
  const fields = [
    'evidence_snippet', 'exploit_result', 'attack_path', 'exploitation_hypothesis',
    'poc', 'remediation_suggestions', 'remediation', 'developer_verification_steps',
    'business_impact', 'code_location', 'cwe',
  ];
  let score = 0;
  for (const key of fields) {
    const v = f[key];
    if (hasValue(v)) score += String(Array.isArray(v) ? v.join(' ') : v).length;
  }
  return score;
};

// Dedup key: prefer the vulnerability ID; fall back to type + endpoint
const dedupeKey = (f) => {
  const id = (f.id || '').trim().toUpperCase();
  if (id) return `id:${id}`;
  const type = (f.type || '').trim().toLowerCase();
  const ep = getEndpoint(f).trim().toLowerCase();
  return `te:${type}|${ep}`;
};

// Collapse duplicate findings, keeping the most complete and merging provenance fields
const dedupeFindings = (findings) => {
  const byKey = new Map();
  for (const f of findings) {
    const key = dedupeKey(f);
    const existing = byKey.get(key);
    if (!existing) {
      byKey.set(key, f);
      continue;
    }
    const [keep, drop] =
      completenessScore(f) >= completenessScore(existing) ? [f, existing] : [existing, f];
    keep.original_ids = mergeMulti(keep.original_ids || keep.id, drop.original_ids || drop.id);
    keep.source_file = mergeMulti(keep.source_file, drop.source_file);
    keep.chained_with = mergeMulti(keep.chained_with, drop.chained_with);
    byKey.set(key, keep);
  }
  return [...byKey.values()];
};

// ── Report generators ──────────────────────────────────────────────────────

const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4, informational: 4 };
const sortBySeverity = (a, b) => (severityOrder[(a.severity || '').toLowerCase()] ?? 5) - (severityOrder[(b.severity || '').toLowerCase()] ?? 5);

const generateDeveloperReport = (findings) => {
  const sorted = [...findings].sort(sortBySeverity);
  const date = new Date().toISOString().split('T')[0];
  const lines = [];

  lines.push('# Developer Security Report');
  lines.push('');
  lines.push(`**Generated:** ${date}`);
  lines.push(`**Total Findings:** ${findings.length}`);
  lines.push('');

  // How to use
  lines.push('> **How to use this report:** Findings are ordered by severity. Each entry under *Detailed Findings* names the vulnerable location, shows the supporting evidence, gives a concrete fix, and lists steps to verify the fix. Work the *Remediation Checklist* at the bottom in order — exploited issues first.');
  lines.push('');

  // Severity breakdown
  const bySev = {};
  for (const f of findings) {
    const s = (f.severity || 'unknown').toLowerCase();
    bySev[s] = (bySev[s] || 0) + 1;
  }
  const exploitedTotal = findings.filter((f) => (f.status || '').toLowerCase() === 'exploited').length;
  lines.push(`**Severity:** 🔴 ${bySev.critical || 0} Critical · 🟠 ${bySev.high || 0} High · 🟡 ${bySev.medium || 0} Medium · 🔵 ${bySev.low || 0} Low · ⚪ ${(bySev.info || 0) + (bySev.informational || 0)} Info`);
  lines.push('');
  lines.push(`**Confirmed exploitable:** ${exploitedTotal} of ${findings.length}`);
  lines.push('');

  // Summary table
  lines.push('## Vulnerability Summary');
  lines.push('');
  lines.push('| ID | Title | Severity | Endpoint | Status | CWE |');
  lines.push('|----|-------|----------|----------|--------|-----|');
  for (const f of sorted) {
    const endpoint = getEndpoint(f).slice(0, 60);
    lines.push(`| ${f.id || '-'} | ${f.type || '-'} | ${severityBadge(f.severity)} | \`${endpoint || '-'}\` | ${titleCase(f.status) || '-'} | ${(f.cwe || '').split(';')[0] || '-'} |`);
  }
  lines.push('');

  // Attack chains
  const chains = new Map();
  for (const f of sorted) {
    if (f.attack_chain_id) {
      if (!chains.has(f.attack_chain_id)) chains.set(f.attack_chain_id, []);
      chains.get(f.attack_chain_id).push(f);
    }
  }

  if (chains.size > 0) {
    lines.push('## Attack Chains');
    lines.push('');
    for (const [chainId, chainFindings] of chains) {
      const entryPoints = chainFindings.filter(f => f.attack_chain_role === 'entry_point');
      const pivots = chainFindings.filter(f => f.attack_chain_role === 'pivot');
      const impacts = chainFindings.filter(f => f.attack_chain_role === 'impact');

      lines.push(`### ${chainId}`);
      lines.push('');

      // Description from first finding that has it
      const desc = chainFindings.find(f => f.attack_chain_description)?.attack_chain_description;
      if (desc) {
        lines.push(`> ${desc}`);
        lines.push('');
      }

      // Flow diagram
      lines.push('**Attack Flow:**');
      lines.push('```');
      const steps = [];
      for (const f of entryPoints) steps.push(`[ENTRY] ${f.id}: ${f.type} @ ${f.source_endpoint || f.affected_endpoint || '?'}`);
      for (const f of pivots) steps.push(`  --> [PIVOT] ${f.id}: ${f.type} @ ${f.source_endpoint || f.affected_endpoint || '?'}`);
      for (const f of impacts) steps.push(`    --> [IMPACT] ${f.id}: ${f.type} @ ${f.source_endpoint || f.affected_endpoint || '?'}`);
      if (steps.length === 0) {
        for (const f of chainFindings) steps.push(`[${(f.attack_chain_role || 'step').toUpperCase()}] ${f.id}: ${f.type}`);
      }
      lines.push(steps.join('\n'));
      lines.push('```');
      lines.push('');
      lines.push(`**Findings in chain:** ${chainFindings.map(f => f.id).join(', ')}`);
      lines.push('');
    }
  }

  // Detailed findings
  lines.push('## Detailed Findings');
  lines.push('');

  for (const f of sorted) {
    lines.push(`### ${f.id || 'Unknown'}: ${f.type || 'Unknown Type'} — ${severityBadge(f.severity)}`);
    lines.push('');
    lines.push(`- **Severity:** ${f.severity || '-'}`);
    lines.push(`- **Status:** ${f.status || '-'}`);
    lines.push(`- **Risk Score:** ${f.risk_score || '-'}/10`);
    if (f.source_endpoint || f.affected_endpoint) {
      lines.push(`- **Endpoint:** \`${f.source_endpoint || f.affected_endpoint}\``);
    }
    if (f.parameter) lines.push(`- **Parameter:** \`${f.parameter}\``);
    if (f.code_location) lines.push(`- **Code Location:** \`${f.code_location}\``);
    if (f.cwe) lines.push(`- **CWE:** ${f.cwe}`);
    if (f.missing_defense) lines.push(`- **Missing Defense:** ${f.missing_defense}`);
    lines.push('');

    if (f.attack_path || f.exploitation_hypothesis) {
      lines.push('**Root Cause & Attack Path:**');
      lines.push('');
      if (f.attack_path) lines.push(f.attack_path);
      if (f.exploitation_hypothesis && f.exploitation_hypothesis !== f.attack_path) lines.push(f.exploitation_hypothesis);
      lines.push('');
    }

    if (f.evidence_snippet) {
      lines.push('**Evidence:**');
      lines.push('```');
      lines.push(f.evidence_snippet);
      lines.push('```');
      lines.push('');
    }

    if (f.exploit_result) {
      lines.push('**Exploit Result:**');
      lines.push('');
      lines.push(f.exploit_result);
      lines.push('');
    }

    // Remediation
    lines.push('**Remediation:**');
    lines.push('');
    lines.push(f.remediation_suggestions || 'No specific remediation available.');
    lines.push('');

    // Verification steps
    if (f.developer_verification_steps) {
      lines.push('**Verification Steps:**');
      lines.push('');
      const steps = String(f.developer_verification_steps).split(' | ');
      for (const step of steps) {
        lines.push(`${step.trim()}`);
      }
      lines.push('');
    }

    lines.push('---');
    lines.push('');
  }

  // Remediation checklist
  lines.push('## Remediation Checklist');
  lines.push('');
  const exploited = sorted.filter(f => (f.status || '').toLowerCase() === 'exploited');
  const blocked = sorted.filter(f => (f.status || '').toLowerCase() === 'blocked');
  const potential = sorted.filter(f => !['exploited', 'blocked', 'false_positive'].includes((f.status || '').toLowerCase()));

  if (exploited.length > 0) {
    lines.push('### Immediate (Exploited Vulnerabilities)');
    lines.push('');
    for (const f of exploited) {
      lines.push(`- [ ] **${f.id}** (${f.severity}) — ${f.type} at \`${f.source_endpoint || f.affected_endpoint || '?'}\``);
      if (f.code_location) lines.push(`  - Fix in: \`${f.code_location}\``);
    }
    lines.push('');
  }

  if (blocked.length > 0) {
    lines.push('### Short-term (Blocked by Controls — Strengthen Defenses)');
    lines.push('');
    for (const f of blocked) {
      lines.push(`- [ ] **${f.id}** (${f.severity}) — ${f.type} at \`${f.source_endpoint || f.affected_endpoint || '?'}\``);
    }
    lines.push('');
  }

  if (potential.length > 0) {
    lines.push('### Medium-term (Potential / Unverified)');
    lines.push('');
    for (const f of potential) {
      lines.push(`- [ ] **${f.id}** (${f.severity}) — ${f.type} at \`${f.source_endpoint || f.affected_endpoint || '?'}\``);
    }
    lines.push('');
  }

  return lines.join('\n');
};

const generateExecutiveReport = (findings) => {
  const sorted = [...findings].sort(sortBySeverity);
  const date = new Date().toISOString().split('T')[0];
  const lines = [];

  lines.push('# Executive Security Assessment Report');
  lines.push('');
  lines.push(`**Generated:** ${date}`);
  lines.push('');

  // Bottom line up front — plain language for non-security readers
  const critHighCount = findings.filter((f) => ['critical', 'high'].includes((f.severity || '').toLowerCase())).length;
  const exploitedUp = findings.filter((f) => (f.status || '').toLowerCase() === 'exploited').length;
  const topRisk = [...findings].sort((a, b) => (b.risk_score || 0) - (a.risk_score || 0))[0];
  lines.push('## Bottom Line');
  lines.push('');
  lines.push(`This assessment found **${findings.length} findings**, of which **${critHighCount} are Critical or High severity** and **${exploitedUp} were confirmed exploitable** during testing.`);
  if (topRisk) {
    const biz = topRisk.business_impact ? ` — ${String(topRisk.business_impact).replace(/\s+/g, ' ').trim().replace(/\.$/, '')}` : '';
    lines.push('');
    lines.push(`The single highest-risk issue is **${topRisk.id || topRisk.type}** (${titleCase(topRisk.severity)}, risk ${topRisk.risk_score || '-'}/10)${biz}.`);
  }
  lines.push('');
  lines.push('**Recommended focus:** remediate the confirmed-exploitable findings first, then the remaining Critical/High issues following the *Strategic Remediation Roadmap* at the end of this report.');
  lines.push('');

  // Executive summary
  lines.push('## Executive Summary');
  lines.push('');

  const bySev = {};
  const byStatus = {};
  for (const f of findings) {
    const s = (f.severity || 'unknown').toLowerCase();
    const st = (f.status || 'unknown').toLowerCase();
    bySev[s] = (bySev[s] || 0) + 1;
    byStatus[st] = (byStatus[st] || 0) + 1;
  }

  lines.push(`This assessment identified **${findings.length} security findings** across the application:`);
  lines.push('');
  lines.push('| Severity | Count |');
  lines.push('|----------|-------|');
  for (const sev of ['critical', 'high', 'medium', 'low', 'info']) {
    const count = bySev[sev] || (sev === 'info' ? (bySev.informational || 0) : 0);
    if (count > 0) lines.push(`| ${sev.charAt(0).toUpperCase() + sev.slice(1)} | ${count} |`);
  }
  lines.push('');

  lines.push('| Status | Count |');
  lines.push('|--------|-------|');
  for (const [st, count] of Object.entries(byStatus).sort((a, b) => b[1] - a[1])) {
    lines.push(`| ${st.charAt(0).toUpperCase() + st.slice(1)} | ${count} |`);
  }
  lines.push('');

  // CRQ Dashboard
  lines.push('## Cyber Risk Quantification (CRQ)');
  lines.push('');

  // Risk matrix
  lines.push('### Risk Matrix');
  lines.push('');
  lines.push('Findings mapped by likelihood of exploitation vs. business impact:');
  lines.push('');

  const likelihoodLabels = ['Almost Certain', 'Likely', 'Possible', 'Unlikely', 'Rare'];
  const likelihoodKeys = ['almost_certain', 'likely', 'possible', 'unlikely', 'rare'];
  const impactLabels = ['Critical', 'High', 'Moderate', 'Low', 'Info'];
  const impactKeys = ['critical', 'high', 'moderate', 'low', 'informational'];

  // Build matrix counts
  const matrix = {};
  for (const lk of likelihoodKeys) {
    matrix[lk] = {};
    for (const ik of impactKeys) {
      matrix[lk][ik] = 0;
    }
  }
  for (const f of findings) {
    const lk = (f.likelihood || 'possible').toLowerCase();
    const ik = (f.impact_level || 'moderate').toLowerCase();
    if (matrix[lk] && matrix[lk][ik] !== undefined) matrix[lk][ik]++;
  }

  lines.push('| Likelihood \\ Impact | Critical | High | Moderate | Low | Info |');
  lines.push('|---------------------|----------|------|----------|-----|------|');
  for (let li = 0; li < likelihoodKeys.length; li++) {
    const row = likelihoodLabels[li];
    const cells = impactKeys.map(ik => {
      const count = matrix[likelihoodKeys[li]][ik];
      return count > 0 ? `**${count}**` : '-';
    });
    lines.push(`| ${row} | ${cells.join(' | ')} |`);
  }
  lines.push('');

  lines.push('*Cell values are finding counts. The top-left region (high likelihood × high impact) is the most urgent to remediate.*');
  lines.push('');

  // Top risks by risk score
  const topRisks = [...sorted].sort((a, b) => (b.risk_score || 0) - (a.risk_score || 0)).slice(0, 10);
  lines.push('### Top Risks by Score');
  lines.push('');
  lines.push('| Rank | ID | Type | Risk Score | Likelihood | Impact | Business Impact |');
  lines.push('|------|----|------|------------|------------|--------|-----------------|');
  topRisks.forEach((f, i) => {
    const biz = (f.business_impact || '-').slice(0, 80);
    lines.push(`| ${i + 1} | ${f.id || '-'} | ${f.type || '-'} | **${f.risk_score || '-'}**/10 | ${f.likelihood || '-'} | ${f.impact_level || '-'} | ${biz} |`);
  });
  lines.push('');

  // Compliance exposure
  const complianceMap = {};
  for (const f of findings) {
    if (!f.compliance_impact) continue;
    const refs = String(f.compliance_impact).split(/[;,]/).map(r => r.trim()).filter(Boolean);
    for (const ref of refs) {
      // Extract framework name
      const framework = ref.split(/\s/)[0].replace(/:$/, '');
      if (!complianceMap[framework]) complianceMap[framework] = { refs: new Set(), count: 0, findings: [] };
      complianceMap[framework].refs.add(ref);
      complianceMap[framework].count++;
      complianceMap[framework].findings.push(f.id);
    }
  }

  if (Object.keys(complianceMap).length > 0) {
    lines.push('### Compliance Exposure');
    lines.push('');
    lines.push('| Framework | Affected Findings | Key Requirements |');
    lines.push('|-----------|-------------------|------------------|');
    for (const [fw, data] of Object.entries(complianceMap).sort((a, b) => b[1].count - a[1].count)) {
      const refs = [...data.refs].slice(0, 3).join('; ');
      lines.push(`| ${fw} | ${data.count} | ${refs} |`);
    }
    lines.push('');
  }

  // Data at risk summary
  const dataRisks = new Map();
  for (const f of findings) {
    if (!f.data_at_risk) continue;
    const items = String(f.data_at_risk).split(/[;,]/).map(r => r.trim()).filter(Boolean);
    for (const item of items) {
      if (!dataRisks.has(item)) dataRisks.set(item, []);
      dataRisks.get(item).push(f.id);
    }
  }

  if (dataRisks.size > 0) {
    lines.push('### Data at Risk');
    lines.push('');
    lines.push('| Data Category | Exposed By |');
    lines.push('|---------------|------------|');
    for (const [data, ids] of [...dataRisks.entries()].sort((a, b) => b[1].length - a[1].length)) {
      lines.push(`| ${data} | ${ids.slice(0, 5).join(', ')}${ids.length > 5 ? ` (+${ids.length - 5} more)` : ''} |`);
    }
    lines.push('');
  }

  // Attack chains (business-focused narrative)
  const chains = new Map();
  for (const f of sorted) {
    if (f.attack_chain_id) {
      if (!chains.has(f.attack_chain_id)) chains.set(f.attack_chain_id, []);
      chains.get(f.attack_chain_id).push(f);
    }
  }

  if (chains.size > 0) {
    lines.push('## Attack Chain Analysis');
    lines.push('');
    lines.push('The following multi-step attack paths were identified, showing how individual vulnerabilities combine for greater business impact:');
    lines.push('');

    for (const [chainId, chainFindings] of chains) {
      const maxScore = Math.max(...chainFindings.map(f => f.risk_score || 0));
      const desc = chainFindings.find(f => f.attack_chain_description)?.attack_chain_description;

      lines.push(`### ${chainId} (Combined Risk: ${maxScore}/10)`);
      lines.push('');
      if (desc) {
        lines.push(desc);
        lines.push('');
      }
      lines.push(`**Findings involved:** ${chainFindings.map(f => `${f.id} (${f.severity})`).join(' -> ')}`);
      lines.push('');

      // Business impact of the chain
      const chainImpacts = chainFindings.map(f => f.business_impact).filter(Boolean);
      if (chainImpacts.length > 0) {
        lines.push(`**Business Impact:** ${chainImpacts[chainImpacts.length - 1]}`);
        lines.push('');
      }
    }
  }

  // Strategic remediation roadmap
  lines.push('## Strategic Remediation Roadmap');
  lines.push('');

  // Group by remediation theme
  const themes = {};
  for (const f of sorted) {
    const type = (f.type || 'Other').toLowerCase();
    let theme;
    if (type.includes('injection') || type.includes('sqli') || type.includes('nosql') || type.includes('xxe') || type.includes('yaml')) {
      theme = 'Input Validation & Injection Prevention';
    } else if (type.includes('auth') || type.includes('credential') || type.includes('session') || type.includes('token')) {
      theme = 'Authentication & Session Management';
    } else if (type.includes('authz') || type.includes('authorization') || type.includes('idor') || type.includes('bola') || type.includes('privilege')) {
      theme = 'Authorization & Access Control';
    } else if (type.includes('xss') || type.includes('csrf') || type.includes('clickjack') || type.includes('client')) {
      theme = 'Client-Side Security';
    } else if (type.includes('ssrf') || type.includes('network') || type.includes('tls') || type.includes('header')) {
      theme = 'Network & Transport Security';
    } else if (type.includes('config') || type.includes('debug') || type.includes('error') || type.includes('disclosure') || type.includes('info')) {
      theme = 'Security Configuration & Hardening';
    } else if (type.includes('crypto') || type.includes('hash') || type.includes('password') || type.includes('secret')) {
      theme = 'Cryptography & Secrets Management';
    } else {
      theme = 'Other Security Improvements';
    }
    if (!themes[theme]) themes[theme] = [];
    themes[theme].push(f);
  }

  // Sort themes by max severity
  const themeEntries = Object.entries(themes).sort((a, b) => {
    const aMax = Math.min(...a[1].map(f => severityOrder[(f.severity || '').toLowerCase()] ?? 5));
    const bMax = Math.min(...b[1].map(f => severityOrder[(f.severity || '').toLowerCase()] ?? 5));
    return aMax - bMax;
  });

  let priority = 1;
  for (const [theme, themeFindings] of themeEntries) {
    const critHigh = themeFindings.filter(f => ['critical', 'high'].includes((f.severity || '').toLowerCase())).length;
    const maxRisk = Math.max(...themeFindings.map(f => f.risk_score || 0));
    lines.push(`### Priority ${priority}: ${theme}`);
    lines.push('');
    lines.push(`- **Findings:** ${themeFindings.length} (${critHigh} critical/high)`);
    lines.push(`- **Max Risk Score:** ${maxRisk}/10`);
    lines.push(`- **Key findings:** ${themeFindings.slice(0, 5).map(f => f.id).join(', ')}`);

    // Collect unique remediations
    const remediations = [...new Set(themeFindings.map(f => f.remediation_suggestions).filter(Boolean))];
    if (remediations.length > 0) {
      lines.push(`- **Action:** ${remediations[0].slice(0, 200)}`);
    }
    lines.push('');
    priority++;
  }

  // Risk summary footer
  lines.push('## Risk Summary');
  lines.push('');
  const exploitedCount = findings.filter(f => (f.status || '').toLowerCase() === 'exploited').length;
  const avgRisk = findings.length > 0 ? (findings.reduce((sum, f) => sum + (f.risk_score || 0), 0) / findings.length).toFixed(1) : '0';
  lines.push(`- **Total findings:** ${findings.length}`);
  lines.push(`- **Exploited (confirmed):** ${exploitedCount}`);
  lines.push(`- **Average risk score:** ${avgRisk}/10`);
  lines.push(`- **Attack chains identified:** ${chains.size}`);
  if (Object.keys(complianceMap).length > 0) {
    lines.push(`- **Compliance frameworks affected:** ${Object.keys(complianceMap).join(', ')}`);
  }
  lines.push('');

  return lines.join('\n');
};

// Curated, human-readable column set. Overlapping/redundant fields are collapsed:
//   - source_endpoint + affected_endpoint  -> single "Endpoint"
//   - cwe already embeds names             -> "cwe_names" dropped
//   - attack_path falls back to exploitation_hypothesis
// Internal metadata (source_file, report_section, notes, original_ids) is intentionally omitted.
const CSV_COLUMNS = [
  { header: 'ID', get: (f) => f.id },
  { header: 'Title', get: (f) => f.type },
  { header: 'Severity', get: (f) => titleCase(f.severity) },
  { header: 'Status', get: (f) => titleCase(f.status) },
  { header: 'Confidence', get: (f) => titleCase(f.confidence) },
  { header: 'Risk Score (0-10)', get: (f) => f.risk_score },
  { header: 'Likelihood', get: (f) => humanize(f.likelihood) },
  { header: 'Impact', get: (f) => humanize(f.impact_level) },
  { header: 'CWE', get: (f) => f.cwe },
  { header: 'Endpoint', get: (f) => getEndpoint(f) },
  { header: 'Parameter', get: (f) => f.parameter },
  { header: 'Code Location', get: (f) => f.code_location },
  { header: 'Attack Path', get: (f) => f.attack_path || f.exploitation_hypothesis },
  { header: 'Evidence', get: (f) => f.evidence_snippet },
  { header: 'Business Impact', get: (f) => f.business_impact },
  { header: 'Data at Risk', get: (f) => f.data_at_risk },
  { header: 'Compliance', get: (f) => f.compliance_impact },
  { header: 'Remediation', get: (f) => f.remediation_suggestions },
  { header: 'Verification Steps', get: (f) => f.developer_verification_steps },
  { header: 'Attack Chain', get: (f) => f.attack_chain_id },
  { header: 'Chain Role', get: (f) => (f.attack_chain_role === 'standalone' ? '' : f.attack_chain_role) },
];

const findingsToCSV = (findings) => {
  const sorted = [...findings].sort(sortBySeverity);

  logInfo(`CSV columns (${CSV_COLUMNS.length}): ${DIM}${CSV_COLUMNS.map((c) => c.header).join(', ')}${RESET}`);
  const withSteps = findings.filter((f) => hasValue(f.developer_verification_steps)).length;
  logInfo(`Findings with verification steps: ${withSteps}/${findings.length}`);

  const lines = [CSV_COLUMNS.map((c) => csvEscape(c.header)).join(',')];
  for (const f of sorted) {
    lines.push(CSV_COLUMNS.map((c) => csvEscape(c.get(f) ?? '')).join(','));
  }

  return lines.join('\n');
};

// ── Main ────────────────────────────────────────────────────────────────────

if (reuseJson && fs.existsSync(jsonOutputPath)) {
  logInfo(`Skipping agent run and reusing existing JSON: ${jsonOutputPath}`);
  console.log('');
} else {
  logInfo('Starting agentic analysis...');
  console.log('');
  await runAgent();
}

const rawFindings = loadFindings();

if (!rawFindings || rawFindings.length === 0) {
  logError('No findings extracted.');
  logError('Check these locations for agent output:');
  logError(`  - ${jsonOutputPath}`);
  logError(`  - ${absDeliverables}/*.json`);
  process.exit(1);
}

// Collapse duplicate findings (same ID, or same type+endpoint) before rendering
const findings = dedupeFindings(rawFindings);
const removedDupes = rawFindings.length - findings.length;
if (removedDupes > 0) {
  logInfo(`De-duplicated ${removedDupes} finding(s): ${rawFindings.length} -> ${findings.length}`);
}

const enrichedFindings = enrichFindings(findings);
const csv = findingsToCSV(enrichedFindings);
fs.writeFileSync(absOutput, csv);

// Generate developer and executive reports
const devReportPath = path.join(absDeliverables, 'developer_security_report.md');
const execReportPath = path.join(absDeliverables, 'executive_security_report.md');

const devReport = generateDeveloperReport(enrichedFindings);
fs.writeFileSync(devReportPath, devReport);
logSuccess(`Developer report written: ${devReportPath}`);

const execReport = generateExecutiveReport(enrichedFindings);
fs.writeFileSync(execReportPath, execReport);
logSuccess(`Executive report written: ${execReportPath}`);

// Summary stats
const chainCount = new Set(enrichedFindings.map(f => f.attack_chain_id).filter(Boolean)).size;
const exploitedCount = enrichedFindings.filter(f => (f.status || '').toLowerCase() === 'exploited').length;

console.log('');
console.log(`${BOLD}═══════════════════════════════════════════════════════════${RESET}`);
logSuccess(`${BOLD}CSV written       : ${absOutput} (${findings.length} findings)${RESET}`);
logSuccess(`${BOLD}Developer report  : ${devReportPath}${RESET}`);
logSuccess(`${BOLD}Executive report  : ${execReportPath}${RESET}`);
logInfo(`Exploited: ${exploitedCount} | Attack chains: ${chainCount} | CRQ scores: ${enrichedFindings.filter(f => f.risk_score).length}/${findings.length}`);
console.log(`${BOLD}═══════════════════════════════════════════════════════════${RESET}`);
console.log('');
