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

   IMPORTANT — ADDITIONAL REQUIRED FIELD:
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
- After writing the JSON output file, output a brief summary of how many findings you found.
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

REQUIRED: Every finding MUST include a "developer_verification_steps" field with numbered, actionable steps a developer can follow to reproduce and verify the vulnerability. Base these on the actual evidence, endpoints, parameters, and exploit details found in the deliverables.

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
  },
  {
    id: 'CWE-79',
    name: 'Improper Neutralization of Input During Web Page Generation',
    patterns: ['xss', 'cross-site scripting', 'cross site scripting', 'script injection'],
    remediation:
      'Apply context-aware output encoding, validate and sanitize untrusted input, and enforce a restrictive Content-Security-Policy to reduce script injection impact.',
  },
  {
    id: 'CWE-918',
    name: 'Server-Side Request Forgery (SSRF)',
    patterns: ['ssrf', 'server-side request forgery', 'server side request forgery'],
    remediation:
      'Strictly validate outbound destinations against an allowlist, block internal address ranges and metadata endpoints, and route outbound requests through a hardened proxy.',
  },
  {
    id: 'CWE-639',
    name: 'Authorization Bypass Through User-Controlled Key',
    patterns: ['bola', 'idor', 'book_title', 'username (path parameter)', 'broken object level authorization'],
    remediation:
      'Authorize access using the authenticated user context on every object lookup. Never trust path, query, or body identifiers alone to decide ownership.',
  },
  {
    id: 'CWE-862',
    name: 'Missing Authorization',
    patterns: ['missing authorization', 'no ownership verification', 'authorization not checked', 'admin-only', 'privilege escalation'],
    remediation:
      'Add explicit authorization checks server-side for each privileged action and deny requests that are not permitted for the authenticated principal.',
  },
  {
    id: 'CWE-287',
    name: 'Improper Authentication',
    patterns: ['authentication_bypass', 'auth bypass', 'improper authentication', 'forged token'],
    remediation:
      'Require robust authentication for protected operations, validate tokens securely, and reject forged or malformed credentials before business logic executes.',
  },
  {
    id: 'CWE-321',
    name: 'Use of Hard-coded Cryptographic Key',
    patterns: ['hardcoded secret', 'hardcoded secret_key', 'hardcoded cryptographic', 'jwt secret key hardcoded', 'secret key hardcoded'],
    remediation:
      'Remove hard-coded cryptographic material from source control. Load high-entropy secrets from a secure secret manager or environment and support rotation.',
  },
  {
    id: 'CWE-798',
    name: 'Use of Hard-coded Credentials',
    patterns: ['default_credentials', 'default credentials', 'hardcoded credentials', 'admin:pass1'],
    remediation:
      'Eliminate default or embedded credentials. Generate unique bootstrap credentials per environment and require immediate rotation on first use.',
  },
  {
    id: 'CWE-256',
    name: 'Plaintext Storage of a Password',
    patterns: ['plaintext_password_storage', 'plaintext passwords', 'password hashing', 'stored as plaintext'],
    remediation:
      'Hash passwords with a modern password hashing algorithm such as Argon2id or bcrypt, add per-password salt, and avoid storing recoverable plaintext passwords.',
  },
  {
    id: 'CWE-306',
    name: 'Missing Authentication for Critical Function',
    patterns: ['unauthenticated_destructive_operation', 'no authentication required', 'without any authentication', 'createdb'],
    remediation:
      'Require strong authentication before invoking administrative or destructive actions, and remove development-only maintenance endpoints from production.',
  },
  {
    id: 'CWE-915',
    name: 'Improperly Controlled Modification of Dynamically-Determined Object Attributes',
    patterns: ['mass_assignment', 'mass assignment', 'admin:true', 'improperly controlled modification'],
    remediation:
      'Use an explicit allowlist of writable fields for object creation and update operations. Ignore or reject privilege-bearing fields supplied by clients.',
  },
  {
    id: 'CWE-489',
    name: 'Active Debug Code',
    patterns: ['debug_mode_enabled', 'debug mode', 'werkzeug debugger', 'debug_endpoint'],
    remediation:
      'Disable debug tooling and developer-only endpoints in production builds. Gate any diagnostics behind secure environment checks and authentication.',
  },
  {
    id: 'CWE-209',
    name: 'Generation of Error Message Containing Sensitive Information',
    patterns: ['verbose_error_messages', 'stack trace', 'schema_disclosure', 'debug_mode_stack_traces', 'validation errors', 'authentication_error_disclosure'],
    remediation:
      'Return generic client-facing errors and log detailed diagnostic context server-side only. Avoid exposing stack traces, schema details, and framework internals.',
  },
  {
    id: 'CWE-703',
    name: 'Improper Check or Handling of Exceptional Conditions',
    patterns: ['missing_exception_handling', 'bare_except_block', 'bare except', 'try/except'],
    remediation:
      'Handle expected exceptions explicitly, fail closed on unexpected errors, and return correct HTTP status codes while preserving server-side logs for debugging.',
  },
  {
    id: 'CWE-307',
    name: 'Improper Restriction of Excessive Authentication Attempts',
    patterns: ['missing_rate_limiting', 'brute force', 'rate limiting', 'credential stuffing'],
    remediation:
      'Apply rate limiting, lockout or progressive backoff controls on authentication and other abuse-prone endpoints, and alert on repeated failures.',
  },
  {
    id: 'CWE-799',
    name: 'Improper Control of Interaction Frequency',
    patterns: ['missing_rate_limiting_registration', 'unlimited', 'registration'],
    remediation:
      'Limit request rates for registration and other public workflows, add abuse detection, and require additional verification for suspicious activity.',
  },
  {
    id: 'CWE-613',
    name: 'Insufficient Session Expiration',
    patterns: ['missing_token_revocation', 'no_logout', 'unlimited_concurrent_sessions', 'missing_token_binding', 'token revocation', 'concurrent sessions'],
    remediation:
      'Track active sessions server-side, revoke tokens on logout or sensitive account changes, enforce session lifetimes, and limit concurrent active sessions.',
  },
  {
    id: 'CWE-294',
    name: 'Authentication Bypass by Capture-replay',
    patterns: ['token_replay', 'token replay'],
    remediation:
      'Bind tokens to strong session context where appropriate, shorten token lifetime, rotate refresh tokens, and detect replay of previously seen credentials.',
  },
  {
    id: 'CWE-525',
    name: 'Information Exposure Through Browser Caching',
    patterns: ['missing_cache_control_headers', 'cache-control', 'cache control'],
    remediation:
      'Set Cache-Control: no-store for sensitive responses and ensure downstream proxies and browsers do not persist authenticated content.',
  },
  {
    id: 'CWE-208',
    name: 'Observable Timing Discrepancy',
    patterns: ['timing_attack', 'timing attack', 'timing discrepancy'],
    remediation:
      'Use constant-time comparisons for sensitive values and make authentication failure paths perform equivalent work to reduce timing side channels.',
  },
  {
    id: 'CWE-367',
    name: 'Time-of-check Time-of-use (TOCTOU) Race Condition',
    patterns: ['race_condition_toctou', 'race condition', 'toctou'],
    remediation:
      'Make state validation and mutation atomic using transactions, row-level locking, or idempotency controls so concurrent requests cannot bypass invariants.',
  },
  {
    id: 'CWE-1021',
    name: 'Improper Restriction of Rendered UI Layers or Frames',
    patterns: ['clickjacking', 'frame-options', 'x-frame-options'],
    remediation:
      'Set X-Frame-Options or frame-ancestors in CSP and ensure sensitive pages cannot be embedded by untrusted origins.',
  },
  {
    id: 'CWE-319',
    name: 'Cleartext Transmission of Sensitive Information',
    patterns: ['weak_tls', 'missing_application_tls', 'insecure_token_delivery', 'http-only', 'unencrypted channel'],
    remediation:
      'Enforce TLS end to end for all sensitive traffic, redirect HTTP to HTTPS, and avoid transmitting secrets or tokens over cleartext channels.',
  },
  {
    id: 'CWE-312',
    name: 'Cleartext Storage of Sensitive Information',
    patterns: ['unencrypted_database_storage', 'encryption at rest', 'plaintext file', 'database.db'],
    remediation:
      'Encrypt sensitive data at rest, protect encryption keys separately from the data store, and minimize direct filesystem exposure to stored secrets.',
  },
  {
    id: 'CWE-200',
    name: 'Exposure of Sensitive Information to an Unauthorized Actor',
    patterns: ['information_disclosure', 'sensitive_data_exposure', 'user_enumeration', 'api_spec_exposure', 'header_leakage', 'security_posture_leak'],
    remediation:
      'Limit sensitive data returned to unauthenticated or unauthorized users, remove unnecessary disclosure endpoints, and minimize metadata leaked in responses.',
  },
  {
    id: 'CWE-204',
    name: 'Observable Response Discrepancy',
    patterns: ['username_enumeration', 'authentication_error_disclosure', 'different error messages'],
    remediation:
      'Normalize authentication and validation error messages so success and failure cases do not disclose whether usernames, emails, or resources exist.',
  },
  {
    id: 'CWE-650',
    name: 'Trusting HTTP Permission Methods on the Server Side',
    patterns: ['http_verb_tampering', 'method override', 'x-http-method-override'],
    remediation:
      'Reject method-override headers unless explicitly required, and enforce authorization and routing based on the effective HTTP method server-side.',
  },
];

// CWE-to-compliance-framework control mapping.
// Maps CWE IDs to OWASP Top 10, PCI-DSS 4.0, SOC 2, and NIST 800-53 control IDs.
const CWE_COMPLIANCE_MAP = {
  'CWE-89':  { owasp: 'A03:2021', pci_dss: '6.2.4', soc2: 'CC6.1', nist: 'SI-10' },
  'CWE-79':  { owasp: 'A03:2021', pci_dss: '6.2.4', soc2: 'CC6.1', nist: 'SI-10' },
  'CWE-918': { owasp: 'A10:2021', pci_dss: '6.2.4', soc2: 'CC6.6', nist: 'SC-7' },
  'CWE-639': { owasp: 'A01:2021', pci_dss: '7.2.2', soc2: 'CC6.1', nist: 'AC-3' },
  'CWE-862': { owasp: 'A01:2021', pci_dss: '7.2.1', soc2: 'CC6.1', nist: 'AC-3' },
  'CWE-287': { owasp: 'A07:2021', pci_dss: '8.3.1', soc2: 'CC6.1', nist: 'IA-2' },
  'CWE-321': { owasp: 'A02:2021', pci_dss: '3.6.1', soc2: 'CC6.1', nist: 'SC-12' },
  'CWE-798': { owasp: 'A07:2021', pci_dss: '8.6.2', soc2: 'CC6.1', nist: 'IA-5' },
  'CWE-256': { owasp: 'A02:2021', pci_dss: '8.3.2', soc2: 'CC6.1', nist: 'IA-5' },
  'CWE-306': { owasp: 'A07:2021', pci_dss: '8.3.1', soc2: 'CC6.1', nist: 'IA-2' },
  'CWE-915': { owasp: 'A01:2021', pci_dss: '6.2.4', soc2: 'CC6.1', nist: 'SI-10' },
  'CWE-489': { owasp: 'A05:2021', pci_dss: '6.3.1', soc2: 'CC8.1', nist: 'CM-7' },
  'CWE-209': { owasp: 'A05:2021', pci_dss: '6.2.4', soc2: 'CC7.2', nist: 'SI-11' },
  'CWE-703': { owasp: 'A05:2021', pci_dss: '6.2.4', soc2: 'CC7.2', nist: 'SI-11' },
  'CWE-307': { owasp: 'A07:2021', pci_dss: '8.3.4', soc2: 'CC6.1', nist: 'AC-7' },
  'CWE-799': { owasp: 'A07:2021', pci_dss: '8.3.4', soc2: 'CC6.1', nist: 'SC-5' },
  'CWE-613': { owasp: 'A07:2021', pci_dss: '8.2.8', soc2: 'CC6.1', nist: 'AC-12' },
  'CWE-294': { owasp: 'A07:2021', pci_dss: '8.3.1', soc2: 'CC6.1', nist: 'IA-2' },
  'CWE-525': { owasp: 'A04:2021', pci_dss: '6.2.4', soc2: 'CC6.7', nist: 'SC-28' },
  'CWE-208': { owasp: 'A02:2021', pci_dss: '6.2.4', soc2: 'CC6.1', nist: 'SC-13' },
  'CWE-367': { owasp: 'A04:2021', pci_dss: '6.2.4', soc2: 'CC8.1', nist: 'SI-7' },
  'CWE-1021': { owasp: 'A05:2021', pci_dss: '6.2.4', soc2: 'CC6.1', nist: 'SI-10' },
  'CWE-319': { owasp: 'A02:2021', pci_dss: '4.2.1', soc2: 'CC6.7', nist: 'SC-8' },
  'CWE-312': { owasp: 'A02:2021', pci_dss: '3.5.1', soc2: 'CC6.1', nist: 'SC-28' },
  'CWE-200': { owasp: 'A01:2021', pci_dss: '6.2.4', soc2: 'CC6.1', nist: 'AC-4' },
  'CWE-204': { owasp: 'A07:2021', pci_dss: '6.2.4', soc2: 'CC6.1', nist: 'SI-11' },
  'CWE-650': { owasp: 'A05:2021', pci_dss: '6.2.4', soc2: 'CC6.1', nist: 'AC-3' },
};

const resolveComplianceControls = (cweIds) => {
  const owasp = new Set();
  const pci_dss = new Set();
  const soc2 = new Set();
  const nist = new Set();

  for (const rawId of cweIds) {
    const id = rawId.trim().toUpperCase();
    const normalized = id.startsWith('CWE-') ? id : `CWE-${id}`;
    const mapping = CWE_COMPLIANCE_MAP[normalized];
    if (mapping) {
      owasp.add(mapping.owasp);
      pci_dss.add(mapping.pci_dss);
      soc2.add(mapping.soc2);
      nist.add(mapping.nist);
    }
  }

  return {
    owasp_controls: [...owasp].join('; '),
    pci_dss_controls: [...pci_dss].join('; '),
    soc2_controls: [...soc2].join('; '),
    nist_controls: [...nist].join('; '),
  };
};

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

  const complianceControls = resolveComplianceControls(cweIds);

  return {
    ...rest,
    source_file: normalizeMultiValueField(finding.source_file),
    original_ids: normalizeMultiValueField(finding.original_ids),
    cwe: compactCwe,
    cwe_names: [...new Set(cweNames)].join('; '),
    remediation_suggestions: hasValue(finding.remediation_suggestions)
      ? String(finding.remediation_suggestions).trim()
      : remediation,
    owasp_controls: complianceControls.owasp_controls,
    pci_dss_controls: complianceControls.pci_dss_controls,
    soc2_controls: complianceControls.soc2_controls,
    nist_controls: complianceControls.nist_controls,
  };
});

const findingsToCSV = (findings) => {
  const keySet = new Set();
  for (const f of findings) {
    for (const k of Object.keys(f)) {
      keySet.add(k);
    }
  }

  const preferredOrder = [
    'id', 'type', 'severity', 'status',
    'source_endpoint', 'parameter', 'code_location',
    'missing_defense', 'attack_path', 'exploitation_hypothesis',
    'confidence', 'externally_exploitable', 'cwe', 'cwe_names', 'remediation_suggestions',
    'owasp_controls', 'pci_dss_controls', 'soc2_controls', 'nist_controls',
    'developer_verification_steps',
    'evidence_snippet', 'exploit_result', 'affected_endpoint',
    'attack_steps_summary', 'report_section', 'source_file', 'notes',
  ];

  const header = [];
  for (const k of preferredOrder) {
    if (keySet.has(k)) {
      header.push(k);
      keySet.delete(k);
    }
  }
  for (const k of [...keySet].sort()) {
    header.push(k);
  }

  logInfo(`CSV columns (${header.length}): ${DIM}${header.join(', ')}${RESET}`);

  // Check how many findings have verification steps
  const withSteps = findings.filter(f => f.developer_verification_steps && f.developer_verification_steps.length > 0).length;
  logInfo(`Findings with verification steps: ${withSteps}/${findings.length}`);

  const lines = [header.map(csvEscape).join(',')];
  for (const row of findings) {
    lines.push(
      header.map((key) => csvEscape(row[key] ?? '')).join(',')
    );
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

const findings = loadFindings();

if (!findings || findings.length === 0) {
  logError('No findings extracted.');
  logError('Check these locations for agent output:');
  logError(`  - ${jsonOutputPath}`);
  logError(`  - ${absDeliverables}/*.json`);
  process.exit(1);
}

const enrichedFindings = enrichFindings(findings);
const csv = findingsToCSV(enrichedFindings);
fs.writeFileSync(absOutput, csv);

console.log('');
console.log(`${BOLD}═══════════════════════════════════════════════════════════${RESET}`);
logSuccess(`${BOLD}CSV written: ${absOutput} (${findings.length} findings)${RESET}`);
console.log(`${BOLD}═══════════════════════════════════════════════════════════${RESET}`);
console.log('');
