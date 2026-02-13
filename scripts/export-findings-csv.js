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
 *   node export-findings-csv.js <deliverables-dir> [output.csv] [--model <model>] [--max-turns <n>]
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

// ── Validation ──────────────────────────────────────────────────────────────

if (!fs.existsSync(deliverablesDir)) {
  logError(`Deliverables directory not found: ${deliverablesDir}`);
  process.exit(1);
}

if (!process.env.ANTHROPIC_API_KEY && !process.env.CLAUDE_CODE_OAUTH_TOKEN) {
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
5. Write the final result as a SINGLE valid JSON array to: ${jsonOutputPath}

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
   - remediation: Recommended fix
   - evidence_snippet: Key evidence text (max 300 chars)
   - exploit_result: What happened when exploited
   - affected_endpoint: Specific affected endpoint
   - attack_steps_summary: Summary of attack steps
   - report_section: Which report section this came from
   - source_file: Which file(s) this finding came from
   - notes: Any additional notes

   If you discover additional relevant fields in the data, include them too.

6. Write the merged JSON array to: ${jsonOutputPath}
   The file must contain ONLY a valid JSON array — no markdown fences, no commentary, no extra text.
   Use the Write tool or bash to write the file.

## IMPORTANT RULES
- Be thorough. Read every file. Do not skip files.
- BE EFFICIENT. Batch file reads using bash. Do not read one file per turn.
- Merge information: if the same finding ID appears in multiple files, combine all fields into one record.
- Do NOT invent data. If a field is not present, use empty string "".
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
    'confidence', 'externally_exploitable', 'remediation',
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

  const lines = [header.map(csvEscape).join(',')];
  for (const row of findings) {
    lines.push(
      header.map((key) => csvEscape(row[key] ?? '')).join(',')
    );
  }

  return lines.join('\n');
};

// ── Main ────────────────────────────────────────────────────────────────────

logInfo('Starting agentic analysis...');
console.log('');

await runAgent();

const findings = loadFindings();

if (!findings || findings.length === 0) {
  logError('No findings extracted.');
  logError('Check these locations for agent output:');
  logError(`  - ${jsonOutputPath}`);
  logError(`  - ${absDeliverables}/*.json`);
  process.exit(1);
}

const csv = findingsToCSV(findings);
fs.writeFileSync(absOutput, csv);

console.log('');
console.log(`${BOLD}═══════════════════════════════════════════════════════════${RESET}`);
logSuccess(`${BOLD}CSV written: ${absOutput} (${findings.length} findings)${RESET}`);
console.log(`${BOLD}═══════════════════════════════════════════════════════════${RESET}`);
console.log('');
