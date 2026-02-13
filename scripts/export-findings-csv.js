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
const maxTurns = parseInt(flag('max-turns') || '30', 10);

// ── Validation ──────────────────────────────────────────────────────────────

if (!fs.existsSync(deliverablesDir)) {
  console.error(`Deliverables directory not found: ${deliverablesDir}`);
  process.exit(1);
}

if (!process.env.ANTHROPIC_API_KEY && !process.env.CLAUDE_CODE_OAUTH_TOKEN) {
  console.error('Missing ANTHROPIC_API_KEY or CLAUDE_CODE_OAUTH_TOKEN.');
  process.exit(1);
}

const absDeliverables = path.resolve(deliverablesDir);
const absOutput = path.resolve(outputPath);
const jsonOutputPath = absOutput.replace(/\.csv$/, '') + '_findings.json';

console.log(`Deliverables : ${absDeliverables}`);
console.log(`Output CSV   : ${absOutput}`);
console.log(`JSON interim : ${jsonOutputPath}`);
console.log(`Model        : ${model}`);
console.log(`Max turns    : ${maxTurns}`);
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

## STEP-BY-STEP INSTRUCTIONS
1. First, list all files in the deliverables directory.
2. Read each file to understand the formats present (JSON queues, markdown reports, text notes, etc.).
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
   Use the Write tool to write the file.

## IMPORTANT RULES
- Be thorough. Read every file. Do not skip files.
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

const runAgent = async () => {
  const options = {
    model,
    maxTurns,
    permissionMode: 'bypassPermissions',
    allowDangerouslySkipPermissions: true,
    allowedTools: ['Bash', 'Read', 'Write', 'Glob', 'Grep'],
    // CRITICAL: Use the claude_code preset so the agent knows how to use tools,
    // then append our analysis instructions.
    systemPrompt: {
      type: 'preset',
      preset: 'claude_code',
      append: APPEND_INSTRUCTIONS,
    },
    cwd: absDeliverables,
  };

  const taskPrompt = `Analyze all security deliverables in ${absDeliverables} and extract every finding into a structured JSON file at ${jsonOutputPath}. Start by listing the files in the directory.`;

  let resultText = '';
  let gotResult = false;

  try {
    for await (const message of query({ prompt: taskPrompt, options })) {
      if (message.type === 'system' && message.subtype === 'init') {
        console.log(`Session: ${message.session_id}`);
      }
      if (message.type === 'assistant') {
        const text = extractContent(message);
        if (text) {
          resultText = text;
          process.stdout.write('.');
        }
      }
      if (message.type === 'result') {
        gotResult = true;
        const cost = message.total_cost_usd?.toFixed(4) || '?';
        const dur = ((message.duration_ms || 0) / 1000).toFixed(1);
        console.log(`\nAgent completed: ${message.num_turns} turns, ${dur}s, $${cost}`);
        if (message.is_error) {
          console.error(`Agent reported error: ${message.result}`);
        }
        if (message.result) {
          resultText = message.result;
        }
      }
    }
  } catch (err) {
    // If we already got a result message, the exit code 1 is a known
    // SDK quirk — the agent finished but the process cleanup fails.
    if (gotResult) {
      console.log('(Ignoring post-completion process exit signal)');
      return resultText;
    }
    const details = err && typeof err === 'object'
      ? JSON.stringify(err, Object.getOwnPropertyNames(err), 2)
      : String(err);
    console.error(`\nAgent error: ${details}`);
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
    // Strip markdown fences if the agent included them
    const cleaned = raw.replace(/^```json\s*/i, '').replace(/\s*```$/i, '');
    const data = JSON.parse(cleaned);
    if (Array.isArray(data) && data.length > 0) return data;
  } catch { /* skip */ }
  return null;
};

const loadFindings = () => {
  // Primary: where we told the agent to write
  const primary = tryLoadJson(jsonOutputPath);
  if (primary) {
    console.log(`Loaded ${primary.length} findings from ${jsonOutputPath}`);
    return primary;
  }

  // Fallback: scan the deliverables dir for any JSON arrays the agent may have written
  console.log('Primary JSON not found, scanning for agent output...');
  const candidates = [];

  // Check deliverables dir and parent for any new json files
  for (const dir of [absDeliverables, path.dirname(absDeliverables), process.cwd()]) {
    try {
      for (const f of fs.readdirSync(dir)) {
        if (f.endsWith('.json')) {
          const fp = path.join(dir, f);
          if (!candidates.includes(fp)) candidates.push(fp);
        }
      }
    } catch { /* ignore */ }
  }

  for (const candidate of candidates) {
    const data = tryLoadJson(candidate);
    if (data) {
      console.log(`Loaded ${data.length} findings from ${candidate}`);
      return data;
    }
  }

  return null;
};

const findingsToCSV = (findings) => {
  // Dynamically discover all keys across all findings
  const keySet = new Set();
  for (const f of findings) {
    for (const k of Object.keys(f)) {
      keySet.add(k);
    }
  }

  // Preferred column order — anything discovered beyond this goes at the end
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

  const lines = [header.map(csvEscape).join(',')];
  for (const row of findings) {
    lines.push(
      header.map((key) => csvEscape(row[key] ?? '')).join(',')
    );
  }

  return lines.join('\n');
};

// ── Main ────────────────────────────────────────────────────────────────────

console.log('Starting agentic analysis...\n');

await runAgent();

const findings = loadFindings();

if (!findings || findings.length === 0) {
  console.error('\nNo findings extracted.');
  console.error('Check these locations for agent output:');
  console.error(`  - ${jsonOutputPath}`);
  console.error(`  - ${absDeliverables}/*.json`);
  process.exit(1);
}

const csv = findingsToCSV(findings);
fs.writeFileSync(absOutput, csv);
console.log(`\nCSV written: ${absOutput} (${findings.length} findings)`);
