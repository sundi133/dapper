# Dapper — Standard Operating Procedure (SOP)

A practical runbook for operators: how to get started, run a pentest, watch it
progress, debug failures, find the logs, and locate the reports.

> Dapper is a defensive-security tool. Only run it against systems you own or
> have explicit written permission to test.

---

## 0. Mental model (read this first)

Dapper runs a **five-phase pentest** (pre-recon → recon → vuln analysis →
exploitation → report) as a **Temporal workflow** inside Docker. Two containers
matter:

- **`temporal`** — the durable workflow engine + Web UI (http://localhost:8233)
- **`worker`** — runs the Claude Agent SDK, external tools, and writes all output

You interact with everything through the `./dapper` CLI. Output lands in two
places:

| What | Where | Purpose |
|------|-------|---------|
| Forensic logs & metrics | `audit-logs/{host}_{sessionId}/` | Debugging, cost/timing, prompts, per-agent turns |
| Security findings | `.../deliverables/` (in the session folder, and/or `repos/<REPO>/deliverables/`) | The reports you deliver — final report is `comprehensive_security_assessment_report.md` |

The `{host}_{sessionId}` folder name **is** the workflow ID (e.g.
`vampi-production-8cbb-up-railway-app_dapper-1773871848991`).

---

## 1. Getting started (first run)

### 1.1 One-time setup
```bash
# Credentials
cp .env.example .env
#   edit .env → set ANTHROPIC_API_KEY=your-key   (or CLAUDE_CODE_OAUTH_TOKEN)

# Put the target source under ./repos/
#   REPO=<name> resolves to ./repos/<name> (mounted at /repos in the container)
ls repos/            # confirm your target folder is here
```

Prerequisites: **Docker** running, and an Anthropic API key (or a router provider
key if using `ROUTER=true`).

### 1.2 Start a pentest
```bash
./dapper start URL=https://target.example.com REPO=<name>
```
The CLI auto-starts the containers, waits for Temporal to become healthy, then
submits the workflow and prints the **workflow ID**. Copy that ID — you need it
for `logs` and `query`.

Common variants:
```bash
# Focus on a subdirectory of the repo
./dapper start URL=<url> REPO=<name> SUBDIR=src/api

# Use an auth/testing config (form login, SSO, TOTP, etc.)
./dapper start URL=<url> REPO=<name> CONFIG=./configs/my-config.yaml

# Custom report output location
./dapper start URL=<url> REPO=<name> OUTPUT=./my-reports

# FAST iteration: minimal prompts, short retry intervals — use while debugging
./dapper start URL=<url> REPO=<name> PIPELINE_TESTING=true

# Pick up code changes that Docker cached
./dapper start URL=<url> REPO=<name> REBUILD=true
```

> Local target? Use `host.docker.internal` instead of `localhost` in the URL —
> the worker runs inside a container.

---

## 2. Monitoring a run

### 2.1 Live worker logs (all workflows)
```bash
docker compose logs -f worker
```

### 2.2 Tail a specific workflow's log
```bash
./dapper logs ID=<workflow-id>
# tails audit-logs/<workflow-id>/workflow.log
```

### 2.3 Query structured progress (phases, agents, cost)
```bash
./dapper query ID=<workflow-id>
```

### 2.4 Temporal Web UI
Open **http://localhost:8233** — inspect workflow history, see which activity
failed, retry state, and stack traces. This is the fastest way to see *where* a
run died.

---

## 3. Where the logs live

For each run, `audit-logs/{host}_{sessionId}/` contains:

```
audit-logs/<workflow-id>/
├── workflow.log      # human-readable phase/agent timeline (what ./dapper logs tails)
├── session.json      # metrics: total_duration_ms, total_cost_usd, phases[], agents[]
├── prompts/          # exact prompts sent per agent (reproducibility)
└── agents/           # turn-by-turn execution logs per agent
```

Quick inspection:
```bash
# Most recent sessions
ls -lt audit-logs/ | head -5

# Cost + timing at a glance
cat audit-logs/<workflow-id>/session.json | jq '.metrics | {total_cost_usd, total_duration_ms}'

# Per-phase / per-agent breakdown
cat audit-logs/<workflow-id>/session.json | jq '.metrics.phases, .metrics.agents'

# The prompt that was actually sent (to reproduce an agent)
ls audit-logs/<workflow-id>/prompts/
```

---

## 4. Generating & finding reports

### 4.1 The automatic final report
The **Reporting phase** runs automatically at the end of every workflow — no
extra command needed. It consolidates recon data + verified exploit evidence,
drops false positives (strict *"No Exploit, No Report"* policy), and writes the
final pentest-grade report:

```
deliverables/comprehensive_security_assessment_report.md
```

This is the primary human-facing deliverable. It's written into the session's
`deliverables/` folder — under `audit-logs/{host}_{sessionId}/deliverables/`
(or under your `OUTPUT=<path>` if you set one).

```bash
# Open the final report for the most recent run
ls -lt audit-logs/*/deliverables/comprehensive_security_assessment_report.md
```

### 4.2 Intermediate deliverables (per phase/agent)
Each phase also emits its own working artifacts alongside the final report:
- `pre_recon_deliverable.md`, `code_analysis_deliverable.md`, `threat_model_deliverable.md`
- `*_analysis_deliverable.md` — vuln analysis per class (injection, xss, auth, authz, ssrf)
- `*_exploitation_queue.json` — hypothesized exploit targets handed to exploitation
- `*_exploitation_evidence.md` — proof of successful exploitation (PoCs)

> Depending on run/config, deliverables may also appear under
> `repos/<REPO>/deliverables/` (the repo is mounted into the worker). Check both
> `audit-logs/<id>/deliverables/` and `repos/<REPO>/deliverables/`.

Reference examples of finished reports live in `sample-reports/`
(`shannon-report-juice-shop.md`, `-crapi.md`, `-capital-api.md`).

### 4.3 Export findings to CSV/JSON (post-processing)
To turn a deliverables folder into a structured findings table, run the agentic
exporter (host-side Node, not the container — needs `ANTHROPIC_API_KEY` or
`CLAUDE_CODE_OAUTH_TOKEN` in your shell):

```bash
node scripts/export-findings-csv.js <deliverables-dir> [output.csv] \
     [--model <model>] [--max-turns <n>] [--reuse-json]

# Example (from the README):
node scripts/export-findings-csv.js repos/DVWA/deliverables --model claude-opus-4-6 --max-turns 100
```

- Reads every file in the folder with the Claude Agent SDK (no regex/format
  assumptions) and extracts structured findings.
- Defaults: writes `<deliverables-dir>/findings.csv` plus a companion
  `<name>_findings.json`. Pass a second positional arg to name the CSV.
- `--reuse-json` skips re-analysis and rebuilds the CSV from the cached
  `_findings.json` (fast, free — use after a first full run).

> Human oversight is required: the LLM can still surface weakly-supported or
> hallucinated items. Validate severity and legitimacy before delivering.

---

## 5. Debugging a failed run

Follow this order — it moves from cheap to expensive checks. (The `/debug` skill
automates this same flow.)

### Step 1 — Confirm the containers are healthy
```bash
docker compose ps                    # both temporal + worker should be "running"/"healthy"
docker compose logs temporal | tail  # "Temporal not ready" → wait or check here
```

### Step 2 — Find where it failed
```bash
./dapper query ID=<workflow-id>      # which phase/agent, status, error
tail -50 audit-logs/<workflow-id>/workflow.log
```
Or open http://localhost:8233 and read the failed activity's stack trace.

### Step 3 — Read the error detail in metrics
```bash
cat audit-logs/<workflow-id>/session.json | jq '.session.status, .metrics.agents'
```

### Step 4 — Identify the failing layer
Map the error to a subsystem before touching code:

| Layer | Symptom | Look at |
|-------|---------|---------|
| CLI / args | "URL and REPO are required", "Repository not found" | `dapper` script, `./repos/<name>` exists |
| Config parsing | YAML / JSON-Schema validation error | `src/config-parser.ts`, `configs/config-schema.json` |
| Claude SDK | agent turn errors, MCP failures, 0 agents completed | `audit-logs/<id>/agents/`, `src/ai/claude-executor.ts` |
| External tools | nmap/subfinder/whatweb missing | run with `PIPELINE_TESTING=true` to skip them |
| Temporal | "Temporal not ready", worker not processing | `docker compose ps`, `docker compose logs temporal` |
| Audit/metrics | partial session.json, lock issues | `src/audit/` |

### Step 5 — Reproduce fast
```bash
# Minimal prompts + 10s retries instead of 5min
./dapper start URL=<url> REPO=<name> PIPELINE_TESTING=true
```

### Step 6 — Common fixes
```bash
# Code changes not picked up by the container
./dapper start URL=<url> REPO=<name> REBUILD=true

# Wedged Temporal / workflow state — nuke and restart clean
./dapper stop CLEAN=true            # removes volumes + all workflow data
./dapper start URL=<url> REPO=<name>

# Permissions: audit-logs / deliverables must be writable by container UID 1001
#   (the CLI chmod 777s these automatically; re-run start if a manual copy broke it)
```

---

## 6. Checking / changing code

Key entry points and where to make changes:

| Task | File(s) |
|------|---------|
| Build TS after edits | `npm run build` (then `REBUILD=true` on next start) |
| Add / reorder agents | `src/session-manager.ts` (AGENT_QUEUE + parallel groups) |
| Workflow phases | `src/temporal/workflows.ts` |
| Activity implementations | `src/temporal/activities.ts` |
| Claude SDK integration | `src/ai/claude-executor.ts` |
| Prompt templates | `prompts/*.txt` (vars: `{{TARGET_URL}}`, `{{CONFIG_CONTEXT}}`, `{{LOGIN_INSTRUCTIONS}}`) |
| Config parsing/validation | `src/config-parser.ts`, `configs/config-schema.json` |
| Error handling / retries | `src/error-handling.ts` |

Workflow to change a prompt or agent:
1. Edit the file(s) above.
2. `npm run build`.
3. Re-run with `REBUILD=true` (Docker caches the build; `REBUILD` forces
   `--no-cache`) and `PIPELINE_TESTING=true` for a fast loop.
4. Verify via `./dapper query` + the new deliverable.

Helper skills available in this repo: `/debug` (structured debugging),
`/skills` (full agent/phase/CLI reference), `/review` (Shannon-specific code
review), `/pr` (conventional-commit PR to main).

---

## 7. Stopping & cleanup
```bash
./dapper stop              # stop containers, preserve workflow data
./dapper stop CLEAN=true   # full cleanup incl. Temporal volumes (destroys history)
```

---

## 8. Quick reference card

```bash
# Run
./dapper start URL=<url> REPO=<name> [SUBDIR=..] [CONFIG=..] [OUTPUT=..] [PIPELINE_TESTING=true] [REBUILD=true] [ROUTER=true]

# Watch
./dapper logs  ID=<workflow-id>            # tail workflow.log
./dapper query ID=<workflow-id>            # structured progress
docker compose logs -f worker             # raw worker logs
open http://localhost:8233                 # Temporal UI

# Inspect
ls -lt audit-logs/ | head                              # recent runs
cat audit-logs/<id>/session.json | jq '.metrics'       # cost/timing

# Reports
#   Final report is generated automatically by the Reporting phase — no command needed:
ls -lt audit-logs/*/deliverables/comprehensive_security_assessment_report.md   # open the final report
ls -lt audit-logs/<id>/deliverables/                   # all deliverables for a run
# Export findings to CSV/JSON (host-side, needs ANTHROPIC_API_KEY):
node scripts/export-findings-csv.js <deliverables-dir> [output.csv] [--model <m>] [--max-turns <n>] [--reuse-json]

# Recover
./dapper stop CLEAN=true && ./dapper start ...         # reset everything
```
