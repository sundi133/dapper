---
title: CLI commands
parent: Reference
nav_order: 2
permalink: /reference/cli
---

# CLI commands
{: .no_toc }

Everything Dapper does is driven by the `./dapper` script. Arguments are
passed as `KEY=value` pairs in any order. The command is the first
positional argument; running `./dapper` with no command (or `help`) prints
usage. This page documents every command and flag.

1. TOC
{:toc}

---

## Command summary

| Command | Purpose |
|:--------|:--------|
| `start` | Run a pentest workflow on the Temporal pipeline. |
| `logs` | Tail the live log for a running workflow. |
| `query` | Print a progress snapshot for a workflow. |
| `stop` | Stop the containers (optionally wipe all data). |
| `web` | Launch the DeepAgents web console (FastAPI). |
| `deepagent` | Run a pentest through the LangChain DeepAgents orchestrator. |
| `help` | Show usage. (Also `--help`, `-h`, or any unknown command.) |

{: .note }
> `.env` is sourced automatically when present, so credentials and provider
> settings defined there are available to every command.

---

## `start` — run a pentest

```bash
./dapper start URL=<url> REPO=<name> [options]
```

`URL` and `REPO` are required. The script verifies that an LLM credential is
set (`ANTHROPIC_API_KEY` or `CLAUDE_CODE_OAUTH_TOKEN`, or an alternative
provider key when `ROUTER=true`), ensures the Temporal containers are
healthy, then submits the workflow.

| Flag | Required | Default | Description |
|:-----|:--------:|:--------|:------------|
| `URL` | ✓ | — | The live target. Use `host.docker.internal` instead of `localhost` for apps on the host. |
| `REPO` | ✓ | — | Folder name under `./repos/` containing the source, **or** an absolute container path under `/repos/` or `/benchmarks/`. The folder must exist. |
| `SUBDIR` | | — | Subdirectory within the repo to focus analysis on (e.g. `src/api`). Leading/trailing slashes are stripped; the path must exist within the repo. |
| `CONFIG` | | — | Path to a YAML [configuration]({{ '/reference/configuration' | relative_url }}) file. |
| `OUTPUT` | | `./audit-logs/` | Output directory for the session folder. Created with permissions for the container user (UID 1001). |
| `PIPELINE_TESTING` | | `false` | `true` runs a fast, shallow pass with minimal prompts and short retry intervals. |
| `ROUTER` | | `false` | `true` routes requests through `claude-code-router` for alternative providers. See [LLM providers]({{ '/reference/llm-providers' | relative_url }}). |
| `REBUILD` | | `false` | `true` forces a clean Docker image rebuild (`--no-cache`) before starting — use when code changes are not picked up. |

```bash
# Basic run
./dapper start URL=https://example.com REPO=app

# Focus on a subdirectory
./dapper start URL=https://example.com REPO=app SUBDIR=services/api

# With an authenticated-testing config
./dapper start URL=https://example.com REPO=app CONFIG=./configs/app.yaml

# Custom output directory
./dapper start URL=https://example.com REPO=app OUTPUT=./my-reports

# Fast smoke test
./dapper start URL=https://example.com REPO=app PIPELINE_TESTING=true

# Force a clean rebuild and route through an alternative provider
./dapper start URL=https://example.com REPO=app REBUILD=true ROUTER=true
```

{: .tip }
> `REPO` can be a bare folder name (resolved under `./repos/`) or an absolute
> container path beginning with `/repos/` or `/benchmarks/`. For container
> paths the host-side existence check is skipped.

## `logs` — stream worker activity

```bash
./dapper logs ID=<workflow-id>
```

| Flag | Required | Description |
|:-----|:--------:|:------------|
| `ID` | ✓ | The workflow ID returned by `start`. |

Tails the live `workflow.log` for a workflow — agents, tool calls, and phase
transitions. The script looks first at `./audit-logs/<ID>/workflow.log`, then
searches up to three directory levels deep to handle custom `OUTPUT` paths.

```bash
./dapper logs ID=example.com_dapper-1234567890
```

## `query` — progress snapshot

```bash
./dapper query ID=<workflow-id>
```

| Flag | Required | Description |
|:-----|:--------:|:------------|
| `ID` | ✓ | The workflow ID to inspect. |

Prints the current phase, active agent, completed agents, and aggregated
metrics for the workflow.

```bash
./dapper query ID=dapper-1234567890
```

## `stop` — shut down

```bash
./dapper stop [CLEAN=true]
```

| Flag | Required | Default | Description |
|:-----|:--------:|:--------|:------------|
| `CLEAN` | | `false` | `true` brings containers down **with volumes** (`down -v`), wiping all Temporal/workflow data. Without it, data is preserved. |

Both forms also stop the router profile container if it is running.

```bash
./dapper stop                # stop containers, preserve workflow data
./dapper stop CLEAN=true     # full reset including volumes
```

## `web` — launch the web console

```bash
./dapper web [HOST=0.0.0.0] [PORT=8000]
```

| Flag | Required | Default | Description |
|:-----|:--------:|:--------|:------------|
| `HOST` | | `0.0.0.0` | Host/interface to bind the FastAPI server to. |
| `PORT` | | `8000` | Port to serve on. |

Starts the DeepAgents web console via Uvicorn
(`scripts.deepagents.webapp:app`). Set `DAPPER_WEB_PASSWORD` to require
sign-in — see [Environment variables]({{ '/reference/environment-variables' | relative_url }}).

```bash
./dapper web
./dapper web HOST=127.0.0.1 PORT=9000
```

## `deepagent` — alternative orchestrator

```bash
./dapper deepagent [URL=<url>] [REPO=<name>] [CONFIG=<file>] [OUTPUT=<path>]
```

Runs a pentest through the LangChain DeepAgents orchestrator
(`scripts.deepagents.orchestrator`) instead of the Temporal pipeline. If
arguments are omitted, it falls back to interactive setup.

| Flag | Required | Maps to | Description |
|:-----|:--------:|:--------|:------------|
| `URL` | | `--url` | Target URL. |
| `REPO` | | `--repo` | Repository to analyze. |
| `CONFIG` | | `--config` | YAML config file. |
| `OUTPUT` | | `--deliverables` | Deliverables output directory. |
| `CLASSES` | | `--classes` | Restrict to specific vulnerability classes. |
| `SKIP_EXPLOIT` | | `--skip-exploit` | `true` skips the exploitation phase. |

```bash
./dapper deepagent URL=https://example.com REPO=app
./dapper deepagent URL=https://example.com REPO=app CLASSES=injection,xss SKIP_EXPLOIT=true
```

## `help`

```bash
./dapper help     # also: ./dapper --help, ./dapper -h, or no command
```

Prints the usage banner and examples.

---

## Monitoring URLs

| Surface | URL |
|:--------|:----|
| Temporal dashboard | `http://localhost:8233` |
| Web console (after `./dapper web`) | `http://localhost:8000` |
