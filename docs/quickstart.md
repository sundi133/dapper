---
title: Quick start
nav_order: 2
---

# Quick start
{: .no_toc }

1. TOC
{:toc}

## Prerequisites

- **Docker** — container runtime. [Install Docker](https://docs.docker.com/get-docker/).
- **AI provider credentials** (choose one):
  - **Anthropic API key** (recommended) — get one from the
    [Anthropic Console](https://console.anthropic.com).
  - **Claude Code OAuth token.**
  - **Alternative providers via [Router Mode]({{ site.baseurl }}/router-mode)** —
    *experimental, unsupported.*

## Install and run

```bash
# 1. Clone Dapper
git clone https://github.com/sundi133/dapper.git
cd dapper

# 2. Configure credentials — choose one method

# Option A: export environment variables
export ANTHROPIC_API_KEY="your-api-key"   # or CLAUDE_CODE_OAUTH_TOKEN

# Option B: create a .env file
cat > .env <<'EOF'
ANTHROPIC_API_KEY=your-api-key
EOF

# 3. Run a pentest
./dapper start URL=https://your-app.com REPO=your-repo
```

Dapper will build the containers, start the workflow, and return a workflow ID.
The pentest runs in the background.

## Prepare your repository

Dapper expects target repositories to live under `./repos/` at the project
root. The `REPO=` flag refers to a folder name inside `./repos/`. Copy or
clone the target repo there:

```bash
git clone https://github.com/your-org/your-repo.git ./repos/your-repo
```

**Monorepos** — clone the whole repo into `./repos/your-monorepo` and pass
it as `REPO=your-monorepo`.

**Multi-repo applications** (separate frontend / backend / api):

```bash
mkdir ./repos/your-app
cd ./repos/your-app
git clone https://github.com/your-org/frontend.git
git clone https://github.com/your-org/backend.git
git clone https://github.com/your-org/api.git
```

## Usage examples

```bash
# Basic pentest
./dapper start URL=https://example.com REPO=repo-name

# With a configuration file
./dapper start URL=https://example.com REPO=repo-name \
  CONFIG=./configs/my-config.yaml

# Custom output directory
./dapper start URL=https://example.com REPO=repo-name OUTPUT=./my-reports
```

## Monitoring progress

```bash
# Real-time worker logs
./dapper logs

# Query a specific workflow's progress
./dapper query ID=dapper-1234567890

# Detailed monitoring via the Temporal Web UI
open http://localhost:8233
```

## Stopping Dapper

```bash
# Stop containers (preserves workflow data)
./dapper stop

# Full cleanup (removes volumes and data)
./dapper stop CLEAN=true
```

## Platform-specific notes

**Linux (native Docker).** You may need to run commands with `sudo` depending
on your Docker setup. If you hit permission issues with output files, make
sure your user has access to the Docker socket.

**macOS.** Works out of the box with Docker Desktop installed.

**Testing local applications.** Docker containers can't reach `localhost` on
the host. Use `host.docker.internal` instead:

```bash
./dapper start URL=http://host.docker.internal:3000 REPO=repo-name
```

## Output structure

All results are saved to `./audit-logs/{hostname}_{sessionId}/` by default.
Use `OUTPUT=<path>` to specify a custom directory.

```
audit-logs/{hostname}_{sessionId}/
├── session.json                                  # metrics and session data
├── agents/                                       # per-agent execution logs
├── prompts/                                      # prompt snapshots
└── deliverables/
    └── comprehensive_security_assessment_report.md
```
