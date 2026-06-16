---
title: Installation
parent: Get started
nav_order: 3
permalink: /get-started/installation
---

# Installation
{: .no_toc }

Everything Dapper needs runs in Docker. There is no language toolchain to install and no agent to deploy into your environment — the Temporal server and the worker that runs the agents both run as containers on your machine. This page covers prerequisites in depth, credential setup, how to lay out the target source under `./repos/`, and how to confirm the install works.

1. TOC
{:toc}

---

## Prerequisites

| Requirement | Why | Notes |
|:------------|:----|:------|
| **Docker** | Runs the Temporal server, the worker, and (optionally) the router. | Docker Desktop on macOS/Windows, or Docker Engine + the Compose plugin on Linux. Dapper uses `docker compose` (v2), not the legacy `docker-compose`. [Install Docker](https://docs.docker.com/get-docker/). |
| **LLM credentials** | Power the agents' reasoning. | One of: an **Anthropic API key** from [console.anthropic.com](https://console.anthropic.com) (recommended), **or** a Claude Code OAuth token. Alternative providers are possible via experimental [Router mode]({{ '/reference/llm-providers' | relative_url }}). |
| **~20 GB free disk** | The first build pulls the Temporal server image and compiles the worker image. | Subsequent runs reuse the cached images and start in seconds. |
| **A non-production target** | Dapper exploits live — see the warning below. | A reachable URL on staging, sandbox, or your local machine. |
| **The target's source code** | Dapper is white-box. | Placed under `./repos/` — see [step 3](#3-add-the-targets-source-code). |

{: .danger }
> Dapper's exploitation agents execute real attacks that can create, modify, or delete data. Only ever install and run it where you can point it at a **staging, sandbox, or local** environment. **Never production.**

### Platform notes

| Platform | What to know |
|:---------|:-------------|
| **macOS** | Works out of the box with Docker Desktop running. `host.docker.internal` resolves to your host automatically. |
| **Linux** | You may need to prefix `docker` commands with `sudo`, or add your user to the `docker` group (`sudo usermod -aG docker $USER`, then re-login). If output files end up owned by `root`, that's the Docker socket running as root — fixing group membership resolves it. |
| **Local targets (any OS)** | Containers cannot reach `localhost` on your host. Use `http://host.docker.internal:<port>` in the `URL=` flag instead. |

{: .note }
> Everything runs locally. The only traffic that leaves your machine is the LLM API calls to your chosen provider.

## Clone Dapper

```bash
git clone https://github.com/sundi133/dapper.git
cd dapper
```

All `./dapper` commands are run from this directory, and `./repos/`, `./configs/`, and `./audit-logs/` are all relative to it.

## Add your credentials

Copy the template and edit it:

```bash
cp .env.example .env
```

Set **one** credential. The Anthropic API key is the recommended path:

```bash
# .env
ANTHROPIC_API_KEY=sk-ant-...
```

Or use a Claude Code OAuth token instead:

```bash
# .env
CLAUDE_CODE_OAUTH_TOKEN=your-oauth-token
```

The `./dapper` CLI loads `.env` automatically and refuses to start if neither credential is present (unless you are in experimental router mode). You can also `export ANTHROPIC_API_KEY=...` in your shell instead of using `.env`.

Other settings in `.env.example` are optional — alternative providers for [Router mode]({{ '/reference/llm-providers' | relative_url }}), and a username/password to protect the optional web console. See [Environment variables]({{ '/reference/environment-variables' | relative_url }}) for the full list.

{: .warning }
> `.env` holds secrets. It is git-ignored by default — keep it that way and never commit your key.

## Add the target's source code

Dapper is white-box, so it needs the application's source. Place it under `./repos/` at the project root. The `REPO=` flag is always the **folder name** inside `./repos/` (not a URL and not an absolute path).

**Single repository** — clone it directly into `./repos/`:

```bash
git clone https://github.com/your-org/your-app.git ./repos/your-app
# → run with REPO=your-app
```

**Monorepo** — clone the whole thing, then optionally narrow the analysis to one area with `SUBDIR=`:

```bash
git clone https://github.com/your-org/your-monorepo.git ./repos/your-monorepo
# analyze everything:
./dapper start URL=... REPO=your-monorepo
# or focus on one service:
./dapper start URL=... REPO=your-monorepo SUBDIR=services/api
```

**Multi-repo application** (separate frontend / backend / api) — create one parent folder and clone each repo inside it, then point `REPO=` at the parent:

```bash
mkdir ./repos/your-app
git clone https://github.com/your-org/frontend.git ./repos/your-app/frontend
git clone https://github.com/your-org/backend.git  ./repos/your-app/backend
git clone https://github.com/your-org/api.git       ./repos/your-app/api
# → run with REPO=your-app
```

The resulting layout:

```text
dapper/
├── repos/
│   ├── your-app/            # single repo, or...
│   └── your-app/            # multi-repo parent
│       ├── frontend/
│       ├── backend/
│       └── api/
├── configs/                 # optional YAML auth configs
└── audit-logs/              # reports land here
```

{: .note }
> If `./repos/<name>` doesn't exist, the CLI exits with `Repository not found`. Double-check the folder name matches the `REPO=` value exactly.

## Verify the install

The fastest way to confirm everything builds and connects is a `PIPELINE_TESTING=true` run, which uses minimal prompts and short retry intervals for a quick shallow pass:

```bash
./dapper start URL=http://host.docker.internal:3000 REPO=your-app PIPELINE_TESTING=true
```

On the first invocation this builds the Docker images (a few minutes) and starts the Temporal server, then submits a workflow and prints a workflow ID. A successful start means your credentials, `./repos/` layout, and Docker setup are all wired correctly.

You can confirm the containers are healthy and watch progress:

```bash
docker compose ps                          # worker + temporal should be running
open http://localhost:8233                 # Temporal Web UI
./dapper query ID=<workflow-id>            # workflow progress
```

{: .warning }
> **Testing a target on your own machine?** Containers can't reach `localhost`. Use `http://host.docker.internal:<port>` instead.

When you're done, stop the containers:

```bash
./dapper stop                # preserves workflow data
./dapper stop CLEAN=true     # full cleanup, removes volumes
```

## Updating Dapper

```bash
git pull
./dapper start ... REBUILD=true   # force a clean --no-cache image rebuild
```

Use `REBUILD=true` whenever a `git pull` brings in code changes that aren't being picked up by the cached image.

## Next steps

Continue to the [Quickstart]({{ '/get-started/quickstart' | relative_url }}) to run a complete assessment against a real vulnerable target, or see the [CLI reference]({{ '/reference/cli' | relative_url }}) for every command and flag.
