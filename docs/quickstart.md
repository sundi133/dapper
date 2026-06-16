---
title: Quickstart
parent: Get started
nav_order: 2
permalink: /get-started/quickstart
---

# Quick start
{: .no_toc }

This walkthrough takes you through a complete first run end to end: spin up a deliberately vulnerable target, give Dapper its source, launch the pentest, watch it work, and read the report. We use **OWASP Juice Shop** because it is safe to attack and exercises every vulnerability class Dapper covers. The same steps apply to your own app once you've finished [Installation]({{ '/get-started/installation' | relative_url }}).

1. TOC
{:toc}

---

## Before you start

You should already have completed [Installation]({{ '/get-started/installation' | relative_url }}):

- Docker running, the Dapper repo cloned, and you're in its directory.
- A credential set in `.env` (`ANTHROPIC_API_KEY=sk-ant-...` or a `CLAUDE_CODE_OAUTH_TOKEN`).

{: .danger }
> Dapper exploits the target for real. Juice Shop is designed to be attacked, so it's a safe choice. Never point this at production.

## Start the target

Run OWASP Juice Shop locally in Docker on port 3000:

```bash
docker run --rm -d -p 3000:3000 bkimminich/juice-shop
```

Confirm it's up at [http://localhost:3000](http://localhost:3000). Leave it running in the background.

{: .note }
> Prefer DVWA? `docker run --rm -d -p 8080:80 vulnerables/web-dvwa` works the same way — just adjust the port in the `URL=` flag below.

## Add the target's source

Dapper is white-box, so clone Juice Shop's source into `./repos/`. The folder name here is what you'll pass as `REPO=`:

```bash
git clone https://github.com/juice-shop/juice-shop.git ./repos/juice-shop
```

For your own monorepos and multi-repo apps, see the layouts in [Installation]({{ '/get-started/installation' | relative_url }}#3-add-the-targets-source-code).

## Launch the pentest

Because the target runs on your host, use `host.docker.internal` instead of `localhost` so the Dapper container can reach it:

```bash
./dapper start URL=http://host.docker.internal:3000 REPO=juice-shop
```

Dapper builds the containers (first run only), starts the Temporal workflow, and prints a **workflow ID** like `host.docker.internal_dapper-1234567890`. The run continues in the background — note that ID, you'll use it to monitor and tail logs.

{: .tip }
> **Fast iteration.** Add `PIPELINE_TESTING=true` for a quick shallow pass that uses minimal prompts and short retry intervals. It's the right way to confirm your setup and config before committing to a full run.
>
> ```bash
> ./dapper start URL=http://host.docker.internal:3000 REPO=juice-shop PIPELINE_TESTING=true
> ```

### Common variations

```bash
# Authenticated app — supply a YAML auth/2FA config
./dapper start URL=http://host.docker.internal:3000 REPO=juice-shop \
  CONFIG=./configs/my-config.yaml

# Focus a monorepo on one service
./dapper start URL=http://host.docker.internal:3000 REPO=your-monorepo SUBDIR=services/api

# Write the report somewhere other than ./audit-logs/
./dapper start URL=http://host.docker.internal:3000 REPO=juice-shop OUTPUT=./my-reports
```

| Flag | Purpose |
|:-----|:--------|
| `URL=` | The running target (use `host.docker.internal` for local apps). **Required.** |
| `REPO=` | Folder name under `./repos/`. **Required.** |
| `CONFIG=` | YAML config for authenticated testing — see [Configuration]({{ '/reference/configuration' | relative_url }}). |
| `SUBDIR=` | Narrow analysis to a subdirectory within the repo. |
| `OUTPUT=` | Custom output directory (default `./audit-logs/`). |
| `PIPELINE_TESTING=true` | Fast, shallow pass for verifying setup. |
| `REBUILD=true` | Force a clean image rebuild when code changes aren't picked up. |

See the [CLI reference]({{ '/reference/cli' | relative_url }}) for the complete list.

## Monitor the run

A full run works through reconnaissance, parallel vulnerability analysis, parallel exploitation, and reporting, so it takes a while. Watch it three ways:

```bash
# Tail the live worker log for a specific workflow (ID is required)
./dapper logs ID=host.docker.internal_dapper-1234567890

# Query the current phase/agent progress for a workflow
./dapper query ID=host.docker.internal_dapper-1234567890

# Open the Temporal Web UI for a visual view of the workflow and its activities
open http://localhost:8233
```

The Temporal UI at [http://localhost:8233](http://localhost:8233) is the richest view — you can see each phase, every parallel agent, retries, and timing. For more, see [Monitoring runs]({{ '/guides/monitoring-runs' | relative_url }}).

{: .note }
> Both `./dapper logs` and `./dapper query` require the `ID=` argument. The workflow ID was printed when you ran `start`; you can also find it in the Temporal UI.

## Read the report

Results land in `./audit-logs/<hostname>_<sessionId>/` (or your `OUTPUT=` path):

```text
audit-logs/<hostname>_<sessionId>/
├── deliverables/
│   └── comprehensive_security_assessment_report.md   # start here
├── session.json     # cost, duration, and turn metrics per agent
├── agents/          # turn-by-turn execution logs
└── prompts/         # prompt snapshots for reproducibility
```

Open `deliverables/comprehensive_security_assessment_report.md` — it contains only the findings Dapper **proved** by exploiting them, each with severity, impact, and a copy-paste proof-of-concept. See [Reading the report]({{ '/guides/reading-the-report' | relative_url }}) and [Output & deliverables]({{ '/reference/output-deliverables' | relative_url }}).

## Stop and clean up

```bash
# Stop Dapper's containers (preserves workflow data so runs can resume)
./dapper stop

# Full cleanup — also removes Temporal volumes and all workflow data
./dapper stop CLEAN=true

# Stop the Juice Shop target
docker stop $(docker ps -q --filter ancestor=bkimminich/juice-shop)
```

## Troubleshooting first runs

| Symptom | Likely cause / fix |
|:--------|:-------------------|
| `Repository not found at ./repos/...` | The `REPO=` value must match a folder name under `./repos/`. |
| Target unreachable from the container | Use `http://host.docker.internal:<port>`, not `localhost`, for local targets. |
| Workflow log not found for `ID=...` | The workflow may not have started yet, or the ID is wrong — check `./dapper query ID=...` or the Temporal UI. |
| `Set ANTHROPIC_API_KEY or CLAUDE_CODE_OAUTH_TOKEN` | No credential found in `.env` or the environment. |
| Code changes not picked up | Re-run with `REBUILD=true` to force a clean rebuild. |

More in [Troubleshooting]({{ '/resources/troubleshooting' | relative_url }}).

## Next steps

- **[Running a pentest]({{ '/guides/running-a-pentest' | relative_url }})** — go deeper on a real run against your own app.
- **[Authenticated testing]({{ '/guides/authenticated-testing' | relative_url }})** — write a `CONFIG=` for apps behind a login, including 2FA/TOTP.
- **[Configuration]({{ '/reference/configuration' | relative_url }})** — the full YAML config reference.
