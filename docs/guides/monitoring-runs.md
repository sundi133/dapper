---
title: Monitoring runs
parent: Guides
nav_order: 3
permalink: /guides/monitoring-runs
---

# Monitoring runs
{: .no_toc }

A run executes in the background on a durable [Temporal]({{ '/concepts/agent-pipeline' | relative_url }}) workflow, so you can watch it without holding a terminal open. There are three complementary ways to follow along: live logs, a progress snapshot, and the Temporal Web UI.

1. TOC
{:toc}

---

Every monitoring command keys off the **workflow ID** that `./dapper start` prints when you launch a run:

```text
Workflow started: staging-your-app-com_dapper-1781063631798
```

## Live logs

```bash
./dapper logs ID=staging-your-app-com_dapper-1781063631798
```

Tails the orchestration log (`workflow.log`) for that run — phase transitions, agents starting and finishing, tools firing, and retries. Use it when you want a running narrative of what the pipeline is doing right now.

Under the hood, `logs` locates the log file for the ID. It checks the default `./audit-logs/<id>/workflow.log` first, then searches up to three levels deep so it still works when you launched with a custom `OUTPUT` path.

{: .note }
> If you get "Workflow log not found", the run either hasn't created its directory yet or the ID is wrong. Confirm with `./dapper query ID=<id>` first.

## Progress snapshot

```bash
./dapper query ID=staging-your-app-com_dapper-1781063631798
```

Prints a point-in-time status without tailing — the status, current phase, current agent, elapsed time, how many of the 13 agents have completed, and per-agent duration and cost for those that finished. Good for a quick "where is it?" check or for scripting a wait loop.

```text
Workflow Progress
────────────────────────────────────────
Workflow ID:   staging-your-app-com_dapper-1781063631798
Status:        running
Current Phase: vulnerability-analysis
Current Agent: injection-vuln
Elapsed:       38m 12s
Completed:     2/13 agents

Completed agents:
  - pre-recon (5m 2s, $1.10)
  - recon (3m 41s, $0.86)
```

## The Temporal Web UI

For a visual, drill-down view, open the Temporal dashboard:

```text
http://localhost:8233
```

Each pentest appears as a `pentestPipelineWorkflow` execution. Click into one to see:

| View | What it shows |
|:-----|:--------------|
| **Workflows list** | Every run, its status (Running / Completed / Failed), and start time. Filter by workflow ID. |
| **Event History** | Every activity (agent) as it's scheduled, started, completed, or retried — the authoritative timeline of the run. |
| **Pending Activities** | What's executing right now and how many agents are running in parallel (up to five in the vulnerability and exploitation phases). |
| **Retries** | An activity's attempt count and the backoff before its next try — useful when an agent is wrestling with a flaky target or a rate limit. |

{: .note }
> Because the workflow is durable, a crashed worker **resumes** from its last checkpoint instead of restarting. Transient and billing errors are retried automatically with backoff, and each agent retries up to 3 times. Read more in [The agent pipeline]({{ '/concepts/agent-pipeline' | relative_url }}).

If the dashboard won't load, the Temporal container may still be starting — check `docker compose logs temporal` or wait for the health check to pass.

## Where output lands

As agents finish, deliverables and metrics are written incrementally under:

```text
audit-logs/<host>_<sessionId>/
├── deliverables/    # the report (written as findings are verified)
├── session.json     # per-agent / per-phase cost and duration metrics
├── agents/          # turn-by-turn logs
├── prompts/         # exact prompts used
└── workflow.log     # orchestration log (what ./dapper logs tails)
```

You don't have to wait for completion — open `deliverables/` mid-run to read findings as they're confirmed. See [Output & deliverables]({{ '/reference/output-deliverables' | relative_url }}) for the full reference.

Next: [Reading the report]({{ '/guides/reading-the-report' | relative_url }}).
