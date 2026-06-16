---
title: Output & deliverables
parent: Reference
nav_order: 2
permalink: /reference/output-deliverables
---

# Output & deliverables
{: .no_toc }

Every run writes a self-contained, crash-safe record to disk. This is the canonical reference for what you get and where.

1. TOC
{:toc}

---

## Location

```text
audit-logs/<host>_<sessionId>/
```

Override the parent directory with `OUTPUT=<path>` on `./dapper start`. The default is `./audit-logs/`.

## Structure

```text
audit-logs/<host>_<sessionId>/
├── deliverables/    # the security report(s)
├── session.json     # metrics: cost, duration, turns per agent
├── agents/          # turn-by-turn execution log per agent
├── prompts/         # the exact prompts used (reproducibility)
└── workflow.log     # orchestration log
```

## `deliverables/`

The security report — the primary output. It leads with an executive summary, then per-finding evidence (vulnerable location pinned to a source line, severity, copy-paste exploitation steps, and proof of impact). Reports are produced in multiple formats for different audiences and tooling:

| Format | Use |
|:-------|:----|
| **Markdown** | Read in any editor; diff-friendly. |
| **HTML** | Share a styled, self-contained report. |
| **PDF** | Hand to stakeholders or attach to a ticket. |
| **JSON** | Machine-readable — feed findings into other systems. |
| **CSV** | Import findings into a spreadsheet or tracker. |

See [Reading the report]({{ '/guides/reading-the-report' | relative_url }}) for how to interpret a finding.

## `session.json`

Aggregated, machine-readable metrics for the run — per-agent and per-phase **cost (USD), duration, and turn counts**, plus run-level totals. Use it to understand what a run costs for a given application and to compare runs over time.

## `agents/`

A turn-by-turn log for every agent — what it observed, which tools it called, and what it concluded. This is where to look when you want to understand *how* a particular finding was reached.

## `prompts/`

Snapshots of the exact prompts each agent ran with, so any run is fully reproducible.

## `workflow.log`

The orchestration log — phase transitions, agent scheduling, and retries from the durable [Temporal pipeline]({{ '/concepts/agent-pipeline' | relative_url }}).

## Crash safety

Logs are append-only and flushed immediately, and `session.json` is written atomically. A run that is interrupted — even with `kill -9` — leaves a consistent, inspectable record rather than a corrupted file.
