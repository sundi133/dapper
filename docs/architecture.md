---
title: Architecture
nav_order: 4
---

# Architecture
{: .no_toc }

1. TOC
{:toc}

Dapper emulates a human penetration tester's methodology using a multi-agent
architecture. It combines white-box source-code analysis with black-box
dynamic exploitation across four phases.

## Pipeline

```
                ┌──────────────────────┐
                │    Reconnaissance    │
                └──────────┬───────────┘
                           │
                           ▼
                ┌──────────┴───────────┐
                │          │           │
                ▼          ▼           ▼
    ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
    │ Vuln Analysis   │ │ Vuln Analysis   │ │      ...        │
    │  (Injection)    │ │     (XSS)       │ │                 │
    └─────────┬───────┘ └─────────┬───────┘ └─────────┬───────┘
              │                   │                   │
              ▼                   ▼                   ▼
    ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
    │  Exploitation   │ │  Exploitation   │ │      ...        │
    │  (Injection)    │ │     (XSS)       │ │                 │
    └─────────┬───────┘ └─────────┬───────┘ └─────────┬───────┘
              │                   │                   │
              └─────────┬─────────┴───────────────────┘
                        │
                        ▼
                ┌──────────────────────┐
                │      Reporting       │
                └──────────────────────┘
```

## Overview

Dapper uses Anthropic's Claude Agent SDK as its core reasoning engine, but
its strength is the multi-agent architecture around it. It combines the deep
context of **white-box source code analysis** with the real-world validation
of **black-box dynamic exploitation**, managed by an orchestrator through
four phases to keep false positives low and context usage intelligent.

### Phase 1 — Reconnaissance

The first phase builds a comprehensive map of the application's attack
surface. Dapper analyzes the source and integrates tools like Nmap and
Subfinder to understand the tech stack and infrastructure. It also performs
live application exploration via browser automation to correlate code-level
insights with real-world behavior, producing a detailed map of entry points,
API endpoints, and authentication mechanisms for the next phase.

### Phase 2 — Vulnerability analysis

Specialized agents for each OWASP category hunt for flaws **in parallel**.
For classes like Injection and SSRF, agents perform a structured data flow
analysis, tracing user input to dangerous sinks. The deliverable is a list
of **hypothesized exploitable paths** that pass to validation.

### Phase 3 — Exploitation

Dedicated exploit agents receive the hypothesized paths and attempt
real-world attacks using browser automation, command-line tools, and custom
scripts. This phase enforces a strict **"No Exploit, No Report"** policy: if
a hypothesis cannot be successfully exploited to demonstrate impact, it is
discarded as a false positive.

### Phase 4 — Reporting

The final phase compiles validated findings into a professional, actionable
report. Only verified vulnerabilities are included, each with **reproducible
copy-and-paste Proof-of-Concepts**.

## Orchestration: Temporal

Dapper uses [Temporal](https://temporal.io) for durable workflow
orchestration:

- **Crash recovery.** Workflows resume automatically after worker restart.
- **Queryable progress.** Real-time status via `./dapper query` or the
  Temporal Web UI at <http://localhost:8233>.
- **Intelligent retry.** Distinguishes transient vs. permanent errors.
- **Parallel execution.** Five concurrent agents in both the vulnerability
  and exploitation phases.

## Audit & metrics

Dapper writes a crash-safe audit trail for every run:

- `audit-logs/{hostname}_{sessionId}/session.json` — metrics with
  attempt-level detail.
- `prompts/` — exact prompts used (for reproducibility).
- `agents/` — turn-by-turn execution logs.
- `deliverables/` — security reports and findings.

Append-only logging with immediate flush survives `kill -9`; atomic writes
keep `session.json` from ending up half-written.
