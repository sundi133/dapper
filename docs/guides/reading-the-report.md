---
title: Reading the report
parent: Guides
nav_order: 6
permalink: /guides/reading-the-report
---

# Reading the report
{: .no_toc }

Dapper's output is built to be acted on, not triaged. Every verified finding was reproduced against the live target and comes with a copy-paste proof-of-concept and a source-line location.

1. TOC
{:toc}

---

## Where to look

```text
audit-logs/<host>_<sessionId>/
├── deliverables/    # the security report(s) — Markdown, HTML, PDF, JSON, CSV
├── session.json     # per-agent / per-phase cost and duration metrics
├── agents/          # turn-by-turn logs for each agent
├── prompts/         # exact prompts used (reproducibility)
└── workflow.log     # orchestration log
```

Start in `deliverables/`. The report opens with an **executive summary** — target, assessment date, scope, and a summary of findings by vulnerability type — written for a non-specialist, followed by per-finding exploitation evidence.

## Report formats

The same report is rendered in several formats so different audiences and tools can consume it:

| Format | Use |
|:-------|:----|
| **Markdown** | Read in any editor; diff-friendly; the source of truth. |
| **HTML** | Share a styled, self-contained report. |
| **PDF** | Hand to stakeholders or attach to a ticket. |
| **JSON** | Machine-readable — feed findings into other systems. |
| **CSV** | Import findings into a spreadsheet or issue tracker. |

## Anatomy of a finding

Every verified finding follows the same shape. Here's a real one (SQL injection auth bypass against OWASP Juice Shop), abbreviated:

```markdown
### INJ-VULN-01: SQL Injection Authentication Bypass

**Summary:**
- **Vulnerable location:** POST /rest/user/login (email field)
- **Overview:** Direct string interpolation in SQL query enables
  complete authentication bypass
- **Impact:** Administrative access bypass, complete system compromise
- **Severity:** Critical

**Prerequisites:**
None - publicly accessible endpoint

**Exploitation Steps:**

1. Send POST request to login endpoint with SQL injection payload:
   ```bash
   curl -X POST http://juice-shop.local:3001/rest/user/login \
     -H "Content-Type: application/json" \
     -d '{"email":"'\'' OR '\''1'\''='\''1'\'' --","password":"test"}'
   ```
2. Receive admin JWT token and user details.

**Proof of Impact:**
Successfully bypassed authentication and obtained an admin-level access
token for user ID 1 (admin@juice-sh.op) with role "admin".

**Notes:**
The vulnerability exists due to direct string interpolation in SQL query
construction at `/routes/login.ts:34`.
```

Read it section by section:

| Section | What it tells you |
|:--------|:------------------|
| **Vulnerable location** | The exact request (method + path + parameter) and, in the notes, the source file and **line number**. |
| **Overview / Impact** | What the flaw is and what an attacker gains. |
| **Severity** | Critical / High / Medium. |
| **Prerequisites** | What an attacker needs first — often "none", sometimes a token from an earlier finding (findings can chain). |
| **Exploitation steps** | A literal, copy-paste reproduction — usually a `curl` command. |
| **Proof of impact** | The concrete result — the token extracted, the record changed, the data exfiltrated. |
| **Notes** | The root cause, pinned to a source line so an engineer can fix it directly. |

Because the location is pinned to a line of code and the PoC is runnable, an engineer can reproduce and fix it in minutes.

{: .note }
> Dapper's exploit-proof model removes the vast majority of false positives, but the underlying models can still occasionally over-state a finding. Treat the report as a strong, evidence-backed starting point and have an engineer confirm severity before remediation.

## Reading the metrics

`session.json` is the machine-readable record of the run's economics. It aggregates cost (USD) and duration at the **run**, **phase**, and **agent** level, plus per-attempt detail:

```json
{
  "session": {
    "id": "...",
    "webUrl": "https://staging.example.com",
    "status": "completed",
    "createdAt": "...",
    "completedAt": "..."
  },
  "metrics": {
    "total_duration_ms": 4380000,
    "total_cost_usd": 12.47,
    "phases": {
      "vulnerability-analysis": {
        "duration_ms": 1980000,
        "duration_percentage": 45.2,
        "cost_usd": 6.10,
        "agent_count": 5
      }
    },
    "agents": {
      "injection-vuln": {
        "status": "success",
        "total_cost_usd": 1.42,
        "final_duration_ms": 410000,
        "attempts": [
          { "attempt_number": 1, "duration_ms": 410000,
            "cost_usd": 1.42, "success": true, "timestamp": "..." }
        ]
      }
    }
  }
}
```

Use it to understand what a run costs for a given application, to spot which phase or agent dominated the spend, and to compare runs over time. Each agent's `attempts` array shows the retry history, so you can see where a flaky target caused re-runs.

## What it won't contain

By default, Dapper reports only what it can **actively exploit**. Issues it can't prove by exploitation — vulnerable dependencies, weak cryptography, static misconfigurations — are out of scope unless you opt into coverage mode (below). See [Disclaimers]({{ '/resources/disclaimers' | relative_url }}) and [Vulnerability coverage]({{ '/reference/vulnerability-coverage' | relative_url }}).

## Coverage mode

By default Dapper runs in **precision** mode (exploit-verified findings only). To additionally surface potential, non-exploited findings — and static checks like security headers and TLS — enable coverage mode in your config:

```yaml
coverage:
  mode: coverage          # 'precision' (default) or 'coverage'
  include_potential: true # include non-exploit-verified candidates
  include_headers_tls: true
  include_sast_sca: true  # static code / dependency findings if available
  max_findings: 200       # optional cap
```

In coverage mode, expect a longer report with a mix of proven findings and flagged-but-unverified candidates — triage accordingly.

Browse real outputs in [Sample reports]({{ '/resources/sample-reports' | relative_url }}).
