---
title: Overview
parent: Get started
nav_order: 1
permalink: /get-started/overview
---

# Overview
{: .no_toc }

Dapper is a fully autonomous AI penetration tester. You give it a running web application and its source code; it finds vulnerabilities, **proves them by executing real exploits**, and produces a report with reproducible proof-of-concepts.

1. TOC
{:toc}

---

## The mental model: white-box + live exploit

A traditional scanner reports *possibilities* — "this parameter might be vulnerable to SQL injection." Someone then has to confirm which of those are real, which is the slow, expensive part. Dapper collapses both steps into one autonomous run by combining two perspectives a human pentester switches between:

- **White-box (source-aware).** Dapper reads the application's source under `./repos/`, traces user-controlled input to dangerous sinks, and uses that context to decide *where* and *how* to attack. It knows your routes, your auth flow, and your query construction before it sends a single request.
- **Black-box (live exploit).** Dapper then drives a real browser and HTTP client against the running target to *prove* each hypothesis. A candidate only becomes a finding if Dapper can demonstrate impact against the live app.

{: .note }
> **No Exploit, No Report.** Every finding in a Dapper report was reproduced against the live target. If a hypothesis cannot be exploited, it is discarded as a false positive rather than reported as a "potential" issue. This is what keeps the report free of the noise a scanner produces.

## What you provide

You give Dapper three things (plus an optional fourth for apps behind a login):

| Input | How you supply it | Why it's needed |
|:------|:------------------|:----------------|
| **A running target** | `URL=` flag pointing at a reachable, **non-production** URL | Dapper drives a real browser and HTTP client against it to confirm exploits. |
| **Source code** | A folder under `./repos/`, referenced by the `REPO=` flag | Dapper reads it to trace input to sinks and guide its attacks (the white-box half). |
| **An LLM key** | `ANTHROPIC_API_KEY` (recommended) or a Claude Code OAuth token in `.env` | Powers the agents' reasoning. See [LLM providers]({{ '/reference/llm-providers' | relative_url }}). |
| **A config** *(optional)* | A YAML file via the `CONFIG=` flag | Only if the app needs a login. Describes the auth flow and 2FA/TOTP. See [Configuration]({{ '/reference/configuration' | relative_url }}). |

A minimal run needs only the first three:

```bash
./dapper start URL=http://host.docker.internal:3000 REPO=your-app
```

## What you get back

Every run writes a self-contained session directory to `./audit-logs/<hostname>_<sessionId>/` (override the location with `OUTPUT=`):

```text
audit-logs/<hostname>_<sessionId>/
├── deliverables/
│   └── comprehensive_security_assessment_report.md   # the report you read
├── session.json     # per-agent cost, duration, and turn metrics
├── agents/          # turn-by-turn execution log for every agent
└── prompts/         # the exact prompts used, for full reproducibility
```

- **`deliverables/`** — the security report. Verified findings with severity, impact, and copy-paste proof-of-concepts. This is the artifact you act on.
- **`session.json`** — machine-readable metrics: cost, duration, and turn counts per agent and per phase.
- **`agents/`** — what each agent actually did, turn by turn, for auditing or debugging a run.
- **`prompts/`** — a snapshot of every prompt, so a run can be understood and reproduced after the fact.

See [Output & deliverables]({{ '/reference/output-deliverables' | relative_url }}) for the full schema and [Reading the report]({{ '/guides/reading-the-report' | relative_url }}) for how to interpret findings.

## The four phases at a glance

Dapper runs a four-phase, multi-agent pipeline on durable [Temporal](https://temporal.io) workflows. Because the work is durable, a run survives a worker restart and resumes where it left off.

```mermaid
flowchart LR
  R[Reconnaissance] --> V[Vulnerability<br/>Analysis]
  V --> E[Exploitation]
  E --> Rep[Reporting]
```

| Phase | What happens | Output |
|:------|:-------------|:-------|
| **1. Reconnaissance** | Maps the attack surface — source analysis plus tools like Nmap, Subfinder, and WhatWeb, correlated with live browser exploration. | A map of entry points, endpoints, and auth mechanisms. |
| **2. Vulnerability analysis** | Specialist agents (Injection, XSS, Auth, Authz, SSRF) hunt their class **in parallel**, tracing input to sinks. | A list of *hypothesized* exploitable paths. |
| **3. Exploitation** | Exploit agents attempt each hypothesis live, using the browser, CLI tools, and custom scripts. Unexploitable hypotheses are dropped. | Verified exploits with evidence. |
| **4. Reporting** | One agent consolidates only the proven findings into a clean report, stripping any noise or hallucinated artifacts. | The final assessment report. |

The parallelism in phases 2 and 3 is why a single class failing doesn't block the others. For the full breakdown see [Architecture]({{ '/concepts/architecture' | relative_url }}) and [Agent pipeline]({{ '/concepts/agent-pipeline' | relative_url }}).

## When to use Dapper

Dapper fits the gap between annual manual pentests and per-commit static analysis:

- **Before a release** — run it against staging to catch exploitable regressions in the classes it covers.
- **After a feature touches auth, input handling, or external requests** — the areas where Injection, XSS, Auth/Authz, and SSRF live.
- **In CI against an ephemeral environment** — see [CI/CD integration]({{ '/guides/cicd' | relative_url }}).

It is **not** a replacement for a full audit. Dapper Lite targets a focused set of *exploitable* classes — **Injection, XSS, Broken Authentication, Broken Authorization, and SSRF** (see [Vulnerability coverage]({{ '/reference/vulnerability-coverage' | relative_url }})). Because of its proof-by-exploitation model, it will not report issues it cannot actively exploit, such as vulnerable third-party libraries or insecure-by-configuration findings.

## How it differs from a scanner

| | Traditional scanner | Dapper |
|:--|:--|:--|
| **Evidence** | Flags *potential* issues from patterns or signatures | Reports only findings it **exploited** live |
| **Source awareness** | Usually black-box only | White-box — reads your code to guide attacks |
| **False positives** | Common; require manual triage | Minimized — unproven hypotheses are discarded |
| **Output** | A list of alerts | A report with reproducible proof-of-concepts |
| **Side effects** | Generally passive | **Active** — can create, modify, or delete data |

That last row is the trade-off for proof-by-exploitation, and the reason for the warning below.

{: .danger }
> **Active tool — staging only.** Dapper's exploitation agents execute real attacks that can create, modify, or delete data, compromise test accounts, and trigger injection side effects. Run it on staging, sandbox, or local environments. **Never on production.** See [Disclaimers]({{ '/resources/disclaimers' | relative_url }}).

## Next steps

<div class="card-grid" markdown="0">
  <a class="card" href="{{ '/get-started/installation' | relative_url }}">
    <div class="card-kicker">Setup</div>
    <div class="card-title">Installation</div>
    <div class="card-desc">Prerequisites and a clean install in about ten minutes.</div>
  </a>
  <a class="card" href="{{ '/get-started/quickstart' | relative_url }}">
    <div class="card-kicker">First run</div>
    <div class="card-title">Quickstart</div>
    <div class="card-desc">Launch your first pentest and read the result.</div>
  </a>
</div>
