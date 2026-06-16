---
title: Security & privacy
parent: Resources
nav_order: 2
permalink: /resources/security-privacy
---

# Security & privacy
{: .no_toc }

Where your code and data go when you run Dapper — and what leaves your network.

1. TOC
{:toc}

---

## Dapper runs on your infrastructure

Dapper executes entirely inside Docker on your own machine or build runner. Your **source code, the target application, the findings, and all logs stay local** — they are read from and written to your host and are never uploaded to Votal or anyone else. There is no Dapper-operated cloud service in the loop; the only external party that ever sees any of your data is the LLM provider you choose, and only to the extent described below.

## What leaves your network

Dapper produces exactly three kinds of outbound traffic. Two are inherent to doing a pentest at all; the third (LLM calls) is the only path your *source code* can travel, and you control which provider receives it.

| Outbound traffic | Destination | What's sent | Stays local if… |
|:-----------------|:------------|:------------|:----------------|
| **LLM API calls** | Your chosen provider — Anthropic by default | Prompts plus the **code and HTTP-context excerpts** the agents reason over. Governed entirely by your provider's data-handling policy. | You run a local model (see Ollama below). |
| **The assessment** | The `URL=` target you specify | HTTP requests, browser navigation, and live exploit payloads — i.e. the pentest itself. | The target is on your own network/staging. |
| **Reconnaissance tools** | The target and its subdomains | Nmap port scans, Subfinder subdomain enumeration, and WhatWeb fingerprinting. | Disabled with `PIPELINE_TESTING=true`. |

Nothing else is transmitted. Findings, deliverables, prompt snapshots, and per-agent logs are written only to disk.

## Zero code egress: run the model locally

If your policy is that **no source code may leave your environment**, point Dapper at a local LLM with [router mode and Ollama]({{ '/reference/llm-providers' | relative_url }}):

```bash
# .env
ROUTER_DEFAULT=ollama,llama3.3
OLLAMA_BASE_URL=http://host.docker.internal:11434

./dapper start URL=http://host.docker.internal:3000 REPO=your-repo ROUTER=true
```

With a local model and a local target, **no code or assessment traffic leaves your machine at all**.

{: .warning }
> Router mode is **experimental and unsupported**. Dapper is built on the Claude Agent SDK and is tuned for Anthropic's Claude — alternative providers (including local models) may produce inconsistent results or fail early phases. Use it for cost-sensitive or air-gapped experimentation, not for assessments you depend on.

## Handling secrets

| Secret | Where it lives | How Dapper handles it |
|:-------|:---------------|:----------------------|
| **LLM API key / OAuth token** | `.env` (`ANTHROPIC_API_KEY`, `CLAUDE_CODE_OAUTH_TOKEN`, or a router provider key) | Read at startup, passed to the SDK. `.env` is git-ignored by default. |
| **Test credentials & TOTP secret** | Your YAML config (`./configs/`) | Used to log in during the run; TOTP codes are generated on the fly. |
| **GitHub token** | Pasted into the web console for a private clone | Used once for the clone and **not persisted**. |
| **Web-console login** | `DAPPER_WEB_USERNAME` / `DAPPER_WEB_PASSWORD` in `.env` | Optional sign-in gate for the browser UI; leave unset for local-only installs. |
| **Session-signing secret** | `DAPPER_SESSION_SECRET` in `.env` | Keeps console logins stable across restarts; a random value is generated if unset (invalidating logins on every restart). |

{: .tip }
> Always authenticate runs with a **dedicated, disposable test account on staging** — never reuse production credentials. Keep `.env` and your config files out of version control.

## The staging-only rule

> Dapper's exploitation agents execute **real attacks** that create, modify, or delete data. Run it on **sandboxed, staging, or local development environments only — never production.** Mutative side effects include creating users, altering or deleting records, compromising test accounts, and injection fallout. Always point authenticated runs at a disposable test account.
{: .danger }

## Data retention

Everything Dapper produces lives under `./audit-logs/{hostname}_{sessionId}/` on your host — `session.json` metrics, per-agent logs, prompt snapshots, and the final report under `deliverables/`. It stays there until **you** delete it; there is no remote retention and nothing is phoned home. See [Output & deliverables]({{ '/reference/output-deliverables' | relative_url }}) for the exact layout.
