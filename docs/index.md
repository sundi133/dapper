---
title: Home
layout: home
nav_order: 1
description: "Dapper — fully autonomous AI pentester."
permalink: /
---

# Dapper

**Dapper is your fully autonomous AI pentester.** Its job is simple: break your
web app before anyone else does — the Red Team to your vibe-coding Blue Team.

[Quick start →]({{ site.baseurl }}/quickstart){: .btn .btn-primary .fs-5 .mb-4 .mb-md-0 .mr-2 }
[View on GitHub](https://github.com/sundi133/dapper){: .btn .fs-5 .mb-4 .mb-md-0 }

---

## What is Dapper?

Dapper is an AI pentester that delivers actual exploits, not just alerts. It
autonomously hunts for attack vectors in your code, then uses its built-in
browser to execute real exploits — injection, auth bypass, SSRF — to prove
the vulnerability is actually exploitable.

**Why this exists.** Thanks to tools like Claude Code and Cursor, your team
ships code non-stop. But your penetration test? That happens once a year.
For the other 364 days, you may be shipping vulnerabilities to production.
Dapper closes that gap as your on-demand whitebox pentester.

## Features

- **Fully autonomous.** Launch with one command. Handles 2FA/TOTP logins
  (including Sign in with Google), browser navigation, and the final report
  with zero intervention.
- **Pentester-grade reports with reproducible exploits.** Copy-and-paste
  Proof-of-Concepts, not noisy alerts.
- **Critical OWASP coverage.** Injection, XSS, SSRF, and Broken Auth/Authz —
  with more in development.
- **Code-aware dynamic testing.** Analyzes your source to guide its attack
  strategy, then performs live browser / CLI exploits on the running app.
- **Powered by integrated tools.** Nmap, Subfinder, WhatWeb, Schemathesis.
- **Parallel processing.** Analysis and exploitation across vulnerability
  classes run concurrently.

## Editions

| Edition | License | Best for |
|---|---|---|
| **Dapper Lite** | AGPL-3.0 | Security teams, independent researchers, testing your own apps |
| **Dapper Pro** | Commercial | Enterprises needing advanced features, CI/CD integration, support |

This site documents **Dapper Lite**. Dapper Pro extends it with an
LLM-powered data flow analysis engine (inspired by the
[LLMDFA paper](https://arxiv.org/abs/2402.10754)) for enterprise-grade code
analysis and deeper detection.

{: .warning }
**White-box only.** Dapper Lite expects access to your application's source
code and repository layout.

## Where to next

- [Quick start]({{ site.baseurl }}/quickstart) — install and run your first scan
- [Configuration]({{ site.baseurl }}/configuration) — auth, TOTP, scope rules
- [Architecture]({{ site.baseurl }}/architecture) — how the multi-agent pipeline works
- [Sample reports]({{ site.baseurl }}/sample-reports) — what Dapper actually finds
- [Disclaimers]({{ site.baseurl }}/disclaimers) — what to know before running

{: .tip }
**Dapper is a fork of [Shannon](https://github.com/KeygraphHQ/shannon)** with
additional specialized agents, enhanced exploitation capabilities, and
extended tooling integration.
