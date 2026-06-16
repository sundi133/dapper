---
title: Get started
nav_order: 2
has_children: true
permalink: /get-started/
---

# Get started
{: .no_toc }

Dapper is a fully autonomous, white-box AI penetration tester. You point it at a running web application **and** that application's source code; it reasons over the code to find candidate vulnerabilities, then drives a real browser and HTTP client to **prove each one by exploiting it live**, and finally writes a pentest-grade report containing only verified findings with copy-paste proof-of-concepts.

This section takes you from a clean checkout to your first complete run. The whole pipeline executes in Docker — there is no language toolchain to install and nothing to deploy into your environment. Everything runs locally; the only traffic that leaves your machine is the LLM API calls.

Read the pages in order:

1. **[Overview]({{ '/get-started/overview' | relative_url }})** — what Dapper does, what you feed it, what comes back, and how it differs from a scanner.
2. **[Installation]({{ '/get-started/installation' | relative_url }})** — prerequisites, `.env` setup, and the `./repos/` layout.
3. **[Quickstart]({{ '/get-started/quickstart' | relative_url }})** — a full end-to-end run against a deliberately vulnerable target.

The first build pulls the Temporal server image and compiles the worker, so budget a few extra minutes the first time around.

{: .danger }
> Dapper is an **active** tool — its exploitation agents create, modify, and delete data to confirm findings. Run it against **staging, sandbox, or local** environments only. **Never against production.**

<div class="card-grid" markdown="0">
  <a class="card" href="{{ '/get-started/overview' | relative_url }}">
    <div class="card-kicker">Orient</div>
    <div class="card-title">Overview</div>
    <div class="card-desc">What Dapper does, what you provide, and what you get back.</div>
  </a>
  <a class="card" href="{{ '/get-started/installation' | relative_url }}">
    <div class="card-kicker">Setup</div>
    <div class="card-title">Installation</div>
    <div class="card-desc">Prerequisites and a clean install in about ten minutes.</div>
  </a>
  <a class="card" href="{{ '/get-started/quickstart' | relative_url }}">
    <div class="card-kicker">First run</div>
    <div class="card-title">Quickstart</div>
    <div class="card-desc">Clone, add your key, point it at a target, and launch.</div>
  </a>
</div>
