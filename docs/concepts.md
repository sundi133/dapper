---
title: Concepts
nav_order: 4
has_children: true
permalink: /concepts/
---

# Concepts
{: .no_toc }

How Dapper works under the hood. These pages explain the design that lets an
LLM behave like a human penetration tester: a four-phase methodology, a team of
specialist agents running on a durable workflow engine, and the tooling that
lets those agents log in, drive a real browser, and prove a finding by
exploiting it.

If you've only read the [Quick start]({{ '/get-started/quickstart' | relative_url }}),
this is where the "magic" gets unpacked. Read the pages in order:

1. **Architecture** — the methodology. What each phase does, why Dapper combines
   white-box source analysis with black-box exploitation, and the *No Exploit,
   No Report* principle that keeps the final report free of false positives.
2. **The agent pipeline** — the orchestration. How dozens of specialist agents
   are paired into vuln→exploit pipelines, run concurrently, and survive crashes
   on a [Temporal](https://temporal.io) workflow.
3. **MCP & tooling** — the hands. The MCP servers and external tools agents use
   to actually act on the target.

<div class="card-grid" markdown="0">
  <a class="card" href="{{ '/concepts/architecture' | relative_url }}">
    <div class="card-kicker">Methodology</div>
    <div class="card-title">Architecture</div>
    <div class="card-desc">The four phases: Recon, Analysis, Exploitation, Reporting.</div>
  </a>
  <a class="card" href="{{ '/concepts/agent-pipeline' | relative_url }}">
    <div class="card-kicker">Orchestration</div>
    <div class="card-title">The agent pipeline</div>
    <div class="card-desc">Parallel specialist agents on a durable Temporal workflow.</div>
  </a>
  <a class="card" href="{{ '/concepts/mcp-tooling' | relative_url }}">
    <div class="card-kicker">Tooling</div>
    <div class="card-title">MCP &amp; tooling</div>
    <div class="card-desc">How agents act: Playwright, TOTP, deliverables, recon tools.</div>
  </a>
</div>
