---
title: Guides
nav_order: 3
has_children: true
permalink: /guides/
---

# Guides
{: .no_toc }

Practical, task-focused walkthroughs for running Dapper against real applications. The reference section documents every flag and field in isolation; these guides put them together end to end — choosing a target and pointing Dapper at your source, logging into authenticated apps (including SSO and 2FA), watching a run as it executes, reading the evidence-backed report it produces, and wiring the whole thing into CI/CD so a pentest happens on every deploy.

Each page is self-contained and starts from a working command you can copy. If you're new, read [Running a pentest]({{ '/guides/running-a-pentest' | relative_url }}) first — it covers the lifecycle the other guides drill into. If you're integrating Dapper into a pipeline, jump straight to [CI/CD integration]({{ '/guides/cicd' | relative_url }}).

{: .note }
> Dapper is a defensive security tool. Only run it against systems you own or have explicit written permission to test, and prefer a **staging** environment with **test accounts** — runs execute real exploits and can create, modify, or delete data. See [Disclaimers]({{ '/resources/disclaimers' | relative_url }}).

<div class="card-grid" markdown="0">
  <a class="card" href="{{ '/guides/running-a-pentest' | relative_url }}">
    <div class="card-kicker">Core</div>
    <div class="card-title">Running a pentest</div>
    <div class="card-desc">The full lifecycle of a single assessment, launch to report.</div>
  </a>
  <a class="card" href="{{ '/guides/authenticated-testing' | relative_url }}">
    <div class="card-kicker">Authentication</div>
    <div class="card-title">Authenticated testing</div>
    <div class="card-desc">Log Dapper in — form, SSO, API, basic auth, and 2FA/TOTP.</div>
  </a>
  <a class="card" href="{{ '/guides/monitoring-runs' | relative_url }}">
    <div class="card-kicker">Observe</div>
    <div class="card-title">Monitoring runs</div>
    <div class="card-desc">Logs, progress queries, and the Temporal dashboard.</div>
  </a>
  <a class="card" href="{{ '/guides/web-console' | relative_url }}">
    <div class="card-kicker">UI</div>
    <div class="card-title">The web console</div>
    <div class="card-desc">Launch, stream findings, chat with the agent, and wire CI/CD.</div>
  </a>
  <a class="card" href="{{ '/guides/cicd' | relative_url }}">
    <div class="card-kicker">Automate</div>
    <div class="card-title">CI/CD integration</div>
    <div class="card-desc">Run a pentest on every deploy with GitHub Actions and more.</div>
  </a>
  <a class="card" href="{{ '/guides/reading-the-report' | relative_url }}">
    <div class="card-kicker">Output</div>
    <div class="card-title">Reading the report</div>
    <div class="card-desc">Deliverables, proof-of-concepts, and session metrics.</div>
  </a>
</div>
