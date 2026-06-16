---
title: Home
layout: home
nav_order: 1
description: "Dapper — autonomous AI pentester. Install, configure, and run it in your environment."
permalink: /
---

<div class="dapper-hero" markdown="0">
  <div class="eyebrow">Votal AI</div>
  <h1>Dapper docs</h1>
  <p class="lead">Dapper is an autonomous AI pentester. Point it at a running app and its source — it finds vulnerabilities, exploits them to prove they're real, and writes a report. Get it running below.</p>
</div>

## Run it in 4 steps

You need **Docker** and an **Anthropic API key**. That's it.

```bash
# 1. Get Dapper
git clone https://github.com/sundi133/dapper.git && cd dapper

# 2. Add your key
cp .env.example .env
echo "ANTHROPIC_API_KEY=sk-ant-..." >> .env

# 3. Add the source of the app you want to test
git clone https://github.com/your-org/your-app.git ./repos/your-app

# 4. Run a pentest (staging/local only — never production)
./dapper start URL=https://staging.your-app.com REPO=your-app
```

The run goes to the background. Watch it, then read the report:

```bash
./dapper logs                    # live progress
open http://localhost:8233       # dashboard
open ./audit-logs/               # report lands here when done
```

{: .danger }
> Dapper runs **real exploits** that can change data. Use staging, sandbox, or local targets only — never production.

[Full quickstart →]({{ '/get-started/quickstart' | relative_url }}){: .btn .btn-primary }
[Integrate with CI/CD →]({{ '/guides/cicd' | relative_url }}){: .btn }

## Common tasks

<div class="card-grid" markdown="0">
  <a class="card" href="{{ '/get-started/' | relative_url }}">
    <div class="card-kicker">Set up</div>
    <div class="card-title">Install &amp; first run</div>
    <div class="card-desc">Prerequisites, install, and your first pentest.</div>
  </a>
  <a class="card" href="{{ '/guides/authenticated-testing' | relative_url }}">
    <div class="card-kicker">Configure</div>
    <div class="card-title">Test behind a login</div>
    <div class="card-desc">Point Dapper at an app with form, SSO, API, or 2FA/TOTP auth.</div>
  </a>
  <a class="card" href="{{ '/guides/cicd' | relative_url }}">
    <div class="card-kicker">Integrate</div>
    <div class="card-title">Run it in CI/CD</div>
    <div class="card-desc">Trigger a scan on every deploy from GitHub Actions, GitLab, or curl.</div>
  </a>
  <a class="card" href="{{ '/reference/configuration' | relative_url }}">
    <div class="card-kicker">Reference</div>
    <div class="card-title">Config &amp; CLI</div>
    <div class="card-desc">Every YAML option, CLI flag, and environment variable.</div>
  </a>
  <a class="card" href="{{ '/reference/output-deliverables' | relative_url }}">
    <div class="card-kicker">Output</div>
    <div class="card-title">Read the results</div>
    <div class="card-desc">What's in <code>audit-logs/</code>: reports, metrics, and logs.</div>
  </a>
  <a class="card" href="{{ '/resources/troubleshooting' | relative_url }}">
    <div class="card-kicker">Help</div>
    <div class="card-title">Troubleshooting</div>
    <div class="card-desc">Docker, Temporal, local targets, and common errors.</div>
  </a>
</div>
