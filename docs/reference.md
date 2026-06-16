---
title: Reference
nav_order: 5
has_children: true
permalink: /reference/
---

# Reference
{: .no_toc }

Authoritative, lookup-oriented reference material for Dapper. Every page
here documents a concrete surface — the YAML config schema, the `./dapper`
CLI, environment variables, vulnerability coverage, output layout, and LLM
provider settings — with full field tables, constraints, and copy-paste
examples. These pages mirror the source of truth in the repo
(`configs/config-schema.json`, the `dapper` script, `.env.example`, and
`COVERAGE.md`), so a developer can rely on them without reading the code.

If you are just getting started, begin with the
[Get started]({{ '/get-started' | relative_url }}) and
[Guides]({{ '/guides' | relative_url }}) sections; come back here when you
need exact field names, defaults, and constraints.

<div class="card-grid" markdown="0">
  <a class="card" href="{{ '/reference/configuration' | relative_url }}">
    <div class="card-kicker">Config</div>
    <div class="card-title">Configuration</div>
    <div class="card-desc">The full YAML schema: auth, login flows, focus/avoid rules.</div>
  </a>
  <a class="card" href="{{ '/reference/output-deliverables' | relative_url }}">
    <div class="card-kicker">Output</div>
    <div class="card-title">Output &amp; deliverables</div>
    <div class="card-desc">The audit-logs structure: reports, metrics, and agent logs.</div>
  </a>
  <a class="card" href="{{ '/reference/cli' | relative_url }}">
    <div class="card-kicker">CLI</div>
    <div class="card-title">CLI commands</div>
    <div class="card-desc">Every command and flag for the <code>./dapper</code> script.</div>
  </a>
  <a class="card" href="{{ '/reference/environment-variables' | relative_url }}">
    <div class="card-kicker">Env</div>
    <div class="card-title">Environment variables</div>
    <div class="card-desc">Credentials, providers, and web-console settings.</div>
  </a>
  <a class="card" href="{{ '/reference/vulnerability-coverage' | relative_url }}">
    <div class="card-kicker">Coverage</div>
    <div class="card-title">Vulnerability coverage</div>
    <div class="card-desc">What Dapper finds and exploits, mapped to OWASP WSTG.</div>
  </a>
  <a class="card" href="{{ '/reference/llm-providers' | relative_url }}">
    <div class="card-kicker">Models</div>
    <div class="card-title">LLM providers</div>
    <div class="card-desc">Anthropic by default; experimental router mode for others.</div>
  </a>
</div>
