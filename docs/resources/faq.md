---
title: FAQ
parent: Resources
nav_order: 4
permalink: /resources/faq
---

# Frequently asked questions
{: .no_toc }

1. TOC
{:toc}

---

The questions teams ask most often before adopting Dapper, grouped by theme.
If you want to see what a run produces first, read the
[Sample reports]({{ '/resources/sample-reports' | relative_url }}); for the
formal scope and legal terms, see [Disclaimers]({{ '/resources/disclaimers' | relative_url }}).

## What it is and how it fits

### How is Dapper different from a scanner like Burp?

Burp is a toolkit a skilled human drives; it surfaces *potential* issues to triage. Dapper replaces the operator — it reads your source, decides what to attack, drives a browser, exploits, and writes the report autonomously, reporting only what it actually broke into. Think of it as a pentester that carries its own tools, not a replacement for the toolkit.

### Does it replace our annual penetration test?

No — it complements it. A human deep-dive is a point-in-time audit with creativity and business-logic judgment Dapper doesn't claim to match. Dapper's value is **continuous coverage on every deploy in between** those audits, closing the gap where you'd otherwise ship unreviewed code for months. Shift security left; don't fire your pentester.

### White-box or black-box — which is it?

Both, deliberately. Dapper is a **white-box** tool at heart: it reads your source code to decide *what* to attack and *where* the dangerous sinks are, then validates each hypothesis with **black-box** dynamic exploitation against the running app. Combining the two is what keeps false positives low.

### Can it test an app I don't have the source for?

Dapper Lite is **white-box only** — it expects access to your application's source code and repository layout, and a run requires both a `URL=` target and a `REPO=` folder. It reads your source to decide what to attack, so source access isn't optional.

### Which languages and frameworks are supported?

It's framework-agnostic for web applications. Rather than relying on language-specific rules, it reasons about your source and the live HTTP behavior, so it works across stacks (the sample reports cover Node/Angular, Python, and Java targets).

## Coverage and accuracy

### What does Dapper test for?

The current version targets *exploitable* instances of: **Broken Authentication & Authorization, SQL and Command Injection, Cross-Site Scripting (XSS), and Server-Side Request Forgery (SSRF).** See the [Coverage and roadmap](https://github.com/sundi133/dapper/blob/main/COVERAGE.md) checklist mapped to OWASP WSTG.

### What does Dapper *not* cover?

By design it only reports what it can **actively exploit**. Static-analysis findings — vulnerable third-party libraries, weak cryptography, insecure configurations — are out of scope for Dapper Lite. Business-logic flaws beyond the targeted classes are also not guaranteed. See [Disclaimers]({{ '/resources/disclaimers' | relative_url }}).

### How does it avoid false positives?

It enforces a **"No Exploit, No Report"** policy: a hypothesized vulnerability is only reported if an exploit agent actually demonstrates impact. In the sample runs, Dapper correctly cleared XSS on two hardened APIs (zero false positives) rather than flagging unproven sinks. That said — see the verification note below.

### Do I still need to verify the findings?

Yes. The proof-by-exploitation model removes most noise, but the underlying LLMs can still produce hallucinated or weakly-supported content. **Human oversight is essential** to confirm the legitimacy and severity of each finding before you act on it.

## Safety and privacy

### Is my source code or data safe?

Everything runs locally in your own Docker environment. The only data that leaves your machine is the **LLM API calls** to your chosen provider, plus the assessment traffic to the target you point it at. Your repository is never uploaded to Votal. For zero code egress, run a local model — see [Security & privacy]({{ '/resources/security-privacy' | relative_url }}).

### Why can't I run it on production?

Dapper's exploitation agents execute **real attacks** — they may create users, modify or delete data, and trigger injection side effects. Run it against **staging, sandbox, or local** environments only, and authenticate with a disposable test account.

## Operating it

### What does a run cost, and how long does it take?

A full run typically takes **1 to 1.5 hours**. Running on Anthropic's Claude Sonnet may incur roughly **$50 USD** in API cost, varying with model pricing and application complexity. Use `PIPELINE_TESTING=true` for a fast, low-cost smoke test during setup.

### Does it handle SSO and 2FA logins?

Yes — form, SSO (including "Sign in with Google"), API, and basic auth, plus TOTP-based 2FA. You describe the flow in a YAML config and Dapper generates the TOTP codes itself during the run. See [Authenticated testing]({{ '/guides/authenticated-testing' | relative_url }}).

### What if a run crashes halfway through?

The pipeline runs on **Temporal**, so it's durable — it resumes from its last checkpoint and automatically retries transient and billing errors. You won't lose a long run to a single hiccup, and a worker restart re-attaches to the in-flight workflow.

### Do I have to use Anthropic's models?

It's strongly recommended. Dapper is built on the Claude Agent SDK and tuned for Claude. An **experimental, unsupported** router mode adds OpenAI, OpenRouter (Gemini), and local Ollama models, but quality varies and early phases may fail. See [LLM providers]({{ '/reference/llm-providers' | relative_url }}).

## Editions and licensing

### What's the difference between Dapper Lite and Dapper Pro?

**Dapper Lite** (this repository, AGPL-3.0) is the core autonomous pentesting framework for the vulnerability classes above. **Dapper Pro** (commercial) adds an LLM-powered data-flow analysis engine for deeper, graph-based code analysis, broader detection, CI/CD integration, and dedicated support. Lite's analysis can be limited by LLM context windows; Pro is built to cover the full codebase.

### How is Dapper Lite licensed?

Under the **AGPL-3.0**. You can use it freely for internal security testing and modify it privately for internal use without sharing changes. The AGPL's sharing requirements primarily apply if you offer Dapper as a public or managed service. See [Disclaimers]({{ '/resources/disclaimers' | relative_url }}).
