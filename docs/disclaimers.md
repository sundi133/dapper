---
title: Disclaimers
parent: Resources
nav_order: 5
permalink: /resources/disclaimers
---

# Disclaimers
{: .no_toc }

Please review these guidelines carefully before using Dapper Lite. Dapper is
an **active exploitation tool, not a passive scanner** — it executes real
attacks to prove vulnerabilities. As a user, you are responsible for your
actions and assume all liability. The two rules that matter most: only test
systems you are authorized to test, and never point it at production.

1. TOC
{:toc}

## Potential for mutative effects — pick the right environment

Dapper is **not a passive scanner**. The exploitation agents are designed to
actively execute attacks to confirm vulnerabilities. This process can have
mutative effects on the target application and its data.

{: .warning }
**Do NOT run Dapper on production environments.**
It is intended exclusively for sandboxed, staging, or local development
environments where data integrity is not a concern. Potential mutative
effects include — but are not limited to — creating new users, modifying or
deleting data, compromising test accounts, and triggering unintended side
effects from injection attacks.

{: .tip }
> See [Security & privacy]({{ '/resources/security-privacy' | relative_url }})
> for where your code and data go, and the [FAQ]({{ '/resources/faq' | relative_url }})
> for adoption questions.

## Legal & ethical use

Dapper is designed for **legitimate security auditing purposes only.** Only run
it against systems you **own or have explicit written permission to test.**
Running active exploitation against systems you are not authorized to test may
be illegal in your jurisdiction — authorization is your responsibility, not
Dapper's.

## LLM & automation caveats

- **Verification is required.** Significant engineering has gone into our
  proof-by-exploitation methodology to eliminate false positives, but the
  underlying LLMs can still generate hallucinated or weakly-supported
  content in the final report. **Human oversight is essential** to validate
  the legitimacy and severity of all reported findings.
- **Comprehensiveness.** Analysis in Dapper Lite may not be exhaustive due
  to LLM context-window limits. For comprehensive, graph-based analysis of
  your entire codebase, **Dapper Pro** uses an advanced data flow analysis
  engine for deeper, more thorough coverage.

## Scope of analysis

**Targeted vulnerabilities.** Dapper Lite specifically targets *exploitable*
classes:

- Broken Authentication & Authorization
- Injection
- Cross-Site Scripting (XSS)
- Server-Side Request Forgery (SSRF)

**What Dapper Lite does NOT cover.** The proof-by-exploitation model means
Dapper will not report issues it cannot actively exploit. Out of scope for
Lite:

- Vulnerable third-party libraries and dependencies.
- Weak or misused cryptography and weak encryption algorithms.
- Insecure configurations and other static-analysis findings.
- Business-logic flaws outside the targeted vulnerability classes.

These deeper static-analysis findings are the focus of the advanced data-flow
analysis engine in **Dapper Pro**. The full mapping of what Lite consistently
catches against the OWASP WSTG checklist is in
[Coverage and roadmap](https://github.com/sundi133/dapper/blob/main/COVERAGE.md).

{: .note }
> Dapper is built on the Claude Agent SDK and is **optimized and primarily
> tested with Anthropic's Claude models.** The experimental router mode for
> OpenAI, OpenRouter, and Ollama is unsupported and may produce inconsistent
> results — see [LLM providers]({{ '/reference/llm-providers' | relative_url }}).

## Cost & performance

- **Time.** A full run typically takes **1 to 1.5 hours**.
- **Cost.** A full run on Anthropic's Claude Sonnet may incur costs of
  approximately **$50 USD**. Costs vary based on model pricing and
  application complexity. Use `PIPELINE_TESTING=true` for a fast, low-cost
  smoke test.

## Windows antivirus false positives

Windows Defender may flag files in `xben-benchmark-results/` or
`deliverables/` as malware. These are **false positives** caused by the real
exploit code embedded in the reports. Add an exclusion for the Dapper
directory in Windows Defender, or run Dapper inside WSL2 / Docker. See
[Troubleshooting]({{ '/resources/troubleshooting' | relative_url }}).

## License

Dapper Lite is released under the
[GNU Affero General Public License v3.0 (AGPL-3.0)](https://github.com/sundi133/dapper/blob/main/LICENSE).
This license allows you to:

- Use it freely for all internal security testing.
- Modify the code privately for internal use without sharing your changes.

AGPL's sharing requirements primarily apply to organizations offering
Dapper as a public or managed service (a SaaS platform). In those cases,
any modifications to the core software must be open-sourced.

## Get in touch

Interested in **Dapper Pro** — designed for organizations serious about
application security, with enterprise-grade features, dedicated support,
and CI/CD integration?

📧 [info@votal.ai](mailto:info@votal.ai) ·
[Express interest →](https://votal.ai/contact/)
