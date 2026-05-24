---
title: Disclaimers
nav_order: 9
---

# Disclaimers
{: .no_toc }

Please review these guidelines carefully before using Dapper Lite. As a
user, you are responsible for your actions and assume all liability.

1. TOC
{:toc}

## 1. Potential for mutative effects — pick the right environment

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

## 2. Legal & ethical use

Dapper is designed for legitimate security auditing purposes only. Only run
it against systems you own or have explicit written permission to test.

## 3. LLM & automation caveats

- **Verification is required.** Significant engineering has gone into our
  proof-by-exploitation methodology to eliminate false positives, but the
  underlying LLMs can still generate hallucinated or weakly-supported
  content in the final report. **Human oversight is essential** to validate
  the legitimacy and severity of all reported findings.
- **Comprehensiveness.** Analysis in Dapper Lite may not be exhaustive due
  to LLM context-window limits. For comprehensive, graph-based analysis of
  your entire codebase, **Dapper Pro** uses an advanced data flow analysis
  engine for deeper, more thorough coverage.

## 4. Scope of analysis

**Targeted vulnerabilities.** Dapper Lite specifically targets *exploitable*
classes:

- Broken Authentication & Authorization
- Injection
- Cross-Site Scripting (XSS)
- Server-Side Request Forgery (SSRF)

**What Dapper Lite does NOT cover.** The proof-by-exploitation model means
Dapper will not report issues it cannot actively exploit — vulnerable
third-party libraries, insecure configurations, and similar findings are
the focus of the advanced analysis engine in **Dapper Pro**.

## 5. Cost & performance

- **Time.** A full run typically takes **1 to 1.5 hours**.
- **Cost.** A full run on Anthropic's Claude 4.5 Sonnet may incur costs of
  approximately **$50 USD**. Costs vary based on model pricing and
  application complexity.

## 6. License

Dapper Lite is released under the
[GNU Affero General Public License v3.0 (AGPL-3.0)](https://github.com/sundi133/dapper/blob/main/LICENSE).
This license allows you to:

- Use it freely for all internal security testing.
- Modify the code privately for internal use without sharing your changes.

AGPL's sharing requirements primarily apply to organizations offering
Dapper as a public or managed service (a SaaS platform). In those cases,
any modifications to the core software must be open-sourced.

## 7. Get in touch

Interested in **Dapper Pro** — designed for organizations serious about
application security, with enterprise-grade features, dedicated support,
and CI/CD integration?

📧 [info@votal.ai](mailto:info@votal.ai) ·
[Express interest →](https://votal.ai/contact/)
