---
title: Sample reports
nav_order: 6
---

# Sample reports
{: .no_toc }

1. TOC
{:toc}

See Dapper's capabilities against industry-standard vulnerable applications.

{: .note }
**Looking for quantitative benchmarks?** See the
[full benchmark methodology and results](https://github.com/sundi133/dapper/tree/main/xben-benchmark-results).

## 🧃 OWASP Juice Shop

[GitHub](https://github.com/juice-shop/juice-shop) · *A notoriously insecure
web application maintained by OWASP, designed to test a tool's ability to
uncover a wide range of modern vulnerabilities.*

**Performance.** Identified **over 20 high-impact vulnerabilities** across
targeted OWASP categories in a single automated run.

**Key results:**

- **Complete authentication bypass** and exfiltrated the entire user
  database via an injection attack.
- **Full privilege escalation** by creating a new administrator account
  through a registration workflow bypass.
- **Systemic authorization flaws (IDOR)** to access and modify any user's
  private data and shopping cart.
- **Server-Side Request Forgery (SSRF)** enabling internal network
  reconnaissance.

[Read the full report →](https://github.com/sundi133/dapper/blob/main/sample-reports/shannon-report-juice-shop.md)

## 🔗 c{api}tal API

[GitHub](https://github.com/Checkmarx/capital) · *An intentionally vulnerable
API from Checkmarx, designed to test a tool's ability to uncover the OWASP
API Security Top 10.*

**Performance.** Identified **nearly 15 critical and high-severity
vulnerabilities**, leading to full application compromise.

**Key results:**

- **Root-level injection** by bypassing a denylist via command chaining in a
  hidden debug endpoint.
- **Complete authentication bypass** by targeting a legacy, unpatched v1 API
  endpoint.
- **Regular user → full administrator** via a Mass Assignment vulnerability
  in the user profile update function.
- **High accuracy** — zero false positives against the app's robust XSS
  defenses.

[Read the full report →](https://github.com/sundi133/dapper/blob/main/sample-reports/shannon-report-capital-api.md)

## 🚗 OWASP crAPI

[GitHub](https://github.com/OWASP/crAPI) · *A modern, intentionally
vulnerable API from OWASP, designed to benchmark a tool's effectiveness
against the OWASP API Security Top 10.*

**Performance.** Identified **over 15 critical and high-severity
vulnerabilities**, achieving full application compromise.

**Key results:**

- **Multiple advanced JWT attacks** — Algorithm Confusion, `alg:none`, and
  weak `kid` injection.
- **Full database compromise** via injection attacks, exfiltrating user
  credentials from PostgreSQL.
- **Critical SSRF** that successfully forwarded internal authentication
  tokens to an external service.
- **High accuracy** against the app's robust XSS defenses (zero false
  positives).

[Read the full report →](https://github.com/sundi133/dapper/blob/main/sample-reports/shannon-report-crapi.md)

---

*These results demonstrate Dapper's ability to move beyond simple scanning,
performing deep contextual exploitation with minimal false positives and
actionable proof-of-concepts.*
