---
title: Sample reports
parent: Resources
nav_order: 1
permalink: /resources/sample-reports
---

# Sample reports
{: .no_toc }

1. TOC
{:toc}

These are real assessments Dapper ran against three industry-standard
vulnerable applications. Each report only includes findings Dapper
**actually exploited** — every entry ships with the request used, the
response observed, and the impact proven. Nothing here is a "potential"
finding from a scanner; the reports follow Dapper's "No Exploit, No Report"
policy.

All three runs scoped the same vulnerability classes: **Authentication,
Authorization, SQL and Command Injection, XSS, and SSRF.** Two of the three
targets are APIs with strong XSS defenses — and Dapper correctly reported
**zero XSS false positives** on both, which is as important a result as the
exploits it did land.

{: .note }
**Looking for quantitative benchmarks?** See the
[full benchmark methodology and results](https://github.com/sundi133/dapper/tree/main/xben-benchmark-results).

## At a glance

| Target | Type | XSS result | Notable proven impact |
|:-------|:-----|:-----------|:----------------------|
| OWASP Juice Shop | Insecure web app | Reflected + JSONP XSS exploited | Auth bypass → full DB exfiltration, admin account creation, IDOR, SSRF |
| c{api}tal API | Vulnerable REST API | No XSS (correctly cleared) | Root RCE via command injection, legacy-endpoint auth bypass, mass-assignment privilege escalation |
| OWASP crAPI | Vulnerable microservice API | No XSS (correctly cleared) | JWT algorithm-confusion / `alg:none` / `kid` injection, PostgreSQL + MongoDB injection, SSRF with header forwarding |

## 🧃 OWASP Juice Shop

[GitHub](https://github.com/juice-shop/juice-shop) · *A notoriously insecure
web application maintained by OWASP, designed to test a tool's ability to
uncover a wide range of modern vulnerabilities.*

**Scope tested.** Authentication, authorization, SQL/command injection, XSS,
and SSRF against the running Juice Shop instance, guided by source-code
analysis of the Node/Angular codebase.

**Proven findings.** Dapper landed **over 20 high-impact exploits** in a
single run, including:

- **SQL injection authentication bypass** — string interpolation in the login
  query (`/routes/login.ts`) let Dapper log in as `admin@juice-sh.op`
  (user ID 1, role `admin`) without a password, returning a valid admin JWT.
- **Full user-database exfiltration** — UNION-based SQL injection dumped every
  user's email, role, and MD5 password hash, which were then **cracked
  offline**.
- **Privilege escalation via registration** — injecting a `role: admin` field
  during account registration created a brand-new administrator.
- **Systemic IDOR** — horizontal access to *any* user's profile, shopping
  basket, and feedback by incrementing object IDs, plus anonymous access to
  all user "memories."
- **NoSQL operator injection** — a `$ne` operator with `{ multi: true }` enabled
  mass data manipulation across documents.
- **XXE file disclosure** and a **YAML-injection DoS**.
- **Reflected XSS** via Angular's `bypassSecurityTrustHtml()` on the search
  parameter, plus **JSONP-callback XSS** enabling cross-domain data theft.
- **SSRF** in the profile-image-URL upload, bypassing the POST-only guard with
  PUT/PATCH to reach the cloud metadata endpoint
  (`http://169.254.169.254/latest/meta-data/`).

[Read the full report →](https://github.com/sundi133/dapper/blob/main/sample-reports/shannon-report-juice-shop.md)

## 🔗 c{api}tal API

[GitHub](https://github.com/Checkmarx/capital) · *An intentionally vulnerable
API from Checkmarx, designed to test a tool's ability to uncover the OWASP
API Security Top 10.*

**Scope tested.** The same five classes against a React frontend and a
Python API backend. XSS was **correctly cleared** — Dapper confirmed React's
default escaping, the XSS sanitization library, and URL validation, and
reported no XSS findings.

**Proven findings.** Nearly 15 critical/high-severity exploits leading to full
compromise:

- **Root-level command injection** — a hidden debug endpoint accepted an
  allow-listed command, but `uptime; <arbitrary command>` chained past the
  whitelist to run code as **root**, enabling data extraction or destruction.
- **Complete authentication bypass on a legacy v1 endpoint** — the unpatched
  endpoint skipped password validation entirely, allowing login as **any user
  with any password** and immediate account takeover.
- **Mass-assignment privilege escalation** — a regular user promoted their own
  account to administrator by adding an admin flag to the profile-update body
  (captured CTF flag `flag{M4sS_AsS1gnm3nt}`).
- **Horizontal and vertical authorization bypass** — access to other users'
  financial data and to admin-only functions.
- **Session hijacking surface** — JWTs stored in `localStorage` are readable by
  JavaScript, so any XSS would steal sessions.
- **No rate limiting** on login (brute force over 25 attempts) and
  **cleartext-HTTP credential interception** on the backend.
- **SSRF** layered on the command-injection debug endpoint, reaching internal
  services via Python socket connections.

[Read the full report →](https://github.com/sundi133/dapper/blob/main/sample-reports/shannon-report-capital-api.md)

## 🚗 OWASP crAPI

[GitHub](https://github.com/OWASP/crAPI) · *A modern, intentionally
vulnerable API from OWASP, designed to benchmark a tool's effectiveness
against the OWASP API Security Top 10.*

**Scope tested.** The same five classes against crAPI's Java/Python
microservices. XSS was **correctly cleared** — code analysis flagged
potential sinks in ReactMarkdown and Django templates, but exploitation was
blocked by validation and framework protections, so nothing was reported.

**Proven findings.** Dapper exploited **12 vulnerabilities — 8 critical, 2
high, 2 medium** — for full compromise:

- **JWT algorithm-confusion (RS256 → HS256)** — re-signing a token with the
  RSA *public* key as the HMAC secret (`JwtProvider.java`) forged an admin
  token.
- **JWT `alg:none` bypass** — the validator accepted an unsigned token,
  bypassing all cryptographic verification.
- **JWT `kid` header injection** — pointing `kid` at `/dev/null` enabled a
  weak-secret forgery, and a **JKU-header SSRF** vector was also identified.
- **PostgreSQL injection** in coupon validation — full database compromise,
  extracting user credentials and system info.
- **MongoDB NoSQL injection** — a `$ne` operator bypassed query filters to read
  arbitrary coupon data.
- **Authorization bypasses** — unauthenticated access to shop orders containing
  payment data, cross-user access to private forum posts, and regular users
  reaching mechanic-only functionality.
- **SSRF via the contact-mechanic endpoint** — reached internal services and
  the cloud metadata endpoint, **forwarding the caller's authorization header**
  to an attacker-controlled destination, with a built-in retry loop.

[Read the full report →](https://github.com/sundi133/dapper/blob/main/sample-reports/shannon-report-crapi.md)

---

Taken together, these runs show Dapper moving past simple scanning into deep,
contextual exploitation — chaining injection into data exfiltration, abusing
JWT internals, and proving SSRF reaches real internal targets — while keeping
false positives low enough to clear XSS on two hardened APIs.
