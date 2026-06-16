---
title: Configuration
parent: Reference
nav_order: 1
permalink: /reference/configuration
---

# Configuration
{: .no_toc }

The complete reference for the Dapper YAML configuration file. A config is
optional — Dapper runs without one — but it unlocks
[authenticated testing]({{ '/guides/authenticated-testing' | relative_url }})
and lets you constrain or steer the scope of a run. Config files live in
`./configs/`, which is mounted into the Docker container automatically, and
are validated against a JSON Schema (`configs/config-schema.json`) before a
run starts.

1. TOC
{:toc}

---

## Using a config file

Copy the bundled example and edit it:

```bash
cp configs/example-config.yaml configs/my-app-config.yaml
```

Pass it to `start` with `CONFIG`:

```bash
./dapper start URL=https://example.com REPO=repo-name \
  CONFIG=./configs/my-app-config.yaml
```

{: .note }
> The file is validated against `configs/config-schema.json` at startup.
> A malformed config (unknown field, wrong type, missing required key)
> fails fast with a schema error rather than starting a partial run.

## Top-level structure

A config is a single YAML object. At least one of `authentication` or
`rules` must be present (`anyOf` in the schema); all other sections are
optional. Unknown top-level keys are rejected.

| Field | Type | Required | Description |
|:------|:-----|:--------:|:------------|
| `authentication` | object | conditional | Credentials and login flow for authenticated testing. Required unless `rules` is provided. |
| `rules` | object | conditional | Scope rules (`avoid` / `focus`). Required unless `authentication` is provided. |
| `coverage` | object | | Breadth-vs-precision controls for what gets reported. |
| `targets` | array&lt;string&gt; | | Additional entry points (subdomains, services, APIs) to include. Max 100. |
| `accounts` | array&lt;object&gt; | | Extra test accounts with roles for richer authorization coverage. Max 50. |
| `seed_data` | array&lt;string&gt; | | Seed data / setup instructions for richer workflows. Max 200 items, each ≤ 2000 chars. |
| `exploration` | object | | Limits for deeper dynamic testing (depth, request budget, time). |
| `schemas` | object | | API schema locations (OpenAPI / GraphQL) to expand dynamic coverage. |
| `login` | object | | **Deprecated.** Use `authentication` instead. |

```yaml
authentication: { ... }
rules:          { ... }
coverage:       { ... }
targets:        [ ... ]
accounts:       [ ... ]
seed_data:      [ ... ]
exploration:    { ... }
schemas:        { ... }
```

---

## `authentication`

Configures how the agent logs into the target. All four child fields are
required when the `authentication` section is present. Unknown keys are
rejected.

| Field | Type | Required | Constraints |
|:------|:-----|:--------:|:------------|
| `login_type` | string (enum) | ✓ | One of `form`, `sso`, `api`, `basic`. |
| `login_url` | string (URI) | ✓ | URL of the login page or endpoint. |
| `credentials` | object | ✓ | See [credentials](#credentials). |
| `login_flow` | array&lt;string&gt; | | 1–20 steps, each 1–500 chars. See [login_flow](#login_flow). |
| `success_condition` | object | ✓ | See [success_condition](#success_condition). |

### `login_type`

The authentication mechanism the target uses.

| Value | Meaning |
|:------|:--------|
| `form` | Standard HTML login form (username/password fields, submit button). |
| `sso` | Single sign-on / federated identity flow. |
| `api` | Token- or key-based API authentication. |
| `basic` | HTTP Basic authentication. |

### `credentials`

The login secrets. `username` and `password` are required; `totp_secret`
is optional. No other keys are allowed.

| Field | Type | Required | Constraints |
|:------|:-----|:--------:|:------------|
| `username` | string | ✓ | 1–255 chars. Username or email. |
| `password` | string | ✓ | 1–255 chars. |
| `totp_secret` | string | | Base32, case-insensitive. Must match the pattern `^[A-Za-z2-7]+=*$`. |

```yaml
credentials:
  username: "test@example.com"
  password: "yourpassword"
  totp_secret: "JBSWY3DPEHPK3PXP"   # optional, Base32
```

The `totp_secret` pattern allows the Base32 alphabet (`A–Z`, `2–7`) with
optional trailing `=` padding. When present, Dapper generates the 6-digit
codes automatically through its `generate_totp` MCP tool during the login
flow — no manual entry. See [TOTP / 2FA](#totp--2fa).

### `login_flow`

An ordered list of natural-language steps the agent performs in a real
browser to authenticate. Each step is a string (1–500 chars); 1–20 steps
allowed. The placeholders `$username`, `$password`, and `$totp` are
substituted with the corresponding credential values at runtime.

```yaml
login_flow:
  - "Type $username into the email field"
  - "Type $password into the password field"
  - "Click the 'Sign In' button"
  - "Enter $totp in the verification code field"
  - "Click 'Verify'"
```

### `success_condition`

How Dapper confirms a login succeeded. Both fields are required; no other
keys are allowed.

| Field | Type | Required | Constraints |
|:------|:-----|:--------:|:------------|
| `type` | string (enum) | ✓ | One of `url_contains`, `element_present`, `url_equals_exactly`, `text_contains`. |
| `value` | string | ✓ | 1–500 chars. The value matched against the chosen condition type. |

| `type` | Succeeds when… |
|:-------|:---------------|
| `url_contains` | The post-login URL contains `value` (e.g. `/dashboard`). |
| `url_equals_exactly` | The URL exactly equals `value`. |
| `element_present` | An element matching `value` (e.g. a selector) is present on the page. |
| `text_contains` | The page text contains `value`. |

```yaml
success_condition:
  type: url_contains
  value: "/dashboard"
```

### Full authentication example

```yaml
authentication:
  login_type: form
  login_url: "https://your-app.com/login"
  credentials:
    username: "test@example.com"
    password: "yourpassword"
    totp_secret: "LB2E2RX7XFHSTGCK"
  login_flow:
    - "Type $username into the email field"
    - "Type $password into the password field"
    - "Click the 'Sign In' button"
    - "Enter $totp in the verification code field"
    - "Click 'Verify'"
  success_condition:
    type: url_contains
    value: "/dashboard"
```

---

## `rules`

Scope rules shape where Dapper looks. Both sub-arrays are optional but each
is capped at 50 entries. Unknown keys are rejected.

| Field | Type | Required | Constraints |
|:------|:-----|:--------:|:------------|
| `avoid` | array&lt;rule&gt; | | Areas to exclude from testing. Max 50. |
| `focus` | array&lt;rule&gt; | | Areas to prioritize. Max 50. |

### Rule object

Every entry in `avoid` and `focus` is the same shape. All three fields are
required.

| Field | Type | Required | Constraints |
|:------|:-----|:--------:|:------------|
| `description` | string | ✓ | 1–200 chars. Human-readable explanation. |
| `type` | string (enum) | ✓ | One of `path`, `subdomain`, `domain`, `method`, `header`, `parameter`. |
| `url_path` | string | ✓ | 1–1000 chars. The pattern/value to match against (per `type`). |

```yaml
rules:
  avoid:
    - description: "Do not test the marketing site subdomain"
      type: subdomain
      url_path: "www"
    - description: "Skip logout functionality"
      type: path
      url_path: "/logout"
    - description: "No DELETE operations on user API"
      type: path
      url_path: "/api/v1/users/*"
  focus:
    - description: "Prioritize beta admin panel subdomain"
      type: subdomain
      url_path: "beta-admin"
    - description: "Focus on user profile updates"
      type: path
      url_path: "/api/v2/user-profile"
```

`avoid` blocks intrusive probes against sensitive paths or features (logout,
destructive admin actions). `focus` biases the agent toward the areas you
care about most (an API surface, a new feature).

---

## `coverage`

Controls breadth versus precision of the findings that get reported.
Unknown keys are rejected.

| Field | Type | Required | Constraints |
|:------|:-----|:--------:|:------------|
| `mode` | string (enum) | | `precision` or `coverage`. |
| `include_potential` | boolean | | Include potential (non-exploit-verified) findings. |
| `include_headers_tls` | boolean | | Include security-header, TLS, and HSTS checks. |
| `include_sast_sca` | boolean | | Include static code / dependency findings when available. |
| `max_findings` | integer | | Optional cap on total findings. 1–10000. |

| `mode` | Behavior |
|:-------|:---------|
| `precision` | Reports only exploit-verified findings. |
| `coverage` | Adds potential findings and misconfigurations on top of verified ones. |

```yaml
coverage:
  mode: coverage
  include_potential: true
  include_headers_tls: true
  include_sast_sca: false
  max_findings: 200
```

---

## `targets`

Additional entry points to bring into scope — subdomains, services, or APIs
beyond the primary `URL`. Array of strings (each 1–2000 chars), max 100.

```yaml
targets:
  - "https://api.example.com"
  - "https://admin.example.com"
```

## `accounts`

Extra test accounts with roles, used to exercise authorization paths (one
role accessing another role's data). Max 50 entries.

| Field | Type | Required | Constraints |
|:------|:-----|:--------:|:------------|
| `role` | string | ✓ | 1–100 chars. |
| `username` | string | ✓ | 1–255 chars. |
| `password` | string | ✓ | 1–255 chars. |
| `totp_secret` | string | | Base32, pattern `^[A-Za-z2-7]+=*$`. |

```yaml
accounts:
  - role: "admin"
    username: "admin@example.com"
    password: "adminpass"
  - role: "viewer"
    username: "viewer@example.com"
    password: "viewerpass"
```

## `seed_data`

Free-form setup instructions or seed data to enable richer workflows
(e.g. "create a project named X before testing"). Array of strings (each
1–2000 chars), max 200.

```yaml
seed_data:
  - "Create a sample project named 'demo' before testing"
  - "Upload a test file under Documents"
```

## `exploration`

Limits for deeper dynamic testing. Unknown keys are rejected.

| Field | Type | Constraints |
|:------|:-----|:------------|
| `max_depth` | integer | 1–20. Crawl/exploration depth. |
| `max_requests` | integer | 100–100000. Request budget. |
| `recon_minutes` | integer | 5–1440. Time budget for reconnaissance. |
| `exploit_minutes` | integer | 5–1440. Time budget for exploitation. |

```yaml
exploration:
  max_depth: 5
  max_requests: 5000
  recon_minutes: 30
  exploit_minutes: 60
```

## `schemas`

API schema locations that expand dynamic coverage. Unknown keys are
rejected.

| Field | Type | Constraints |
|:------|:-----|:------------|
| `openapi_urls` | array&lt;string&gt; | Each 1–2000 chars, max 50. |
| `graphql_endpoints` | array&lt;string&gt; | Each 1–2000 chars, max 50. |

```yaml
schemas:
  openapi_urls:
    - "https://api.example.com/openapi.json"
  graphql_endpoints:
    - "https://api.example.com/graphql"
```

## `login` (deprecated)

The `login` section is **deprecated**. Use [`authentication`](#authentication)
instead. It remains in the schema only for backward compatibility.

---

## TOTP / 2FA

If the target uses two-factor authentication, supply the Base32 TOTP secret
in `credentials.totp_secret` (or per-account in `accounts[].totp_secret`):

```yaml
authentication:
  credentials:
    totp_secret: "LB2E2RX7XFHSTGCK"
```

Dapper generates the required 6-digit codes automatically through its
`generate_totp` MCP tool during the login flow, so no manual intervention
is needed. Reference `$totp` in a `login_flow` step to place the code.

## Ready-made configs

The [`configs/`](https://github.com/sundi133/dapper/tree/main/configs)
folder in the repo holds working examples — OWASP Juice Shop, Chatwoot,
Cal.com, Metabase, Keygraph, and others — plus `config-schema.json`, the
authoritative schema this page documents.
