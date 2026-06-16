---
title: Authenticated testing
parent: Guides
nav_order: 2
permalink: /guides/authenticated-testing
---

# Authenticated testing
{: .no_toc }

Most of an application's attack surface sits behind a login. Dapper authenticates itself — form logins, SSO, API tokens, HTTP Basic, and two-factor — from a small YAML `authentication` block in your config.

1. TOC
{:toc}

---

## How it works

You describe the login the way you'd brief a teammate: where the login page is, what credentials to use, and the steps to get in. Dapper drives a real browser through those steps, then checks a **success condition** to confirm it actually got in before any testing begins. Pass the config with `CONFIG`:

```bash
./dapper start URL=https://staging.your-app.com REPO=your-app \
               CONFIG=./configs/your-app.yaml
```

An `authentication` block has four required fields and one optional one:

| Field | Required | Description |
|:------|:---------|:------------|
| `login_type` | yes | One of `form`, `sso`, `api`, `basic`. |
| `login_url` | yes | The login page or auth endpoint (a full URI). |
| `credentials` | yes | `username` and `password` (both required), plus optional `totp_secret`. |
| `success_condition` | yes | How Dapper confirms it's authenticated. |
| `login_flow` | no | Step-by-step instructions (1–20 steps) for browser-driven logins. |

{: .danger }
> Point Dapper at a **test account on a staging environment**. Authenticated testing exercises destructive actions — it may create, modify, or delete data for the logged-in user.

## Credentials and placeholders

Credentials live under `credentials`. In `login_flow` steps, reference them with placeholders so the raw values never appear in step text or logs:

| Placeholder | Substituted with |
|:------------|:-----------------|
| `$username` | `credentials.username` |
| `$password` | `credentials.password` |
| `$totp` | A fresh TOTP code computed from `credentials.totp_secret` |

```yaml
credentials:
  username: "test@example.com"
  password: "your-password"
  totp_secret: "JBSWY3DPEHPK3PXP"   # optional, Base32
```

{: .tip }
> Keep secrets out of git. Template the config and inject credentials from environment/CI variables at runtime — see [CI/CD integration]({{ '/guides/cicd' | relative_url }}).

## The login flow

`login_flow` is an ordered list of natural-language steps (1–20). Each is an instruction Dapper carries out in the browser, in order. Be specific about field labels and button text so the agent targets the right elements:

```yaml
login_flow:
  - "Type $username into the email field"
  - "Type $password into the password field"
  - "Click the 'Sign In' button"
```

For `api` and `basic` logins, where there's no page to click through, you can omit `login_flow` entirely and let Dapper handle the mechanism from `login_type` and `login_url`.

## The four login types

| `login_type` | Use for |
|:-------------|:--------|
| `form` | Standard username/password forms rendered in the browser. |
| `sso` | Single sign-on / OAuth flows, including "Sign in with Google" style redirects. |
| `api` | Token- or endpoint-based authentication (no interactive page). |
| `basic` | HTTP Basic auth (the browser credential dialog). |

### `form` + two-factor (TOTP)

The most common case. Add `totp_secret` (Base32) and a step that enters `$totp`; Dapper computes the current code itself via the [`generate_totp` tool]({{ '/concepts/mcp-tooling' | relative_url }}) — you never paste a code.

```yaml
authentication:
  login_type: form
  login_url: "https://staging.your-app.com/login"
  credentials:
    username: "test@example.com"
    password: "your-password"
    totp_secret: "JBSWY3DPEHPK3PXP"
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

Omit `totp_secret` and the `$totp` step for a plain form login without 2FA.

### `sso`

Describe the redirect dance step by step — clicking the SSO button, landing on the identity provider, entering credentials there, and being sent back. The `login_url` is your app's login page (where the SSO button lives).

```yaml
authentication:
  login_type: sso
  login_url: "https://staging.your-app.com/login"
  credentials:
    username: "test@corp-idp.example"
    password: "your-idp-password"
    totp_secret: "JBSWY3DPEHPK3PXP"   # if the IdP enforces 2FA
  login_flow:
    - "Click the 'Sign in with SSO' button"
    - "On the identity provider page, type $username into the email field"
    - "Click 'Next'"
    - "Type $password into the password field"
    - "Click 'Sign in'"
    - "Enter $totp in the authenticator code field if prompted"
    - "Approve the consent screen if shown"
  success_condition:
    type: element_present
    value: "nav[data-testid='user-menu']"
```

### `api`

For token-based APIs there's no page to drive — point `login_url` at the auth endpoint and describe how to obtain and use the token.

```yaml
authentication:
  login_type: api
  login_url: "https://staging.your-app.com/api/v1/auth/login"
  credentials:
    username: "service-tester"
    password: "your-api-password"
  login_flow:
    - "POST $username and $password as JSON to the login endpoint"
    - "Read the returned token from the 'access_token' field"
    - "Send it as an 'Authorization: Bearer <token>' header on subsequent requests"
  success_condition:
    type: text_contains
    value: "access_token"
```

### `basic`

HTTP Basic auth needs only credentials and the protected URL.

```yaml
authentication:
  login_type: basic
  login_url: "https://staging.your-app.com/admin"
  credentials:
    username: "admin"
    password: "your-basic-password"
  success_condition:
    type: url_contains
    value: "/admin"
```

## Confirming success

The `success_condition` tells Dapper its login attempt actually worked — without it, the agent might test an app it never logged into. Pick whichever signal is unambiguous for your app:

| `type` | Matches when… | Example `value` |
|:-------|:--------------|:----------------|
| `url_contains` | The post-login URL contains a substring. | `/dashboard` |
| `url_equals_exactly` | The URL matches exactly. | `https://app.example.com/home` |
| `element_present` | A specific element appears on the page (CSS selector). | `nav[data-testid='user-menu']` |
| `text_contains` | The page contains given text. | `Welcome back` |

Both `type` and `value` are required, and `value` is capped at 500 characters.

## Multiple accounts for authz testing

To exercise authorization flaws (privilege escalation, IDOR), give Dapper extra accounts with roles via the top-level `accounts` list. The primary login still comes from `authentication`; these are additional identities for comparison.

```yaml
accounts:
  - role: "admin"
    username: "admin@example.com"
    password: "admin-password"
    totp_secret: "JBSWY3DPEHPK3PXP"
  - role: "viewer"
    username: "viewer@example.com"
    password: "viewer-password"
```

## Scoping the authenticated surface

Pair authentication with `rules` so Dapper doesn't, for example, log itself out mid-run:

```yaml
rules:
  avoid:
    - description: "Don't hit logout — it kills our session"
      type: path
      url_path: "/logout"
  focus:
    - description: "Prioritise the authenticated admin area"
      type: path
      url_path: "/admin"
```

See the full [Configuration reference]({{ '/reference/configuration' | relative_url }}) for every field, and [Running a pentest]({{ '/guides/running-a-pentest' | relative_url }}) for the launch lifecycle.
