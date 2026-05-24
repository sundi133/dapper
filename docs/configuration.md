---
title: Configuration
nav_order: 3
---

# Configuration
{: .no_toc }

1. TOC
{:toc}

You can run Dapper with no configuration file, but creating one unlocks
**authenticated testing** and **scope rules**. Configuration files live in
`./configs/`, which is mounted into the Docker container automatically.

## Create a config file

Copy and modify the example configuration:

```bash
cp configs/example-config.yaml configs/my-app-config.yaml
```

Then pass it on the command line:

```bash
./dapper start URL=https://example.com REPO=repo-name \
  CONFIG=./configs/my-app-config.yaml
```

## Basic structure

```yaml
authentication:
  login_type: form
  login_url: "https://your-app.com/login"
  credentials:
    username: "test@example.com"
    password: "yourpassword"
    totp_secret: "LB2E2RX7XFHSTGCK"   # optional, for 2FA

  login_flow:
    - "Type $username into the email field"
    - "Type $password into the password field"
    - "Click the 'Sign In' button"

  success_condition:
    type: url_contains
    value: "/dashboard"

rules:
  avoid:
    - description: "AI should avoid testing logout functionality"
      type: path
      url_path: "/logout"

  focus:
    - description: "AI should emphasize testing API endpoints"
      type: path
      url_path: "/api"
```

## Authentication

Dapper supports form, SSO, API-key, and basic authentication. The
`login_flow` is a natural-language script the agent follows in a real
browser. `success_condition` tells Dapper how to detect a successful login
(e.g. `url_contains: /dashboard`, presence of an element, etc.).

## TOTP / 2FA

If your application uses two-factor authentication, add the TOTP secret to
your config:

```yaml
authentication:
  credentials:
    totp_secret: "LB2E2RX7XFHSTGCK"
```

Dapper will generate the required 6-digit codes automatically via its
`generate_totp` MCP tool during the login flow — no manual intervention.

## Scope rules

The `rules` section shapes where Dapper looks. `avoid` blocks intrusive
probes against specific paths or features (logout, destructive admin
actions, etc.). `focus` biases the agent toward areas you care about most
(an API surface, a new feature).

## Ready-made configs

See the [`configs/`](https://github.com/sundi133/dapper/tree/main/configs)
folder in the repo for working examples — OWASP Juice Shop, Chatwoot, Cal.com,
Metabase, Keygraph, and others.
