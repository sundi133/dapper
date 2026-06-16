---
title: The web console
parent: Guides
nav_order: 4
permalink: /guides/web-console
---

# The web console
{: .no_toc }

Everything you can do from the command line, you can also do from a browser. The web console gives you a launch form, live streaming findings, a chat with the running agent, searchable run history, and CI/CD wiring — all in one place.

1. TOC
{:toc}

---

## Launch it

```bash
./dapper web                 # -> http://localhost:8000
./dapper web HOST=0.0.0.0 PORT=8080
```

Open `http://localhost:8000`. The console runs the LangChain **DeepAgents** orchestrator (a sibling of the Temporal pipeline behind `./dapper start`) and is served by FastAPI/uvicorn.

| Variable | Default | Effect |
|:---------|:--------|:-------|
| `HOST` | `0.0.0.0` | Interface to bind. |
| `PORT` | `8000` | Port to serve on. |
| `PYTHON` | `python3` | Python interpreter to launch uvicorn with. |

The console reads `ANTHROPIC_API_KEY` from `.env`. If it isn't set, the Start form shows a warning and refuses to launch a run.

The interface has three tabs across the top — **Start**, **Runs**, and **CI/CD** — plus a "Sign out" link when authentication is enabled.

## Authentication

By default the console is fully open — appropriate for a local-only Docker install where there's nothing exposed to protect. To require a login, set a password in `.env`:

```bash
DAPPER_WEB_USERNAME=admin                 # optional, defaults to "admin"
DAPPER_WEB_PASSWORD=change-me-to-something-long
DAPPER_SESSION_SECRET=<random-string>     # optional but recommended
```

| Variable | Behaviour |
|:---------|:----------|
| `DAPPER_WEB_PASSWORD` | When set, the whole UI requires a username + password sign-in. When unset, the gate is disabled. |
| `DAPPER_WEB_USERNAME` | The expected username. Defaults to `admin`. |
| `DAPPER_SESSION_SECRET` | Signs the session cookie. If unset, a random value is generated at startup, which invalidates all logins on every restart. Set a stable value to keep sessions alive across restarts. |

Sessions are stateless HMAC-signed cookies with a 7-day TTL — there's no per-user database. The `/api/scans` CI endpoint is gated separately by Bearer token (see [CI/CD](#the-cicd-tab) below).

{: .tip }
> Generate a session secret with `python -c "import secrets; print(secrets.token_urlsafe(32))"`.

{: .warning }
> Binding to `0.0.0.0` exposes the console on your network. If you do that, always set `DAPPER_WEB_PASSWORD`, and ideally run behind an HTTPS reverse proxy.

## The Start tab

Launch a new assessment from the left-hand form. Findings and chat stream in on the right as the run proceeds.

| Field | Notes |
|:------|:------|
| **Target URL** | The live app to test. Must start with `http://` or `https://`. |
| **Repo** | Pick an existing folder under `./repos/`. Leave blank for a pure black-box (DAST-only) scan. |
| **Or clone a repo by git URL** | Paste a Git URL and the console does a shallow clone into `./repos/` for you. |
| **GitHub token** | Only for private repos. A PAT (`repo` scope) or GitHub App installation token, sent once over TLS for the clone, **never stored or logged**. |
| **Config source** | `(none)`, a **built-in config** from `./configs/`, or **paste your own YAML**. Picking a built-in prefills the YAML editor so you can fork it. |
| **Vuln classes** | Toggle which classes to test — `injection`, `xss`, `auth`, `authz`, `ssrf`, `client-side`, `session-mgmt`, `api-testing`, `business-logic`, `crypto`, `config-deploy`, `error-handling`, `info-gathering`, `web-attacks`. All on by default. |
| **Skip exploitation phase** | Stop after vulnerability analysis — candidate findings without exploit verification. |
| **Initial instruction** | Steer the run in plain English, e.g. *"Focus on the /api/v2 endpoints and skip nmap."* |

### The Reports & Findings panel

Proven findings and reports stream into this panel as agents confirm them. The executive summary is highlighted (★) once the run completes. Click any file to open it in a side-by-side viewer (Markdown is rendered; other formats show raw), or download the whole bundle as a `.zip`.

### The Chat panel

Talk to the agent while it works, like messaging a teammate. A single message box does double duty:

- If the agent has **paused to ask you a question** (shown in an amber prompt), your message answers it.
- Otherwise, your message **queues as a follow-up instruction** for the agent's next turn — e.g. "dig deeper on that IDOR" or "now look at the file-upload endpoint."

Press `Cmd`/`Ctrl`+`Enter` to send.

## The Runs tab

A searchable, sortable history of every assessment this instance has executed. Filter by URL or repo, filter by status (Running / Completed / Error), and sort by start time, duration, or file count. Click any row to reopen its reports in read-only mode.

This is your audit trail of continuous testing — useful as compliance evidence. Runs are merged from two sources: the Postgres database (when `DATABASE_URL` is set) and the `audit-logs/` directory on disk, so legacy and DB-disabled runs still show up.

## The CI/CD tab

Wire Dapper into your pipeline against a long-running console instance:

1. **Mint an API key** with a descriptive label (e.g. `github-actions-staging`). The plaintext token is shown **exactly once** — copy it immediately; afterward only its prefix is visible. You can revoke a key at any time from the same table.
2. **Copy a trigger snippet.** The tab generates ready-made snippets — cURL, GitHub Actions, GitLab CI, and CircleCI — pre-filled with this instance's origin. Each one `POST`s to `/api/scans` with `Authorization: Bearer $DAPPER_API_KEY`.

Store the key as a secret in your CI provider and drop the snippet into your deploy workflow. The CI endpoint (`POST /api/scans`) requires a valid Bearer token even when the browser UI is open, so it can be secured independently.

For the per-job alternative (a fresh container each run, no always-on instance), see [CI/CD integration]({{ '/guides/cicd' | relative_url }}).

## Persistence

| Mode | Behaviour |
|:-----|:----------|
| `DATABASE_URL` **set** (Postgres) | Runs, deliverables, and API keys persist across restarts. The Runs tab and historical report lookups survive container recreation. |
| `DATABASE_URL` **unset** | The console keeps live state for the current process only. Historical runs are still read from the `audit-logs/` directory, but API keys can't be minted — the CI/CD endpoints return `503`. |

{: .note }
> API key minting and the `/api/scans` CI trigger **require** `DATABASE_URL`. Without it, the CI/CD tab can show snippets but can't issue or verify keys.

See [Environment variables]({{ '/reference/environment-variables' | relative_url }}) for every setting.
