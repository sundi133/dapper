---
title: Environment variables
parent: Reference
nav_order: 3
permalink: /reference/environment-variables
---

# Environment variables
{: .no_toc }

Configuration lives in `.env` (copy it from `.env.example`). The `./dapper`
script sources `.env` automatically. The only hard requirement is an LLM
credential — everything else is optional and depends on the features you
use.

1. TOC
{:toc}

---

## All variables

| Variable | Required? | Purpose | Example |
|:---------|:----------|:--------|:--------|
| `ANTHROPIC_API_KEY` | Yes (one LLM credential) | Anthropic API key — the default and recommended LLM credential. | `sk-ant-...` |
| `CLAUDE_CODE_OAUTH_TOKEN` | Alternative to API key | Claude Code OAuth token, used instead of `ANTHROPIC_API_KEY`. | `sk-ant-oat-...` |
| `OPENAI_API_KEY` | Router mode only | OpenAI API key, used when routing through OpenAI. | `sk-...` |
| `OPENROUTER_API_KEY` | Router mode only | OpenRouter API key — access to Gemini and many other models via one API. | `sk-or-...` |
| `ROUTER_DEFAULT` | Router mode only | Default `provider,model` used by the router. | `openai,gpt-5.2` |
| `OLLAMA_BASE_URL` | No | Ollama endpoint when using local models via the router. | `http://host.docker.internal:11434` |
| `DAPPER_WEB_USERNAME` | No | Username for the web console sign-in. | `admin` |
| `DAPPER_WEB_PASSWORD` | No | When set, the web console requires sign-in. Unset = open (local-only). | `change-me-to-something-long` |
| `DAPPER_SESSION_SECRET` | No | Stable secret for signing web-console session cookies. | (32-byte URL-safe token) |
| `DATABASE_URL` | No | Database connection string for the web console / runs store. | `postgresql://user:pass@host:5432/dapper` |

{: .note }
> Exactly one LLM credential is required to run a pentest:
> `ANTHROPIC_API_KEY` **or** `CLAUDE_CODE_OAUTH_TOKEN`. With `ROUTER=true`,
> a provider key (`OPENAI_API_KEY`, `OPENROUTER_API_KEY`) or an
> `ollama,<model>` value in `ROUTER_DEFAULT` satisfies the credential check
> instead.

---

## LLM credentials

The default, supported path is Anthropic's Claude. Provide either an API
key or an OAuth token:

```bash
# Recommended
ANTHROPIC_API_KEY=sk-ant-...

# Or, instead of the API key:
# CLAUDE_CODE_OAUTH_TOKEN=your-oauth-token-here
```

Get an API key from [console.anthropic.com](https://console.anthropic.com).

## Alternative providers (experimental)

Used only with `ROUTER=true`. Dapper is built on the Anthropic Agent SDK and
optimized for Claude; alternative providers are experimental and unsupported.
Configure **one** provider, plus a `ROUTER_DEFAULT` of the form
`provider,model`. See [LLM providers]({{ '/reference/llm-providers' | relative_url }}).

```bash
# OpenAI
OPENAI_API_KEY=sk-your-openai-key
ROUTER_DEFAULT=openai,gpt-5.2

# OpenRouter (e.g. Gemini 3 family)
OPENROUTER_API_KEY=sk-or-your-openrouter-key
ROUTER_DEFAULT=openrouter,google/gemini-3-flash-preview

# Ollama (local, no API key)
ROUTER_DEFAULT=ollama,llama3.3
OLLAMA_BASE_URL=http://host.docker.internal:11434   # default; change if Ollama runs elsewhere
```

## Web console

These configure the optional DeepAgents web console launched with
`./dapper web`.

```bash
# If DAPPER_WEB_PASSWORD is set, the UI requires a username + password.
# Leave it unset to keep the console open (recommended for local-only Docker).
DAPPER_WEB_USERNAME=admin                 # defaults to "admin" if unset
DAPPER_WEB_PASSWORD=change-me-to-something-long

# Stable cookie-signing secret. If unset, a random value is generated at
# startup and all logins are invalidated on every restart.
DAPPER_SESSION_SECRET=

# Generate a session secret:
#   python -c "import secrets; print(secrets.token_urlsafe(32))"

# Connection string for the console's runs store (optional).
DATABASE_URL=postgresql://user:pass@host:5432/dapper
```

{: .warning }
> `.env` holds secrets — keep it out of version control. In CI, inject these
> as masked pipeline variables rather than committing them.
