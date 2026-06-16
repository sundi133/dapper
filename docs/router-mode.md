---
title: LLM providers
parent: Reference
nav_order: 5
permalink: /reference/llm-providers
---

# LLM providers
{: .no_toc }

Dapper runs on Anthropic's Claude by default and is built and optimized for
it. An experimental **router mode** can route requests through alternative
providers (OpenAI, OpenRouter, Ollama) via
[claude-code-router](https://github.com/musistudio/claude-code-router), for
model experimentation only.

1. TOC
{:toc}

---

## Anthropic (default, recommended)

The default and supported path. Provide an Anthropic credential in `.env` —
either an API key or a Claude Code OAuth token — and run normally (no
`ROUTER` flag).

```bash
# .env — recommended
ANTHROPIC_API_KEY=sk-ant-...

# or, instead of the API key:
# CLAUDE_CODE_OAUTH_TOKEN=your-oauth-token-here
```

```bash
./dapper start URL=https://example.com REPO=repo-name
```

Get an API key from [console.anthropic.com](https://console.anthropic.com).
See [Environment variables]({{ '/reference/environment-variables' | relative_url }})
for the full credential reference.

---

## Router mode (experimental)

{: .warning }
> **Experimental and unsupported.** Dapper is built on the Anthropic Agent
> SDK and optimized for Claude. Alternative providers may produce
> inconsistent results — including failing early phases such as Recon —
> depending on the model and routing setup. Bug reports against router mode
> are best-effort.

Router mode is intended for trying Dapper with non-Claude models. Enable it
by configuring one provider in `.env`, then passing `ROUTER=true`:

```bash
./dapper start URL=https://example.com REPO=repo-name ROUTER=true
```

When `ROUTER=true`, the `./dapper` script starts the `claude-code-router`
container and points the Agent SDK at it. The router reads `ROUTER_DEFAULT`
(format: `provider,model`) to pick the active provider and model.

### Supported providers

| Provider | Models | API key | Notes |
|:---------|:-------|:--------|:------|
| **OpenAI** | `gpt-5.2`, `gpt-5-mini` | `OPENAI_API_KEY` | Good tool use; balanced cost/performance. |
| **OpenRouter** | `google/gemini-3-flash-preview` (and others OpenRouter exposes) | `OPENROUTER_API_KEY` | Access to Gemini 3 family and many models via one API. |
| **Ollama** | any locally pulled model (e.g. `llama3.3`, `qwen2.5`, `deepseek-r1`) | none | Free local inference; configurable via `OLLAMA_BASE_URL`. |

### OpenAI

```bash
# .env
OPENAI_API_KEY=sk-your-openai-key
ROUTER_DEFAULT=openai,gpt-5.2
```

```bash
./dapper start URL=https://example.com REPO=repo-name ROUTER=true
```

### OpenRouter

```bash
# .env
OPENROUTER_API_KEY=sk-or-your-openrouter-key
ROUTER_DEFAULT=openrouter,google/gemini-3-flash-preview
```

```bash
./dapper start URL=https://example.com REPO=repo-name ROUTER=true
```

### Ollama (local)

No API key is required. By default the router reaches Ollama at
`http://host.docker.internal:11434`; override with `OLLAMA_BASE_URL` if it
runs elsewhere.

```bash
# .env
ROUTER_DEFAULT=ollama,llama3.3
# OLLAMA_BASE_URL=http://host.docker.internal:11434   # default; change if needed
```

```bash
./dapper start URL=https://example.com REPO=repo-name ROUTER=true
```

{: .note }
> Ollama satisfies the credential check on its own — with
> `ROUTER_DEFAULT=ollama,<model>` you do not need an Anthropic or other
> provider key set.

---

## How routing is wired

With `ROUTER=true`, the script:

1. Starts the `router` profile container (`claude-code-router`) if it is not
   already running.
2. Sets `ANTHROPIC_BASE_URL=http://router:3456` and an auth token so the
   Agent SDK talks to the router instead of Anthropic directly.
3. The router (`configs/router-config.json`) maps the request to the
   provider/model named in `ROUTER_DEFAULT`.

`./dapper stop` (and `./dapper stop CLEAN=true`) also bring the router
container down.

## Caveats

- **Quality varies.** Some providers fail early phases such as Recon.
- **No official support.** Router mode is best-effort.
- **Costs and rate limits differ** per provider — track your own quota.
- **Optimized for Claude.** For reliable results, use Anthropic models.
