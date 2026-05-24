---
title: Router mode (experimental)
nav_order: 7
---

# Router mode (experimental)
{: .no_toc }

{: .warning }
**Experimental and unsupported.** Dapper is built on the Anthropic Agent SDK
and is optimized for Claude models. Alternative providers may produce
inconsistent results (including failing early phases like Recon) depending
on the model and routing setup.

1. TOC
{:toc}

Dapper can route requests through alternative AI providers using
[claude-code-router](https://github.com/musistudio/claude-code-router).
This mode is primarily intended for **model experimentation** — trying
Dapper with GPT-5.2 or Gemini 3–family models.

## Quick setup

1. Add your provider API key to `.env`:

   ```bash
   # Choose one provider:
   OPENAI_API_KEY=sk-...
   # OR
   OPENROUTER_API_KEY=sk-or-...

   # Set default model (provider,model format):
   ROUTER_DEFAULT=openai,gpt-5.2
   ```

2. Run with `ROUTER=true`:

   ```bash
   ./dapper start URL=https://example.com REPO=repo-name ROUTER=true
   ```

## Supported providers

| Provider | Models | Notes |
|---|---|---|
| **OpenAI** | `gpt-5.2`, `gpt-5-mini` | Good tool use, balanced cost/perf |
| **OpenRouter** | `google/gemini-3-flash-preview` | Access to Gemini 3 via a single API |
| **Ollama** | any pulled model (e.g. `llama3.3`) | Free local inference, no API key |

Ollama example:

```bash
ROUTER_DEFAULT=ollama,llama3.3
```

## Caveats

- **Quality varies.** Some providers fail early phases like Recon.
- **No official support.** Bug reports against Router Mode are best-effort.
- **Costs and rate limits differ** per provider — track your own quota.
