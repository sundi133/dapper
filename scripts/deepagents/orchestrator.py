"""DeepAgents orchestrator for Dapper DAST pentesting (Option A).

Replaces Dapper's Temporal planner with a `deepagents` deep agent that:
  1. Plans the engagement using Dapper's recon prompt as system instructions.
  2. Dispatches per-vulnerability-class subagents (XSS, injection, authz, ...)
     each primed with the matching `prompts/vuln-*.txt` template.
  3. Calls DAST tools (nuclei, sqlmap, whatweb, ffuf, curl, ...) plus file
     read/write tools so the agent can chain findings across phases.
  4. Can call back to the human via the `ask_user` tool when it needs creds,
     scope clarification, or confirmation before an intrusive probe.

Missing CLI args (URL, repo, config, API key) trigger an interactive setup
flow when running on a TTY.
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

from deepagents import create_deep_agent

from .dast_tools import ALL_TOOLS
from .interactive import (
    ask_user,
    ensure_api_key,
    ensure_config,
    ensure_repo,
    ensure_url,
    load_config_context,
)
from .prompt_loader import load_prompt

VULN_CLASSES = [
    "injection",
    "xss",
    "auth",
    "authz",
    "ssrf",
    "client-side",
    "session-mgmt",
    "api-testing",
    "business-logic",
    "crypto",
    "config-deploy",
    "error-handling",
    "info-gathering",
    "web-attacks",
]


def build_subagent(vuln_class: str, vars_: dict[str, str], tool_names: list[str]) -> dict:
    prompt = load_prompt(f"vuln-{vuln_class}", vars_)
    return {
        "name": f"{vuln_class}-vuln",
        "description": f"Hunt for {vuln_class} vulnerabilities against the target.",
        "system_prompt": prompt,
        "tools": tool_names,
    }


def build_exploit_subagent(vuln_class: str, vars_: dict[str, str], tool_names: list[str]) -> dict | None:
    prompt_path = Path(__file__).resolve().parents[2] / "prompts" / f"exploit-{vuln_class}.txt"
    if not prompt_path.exists():
        return None
    prompt = load_prompt(f"exploit-{vuln_class}", vars_)
    return {
        "name": f"{vuln_class}-exploit",
        "description": f"Exploit confirmed {vuln_class} vulnerabilities (proof only).",
        "system_prompt": prompt,
        "tools": tool_names,
    }


def main() -> int:
    load_dotenv()
    parser = argparse.ArgumentParser(description="Dapper x DeepAgents DAST orchestrator")
    parser.add_argument("--url", default=None, help="Primary target URL (prompted if missing)")
    parser.add_argument("--repo", default=None, help="Folder name under ./repos/ (prompted if missing)")
    parser.add_argument("--config", default=None, help="YAML config path (optional)")
    parser.add_argument("--deliverables", default=None, help="Output dir for findings")
    parser.add_argument("--model", default="claude-opus-4-7", help="Anthropic model id")
    parser.add_argument("--classes", default=",".join(VULN_CLASSES), help="Vuln classes to enable")
    parser.add_argument("--skip-exploit", action="store_true", help="Skip exploitation phase")
    parser.add_argument("--non-interactive", action="store_true", help="Fail instead of prompting")
    args = parser.parse_args()

    if args.non_interactive:
        # Force interactive helpers to exit with error if anything is missing.
        os.environ.setdefault("CI", "1")

    ensure_api_key()
    url = ensure_url(args.url)
    repo = ensure_repo(args.repo)
    config_path = ensure_config(args.config)
    config_context, login_instructions = load_config_context(config_path)

    deliverables = args.deliverables
    if not deliverables:
        host = url.split("://", 1)[-1].split("/", 1)[0].replace(":", "_")
        ts = int(__import__("time").time())
        deliverables = str(Path("audit-logs") / f"{host}_deepagent-{ts}" / "deliverables")
    Path(deliverables).mkdir(parents=True, exist_ok=True)

    print("\n=== Dapper x DeepAgents ===")
    print(f"  URL          : {url}")
    print(f"  Repo         : ./repos/{repo}")
    print(f"  Config       : {config_path or '(none)'}")
    print(f"  Deliverables : {deliverables}")
    print(f"  Model        : {args.model}")
    print(f"  Skip exploit : {args.skip_exploit}\n")

    template_vars = {
        "WEB_URL": url,
        "TARGET_URL": url,
        "ADDITIONAL_TARGETS": "",
        "ACCOUNTS": "",
        "SEED_DATA": "",
        "EXPLORATION_LIMITS": "Stay strictly within scope. Read-only probing first.",
        "API_SCHEMAS": "",
        "CONFIG_CONTEXT": config_context,
        "LOGIN_INSTRUCTIONS": login_instructions,
        "REPO": repo,
        "DELIVERABLES_DIR": deliverables,
    }

    tools = ALL_TOOLS + [ask_user]
    tool_names = [t.name for t in tools]

    classes = [c.strip() for c in args.classes.split(",") if c.strip()]
    subagents: list[dict] = []
    for vc in classes:
        subagents.append(build_subagent(vc, template_vars, tool_names))
        if not args.skip_exploit:
            ex = build_exploit_subagent(vc, template_vars, tool_names)
            if ex:
                subagents.append(ex)

    planner_instructions = load_prompt("recon", template_vars) + f"""

# Orchestration rules
- Target: {url}
- Local repo (for code-assisted DAST): ./repos/{repo}
- Persist every finding via `write_finding` into: {deliverables}
- Phase 1: run recon tools (whatweb, subfinder, nmap, nuclei, http_get).
- Phase 2: dispatch one vuln subagent per relevant class — in parallel where
  possible. Pass them the recon deliverables paths.
- Phase 3: for any *confirmed* vuln, hand it to the matching exploit subagent
  (skipped if --skip-exploit was passed).
- Phase 4: write an executive summary to {deliverables}/00-executive-summary.md.
- Always cite source-to-sink traces, request/response evidence, and CVSS.

# Human in the loop
- You are running interactively. If you lack information you need — login
  credentials, an OTP, a confirmed scope boundary, permission to run an
  intrusive probe (sqlmap, ffuf, nuclei aggressive templates), an out-of-band
  callback URL, etc. — call the `ask_user` tool. Phrase questions short and
  specific. Do NOT guess credentials or attack out-of-scope hosts.
- If a config was loaded, prefer its values over asking; only ask for what is
  truly missing.

# Loaded config (may be empty)
{config_context or '(no config provided)'}
"""

    agent = create_deep_agent(
        model=args.model,
        tools=tools,
        system_prompt=planner_instructions,
        subagents=subagents,
    )

    initial = (
        f"Conduct a full DAST pentest of {url}. Repo: {repo}. "
        f"Write all deliverables to {deliverables}. "
        "Start with recon, then dispatch the vulnerability subagents you judge "
        "relevant. Use `ask_user` whenever you need information from the human "
        "operator (creds, scope, confirmation for intrusive probes). End by "
        "writing 00-executive-summary.md."
    )

    result = agent.invoke({"messages": [{"role": "user", "content": initial}]})

    final = result["messages"][-1]
    content = getattr(final, "content", final)
    print(content if isinstance(content, str) else str(content))
    return 0


if __name__ == "__main__":
    sys.exit(main())
