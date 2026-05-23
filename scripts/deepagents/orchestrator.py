"""DeepAgents orchestrator for Dapper DAST pentesting (Option A).

Replaces Dapper's Temporal planner with a `deepagents` deep agent that:
  1. Plans the engagement using Dapper's recon prompt as system instructions.
  2. Dispatches per-vulnerability-class subagents (XSS, injection, authz, ...)
     each primed with the matching `prompts/vuln-*.txt` template.
  3. Calls DAST tools (nuclei, sqlmap, whatweb, ffuf, curl, ...) plus file
     read/write tools so the agent can chain findings across phases.

Usage:
    python -m scripts.deepagents.orchestrator \
        --url https://target.example \
        --repo target-repo \
        --deliverables ./audit-logs/target_$(date +%s)/deliverables

Environment:
    ANTHROPIC_API_KEY must be set (loaded from .env if present).
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

from deepagents import create_deep_agent

from .dast_tools import ALL_TOOLS
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


def build_subagent(vuln_class: str, vars_: dict[str, str]) -> dict:
    prompt = load_prompt(f"vuln-{vuln_class}", vars_)
    return {
        "name": f"{vuln_class}-vuln",
        "description": f"Hunt for {vuln_class} vulnerabilities against the target.",
        "prompt": prompt,
        "tools": [t.name for t in ALL_TOOLS],
    }


def build_exploit_subagent(vuln_class: str, vars_: dict[str, str]) -> dict | None:
    prompt_path = Path(__file__).resolve().parents[2] / "prompts" / f"exploit-{vuln_class}.txt"
    if not prompt_path.exists():
        return None
    prompt = load_prompt(f"exploit-{vuln_class}", vars_)
    return {
        "name": f"{vuln_class}-exploit",
        "description": f"Exploit confirmed {vuln_class} vulnerabilities (proof only).",
        "prompt": prompt,
        "tools": [t.name for t in ALL_TOOLS],
    }


def main() -> int:
    load_dotenv()
    parser = argparse.ArgumentParser(description="Dapper x DeepAgents DAST orchestrator")
    parser.add_argument("--url", required=True, help="Primary target URL")
    parser.add_argument("--repo", required=True, help="Folder name under ./repos/")
    parser.add_argument("--deliverables", required=True, help="Output directory for findings")
    parser.add_argument("--model", default="claude-opus-4-7", help="Anthropic model id")
    parser.add_argument(
        "--classes",
        default=",".join(VULN_CLASSES),
        help="Comma-separated vuln classes to enable",
    )
    parser.add_argument(
        "--skip-exploit",
        action="store_true",
        help="Skip exploitation subagents (vuln analysis only)",
    )
    args = parser.parse_args()

    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("ERROR: ANTHROPIC_API_KEY not set", file=sys.stderr)
        return 2

    Path(args.deliverables).mkdir(parents=True, exist_ok=True)

    template_vars = {
        "WEB_URL": args.url,
        "TARGET_URL": args.url,
        "ADDITIONAL_TARGETS": "",
        "ACCOUNTS": "",
        "SEED_DATA": "",
        "EXPLORATION_LIMITS": "Stay strictly within scope. Read-only probing first.",
        "API_SCHEMAS": "",
        "CONFIG_CONTEXT": "",
        "LOGIN_INSTRUCTIONS": "",
        "REPO": args.repo,
        "DELIVERABLES_DIR": args.deliverables,
    }

    classes = [c.strip() for c in args.classes.split(",") if c.strip()]
    subagents: list[dict] = []
    for vc in classes:
        subagents.append(build_subagent(vc, template_vars))
        if not args.skip_exploit:
            ex = build_exploit_subagent(vc, template_vars)
            if ex:
                subagents.append(ex)

    planner_instructions = load_prompt("recon", template_vars) + f"""

# Orchestration rules
- Target: {args.url}
- Local repo (for code-assisted DAST): ./repos/{args.repo}
- Persist every finding via `write_finding` into: {args.deliverables}
- Phase 1: run recon tools (whatweb, subfinder, nmap, nuclei, http_get).
- Phase 2: dispatch one vuln subagent per relevant class — in parallel where
  possible. Pass them the recon deliverables paths.
- Phase 3: for any *confirmed* vuln, hand it to the matching exploit subagent
  (skipped if --skip-exploit was passed).
- Phase 4: write an executive summary to {args.deliverables}/00-executive-summary.md.
- Always cite source-to-sink traces, request/response evidence, and CVSS.
"""

    agent = create_deep_agent(
        model=args.model,
        tools=ALL_TOOLS,
        instructions=planner_instructions,
        subagents=subagents,
    )

    initial = (
        f"Conduct a full DAST pentest of {args.url}. Repo: {args.repo}. "
        f"Write all deliverables to {args.deliverables}. "
        "Start with recon, then dispatch the vulnerability subagents you judge "
        "relevant. End by writing 00-executive-summary.md."
    )

    result = agent.invoke({"messages": [{"role": "user", "content": initial}]})

    final = result["messages"][-1]
    content = getattr(final, "content", final)
    print(content if isinstance(content, str) else str(content))
    return 0


if __name__ == "__main__":
    sys.exit(main())
