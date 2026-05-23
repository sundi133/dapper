"""Interactive setup helpers — collect missing URL / repo / config from the user
before kicking off the deep agent, and provide an `ask_user` tool so the agent
can solicit info mid-run (creds, scope clarifications, auth flow steps).
"""
from __future__ import annotations

import os
import re
import sys
from pathlib import Path
from urllib.parse import urlparse

from langchain_core.tools import tool

REPO_ROOT = Path(__file__).resolve().parents[2]
REPOS_DIR = REPO_ROOT / "repos"
CONFIGS_DIR = REPO_ROOT / "configs"
ENV_PATH = REPO_ROOT / ".env"


def _isatty() -> bool:
    return sys.stdin.isatty() and sys.stdout.isatty()


def _prompt(label: str, default: str | None = None, required: bool = True) -> str:
    suffix = f" [{default}]" if default else ""
    while True:
        try:
            val = input(f"{label}{suffix}: ").strip()
        except EOFError:
            val = ""
        if not val and default is not None:
            return default
        if val:
            return val
        if not required:
            return ""
        print("  (required)")


def _confirm(label: str, default: bool = True) -> bool:
    d = "Y/n" if default else "y/N"
    try:
        ans = input(f"{label} [{d}]: ").strip().lower()
    except EOFError:
        return default
    if not ans:
        return default
    return ans in ("y", "yes")


def _valid_url(u: str) -> bool:
    p = urlparse(u)
    return p.scheme in ("http", "https") and bool(p.netloc)


def ensure_api_key() -> None:
    """Prompt for ANTHROPIC_API_KEY if missing and offer to persist to .env."""
    if os.environ.get("ANTHROPIC_API_KEY"):
        return
    if not _isatty():
        print("ERROR: ANTHROPIC_API_KEY not set (non-interactive shell)", file=sys.stderr)
        sys.exit(2)
    print("ANTHROPIC_API_KEY is not set.")
    key = _prompt("Anthropic API key (sk-ant-...)")
    os.environ["ANTHROPIC_API_KEY"] = key
    if _confirm(f"Save to {ENV_PATH}?", default=True):
        existing = ENV_PATH.read_text() if ENV_PATH.exists() else ""
        if "ANTHROPIC_API_KEY=" in existing:
            existing = re.sub(r"ANTHROPIC_API_KEY=.*", f"ANTHROPIC_API_KEY={key}", existing)
        else:
            if existing and not existing.endswith("\n"):
                existing += "\n"
            existing += f"ANTHROPIC_API_KEY={key}\n"
        ENV_PATH.write_text(existing)
        print(f"  wrote {ENV_PATH}")


def ensure_url(url: str | None) -> str:
    if url and _valid_url(url):
        return url
    if url:
        print(f"WARN: '{url}' is not a valid http(s) URL")
    if not _isatty():
        print("ERROR: --url is required", file=sys.stderr)
        sys.exit(2)
    while True:
        u = _prompt("Target URL (https://...)")
        if _valid_url(u):
            return u
        print("  must start with http:// or https://")


def ensure_repo(repo: str | None) -> str:
    """Ask for / create the local repo dir under ./repos/."""
    if not _isatty() and not repo:
        print("ERROR: --repo is required", file=sys.stderr)
        sys.exit(2)
    if not repo:
        existing = sorted([p.name for p in REPOS_DIR.iterdir() if p.is_dir()]) if REPOS_DIR.exists() else []
        if existing:
            print("Existing repos under ./repos/:")
            for name in existing:
                print(f"  - {name}")
        repo = _prompt("Repo folder name under ./repos/")

    target = REPOS_DIR / repo
    if target.exists() and target.is_dir():
        return repo

    if not _isatty():
        print(f"ERROR: ./repos/{repo} does not exist", file=sys.stderr)
        sys.exit(2)

    print(f"./repos/{repo} does not exist.")
    print("  [1] clone from a git URL")
    print("  [2] create empty directory")
    print("  [3] abort")
    choice = _prompt("Choose", default="1")
    if choice == "1":
        git_url = _prompt("Git URL to clone")
        REPOS_DIR.mkdir(parents=True, exist_ok=True)
        rc = os.system(f"git clone {git_url!r} {str(target)!r}")
        if rc != 0:
            print("ERROR: clone failed", file=sys.stderr)
            sys.exit(2)
    elif choice == "2":
        target.mkdir(parents=True, exist_ok=True)
    else:
        sys.exit(0)
    return repo


def ensure_config(config: str | None) -> str | None:
    """Optionally pick a YAML config from ./configs/."""
    if config:
        p = Path(config)
        if p.exists():
            return str(p)
        print(f"WARN: config '{config}' not found")
        if not _isatty():
            return None

    if not _isatty():
        return None

    if not _confirm("Use a YAML config for auth / scope?", default=False):
        return None

    available = sorted(CONFIGS_DIR.glob("*.yaml")) if CONFIGS_DIR.exists() else []
    if available:
        print("Available configs:")
        for i, p in enumerate(available, 1):
            print(f"  [{i}] {p.name}")
        print(f"  [0] none / enter path manually")
        sel = _prompt("Pick", default="0")
        if sel.isdigit() and 1 <= int(sel) <= len(available):
            return str(available[int(sel) - 1])

    path = _prompt("Config path (blank to skip)", required=False)
    if not path:
        return None
    if not Path(path).exists():
        print(f"WARN: '{path}' not found, skipping")
        return None
    return path


def load_config_context(config_path: str | None) -> tuple[str, str]:
    """Return (config_context, login_instructions) for prompt substitution."""
    if not config_path:
        return "", ""
    raw = Path(config_path).read_text()
    login = ""
    shared_login = REPO_ROOT / "prompts" / "shared" / "login-instructions.txt"
    if shared_login.exists():
        login = shared_login.read_text()
    return raw, login


@tool
def ask_user(question: str) -> str:
    """Ask the human operator a question and return their typed answer.

    Use this when you need information you don't have: credentials, scope
    clarification, auth flow steps, whether to proceed with an intrusive probe,
    confirmation on out-of-band tests, etc. Keep questions short and specific.
    """
    if not _isatty():
        return "ERROR: no interactive terminal — proceed with safe defaults"
    print("\n" + "=" * 60)
    print("AGENT QUESTION:")
    print(question)
    print("=" * 60)
    try:
        ans = input("Your answer (multi-line: end with blank line)> ").rstrip()
    except EOFError:
        return "(no answer)"
    extra: list[str] = []
    while True:
        try:
            line = input()
        except EOFError:
            break
        if not line.strip():
            break
        extra.append(line)
    if extra:
        ans = ans + "\n" + "\n".join(extra)
    return ans or "(no answer)"
