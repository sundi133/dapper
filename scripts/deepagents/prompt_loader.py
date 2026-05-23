"""Resolve Dapper prompt templates with @include() directives and {{VAR}} substitution."""
from __future__ import annotations

import re
from pathlib import Path

PROMPTS_DIR = Path(__file__).resolve().parents[2] / "prompts"
INCLUDE_RE = re.compile(r"@include\(([^)]+)\)")
VAR_RE = re.compile(r"{{\s*([A-Z0-9_]+)\s*}}")


def _resolve_includes(text: str, seen: set[str]) -> str:
    def repl(match: re.Match[str]) -> str:
        rel = match.group(1).strip()
        if rel in seen:
            return ""
        seen.add(rel)
        path = PROMPTS_DIR / rel
        if not path.suffix:
            path = path.with_suffix(".txt")
        return _resolve_includes(path.read_text(), seen)

    return INCLUDE_RE.sub(repl, text)


def load_prompt(name: str, variables: dict[str, str] | None = None) -> str:
    """Load a Dapper prompt by stem (e.g. 'vuln-xss') and substitute {{VARS}}."""
    path = PROMPTS_DIR / f"{name}.txt"
    text = _resolve_includes(path.read_text(), set())
    if variables:
        def sub(m: re.Match[str]) -> str:
            return variables.get(m.group(1), m.group(0))
        text = VAR_RE.sub(sub, text)
    return text
