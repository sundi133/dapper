"""DAST tool wrappers exposed to DeepAgents as LangChain tools.

These shell out to standard pentesting binaries. Each tool returns truncated
stdout so the agent's context window stays manageable.
"""
from __future__ import annotations

import json
import shlex
import subprocess
from pathlib import Path

from langchain_core.tools import tool

MAX_OUTPUT = 12_000


def _run(cmd: list[str], timeout: int = 300) -> str:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        return f"ERROR: binary not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return f"ERROR: timeout after {timeout}s: {shlex.join(cmd)}"
    out = (proc.stdout or "") + (("\n--STDERR--\n" + proc.stderr) if proc.stderr else "")
    if len(out) > MAX_OUTPUT:
        out = out[:MAX_OUTPUT] + f"\n... (truncated, {len(out) - MAX_OUTPUT} bytes)"
    return out or f"(no output, exit={proc.returncode})"


@tool
def http_get(url: str, headers_json: str = "{}") -> str:
    """Fetch a URL with curl. headers_json is a JSON object of extra headers."""
    headers = json.loads(headers_json or "{}")
    cmd = ["curl", "-sSL", "-D", "-", "--max-time", "30"]
    for k, v in headers.items():
        cmd += ["-H", f"{k}: {v}"]
    cmd.append(url)
    return _run(cmd, timeout=45)


@tool
def http_request(
    method: str,
    url: str,
    headers_json: str = "{}",
    body: str = "",
) -> str:
    """Send an HTTP request with any verb (POST/PUT/PATCH/DELETE/OPTIONS/HEAD/GET).

    Args:
      method: HTTP verb, case-insensitive (e.g. "POST").
      url: full target URL.
      headers_json: JSON object of extra headers, e.g.
        '{"Content-Type":"application/json","Authorization":"Bearer ..."}'.
      body: raw request body. For JSON, pass the serialized string and set
        Content-Type in headers_json.

    Returns response headers + body (truncated). Follows redirects.
    """
    verb = (method or "GET").upper()
    allowed = {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"}
    if verb not in allowed:
        return f"ERROR: unsupported method {verb!r}; allowed: {sorted(allowed)}"
    try:
        headers = json.loads(headers_json or "{}")
    except json.JSONDecodeError as exc:
        return f"ERROR: headers_json is not valid JSON: {exc}"
    cmd = ["curl", "-sSL", "-D", "-", "--max-time", "30", "-X", verb]
    for k, v in headers.items():
        cmd += ["-H", f"{k}: {v}"]
    if body:
        # --data-raw avoids curl's @file interpretation of a leading '@'.
        cmd += ["--data-raw", body]
    cmd.append(url)
    return _run(cmd, timeout=45)


@tool
def nuclei_scan(url: str, templates: str = "cves,vulnerabilities,exposures") -> str:
    """Run a nuclei scan against url with a comma-separated list of template tags."""
    return _run(["nuclei", "-u", url, "-tags", templates, "-silent", "-j"], timeout=900)


@tool
def nmap_scan(host: str, ports: str = "1-10000") -> str:
    """Run a nmap TCP SYN scan on host across the given port range."""
    return _run(["nmap", "-sS", "-sV", "-Pn", "-p", ports, host], timeout=900)


@tool
def subfinder_scan(domain: str) -> str:
    """Enumerate subdomains for a domain via subfinder."""
    return _run(["subfinder", "-d", domain, "-silent"], timeout=300)


@tool
def whatweb_fingerprint(url: str) -> str:
    """Fingerprint web technologies at url via whatweb."""
    return _run(["whatweb", "--no-errors", "-a", "3", url], timeout=120)


@tool
def sqlmap_probe(url: str, data: str = "", cookie: str = "") -> str:
    """Run sqlmap in batch/non-interactive mode against url. Use sparingly."""
    cmd = ["sqlmap", "-u", url, "--batch", "--level=2", "--risk=1", "--smart"]
    if data:
        cmd += ["--data", data]
    if cookie:
        cmd += ["--cookie", cookie]
    return _run(cmd, timeout=900)


@tool
def ffuf_dirfuzz(url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt") -> str:
    """Directory fuzzing via ffuf. url must contain FUZZ marker."""
    if "FUZZ" not in url:
        return "ERROR: url must contain FUZZ marker"
    return _run(["ffuf", "-u", url, "-w", wordlist, "-mc", "200,301,302,401,403", "-s"], timeout=600)


@tool
def write_finding(deliverables_dir: str, filename: str, content: str) -> str:
    """Persist a finding to deliverables_dir/filename. Use markdown.

    Always overwrites — call this again with the same filename to update a
    deliverable. Prefer this over the built-in `write_file` for any file
    under the deliverables directory; `write_file` refuses to overwrite
    existing paths and will block the run.
    """
    base = Path(deliverables_dir)
    base.mkdir(parents=True, exist_ok=True)
    target = base / filename
    target.write_text(content)
    return f"wrote {target} ({len(content)} bytes)"


@tool
def read_file(path: str) -> str:
    """Read a file from disk (e.g. an earlier deliverable)."""
    p = Path(path)
    if not p.exists():
        return f"ERROR: not found: {path}"
    data = p.read_text()
    if len(data) > MAX_OUTPUT:
        return data[:MAX_OUTPUT] + f"\n... (truncated)"
    return data


ALL_TOOLS = [
    http_get,
    http_request,
    nuclei_scan,
    nmap_scan,
    subfinder_scan,
    whatweb_fingerprint,
    sqlmap_probe,
    ffuf_dirfuzz,
    write_finding,
    read_file,
]
