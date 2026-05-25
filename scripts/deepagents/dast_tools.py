"""DAST tool wrappers exposed to DeepAgents as LangChain tools.

These shell out to standard pentesting binaries. Each tool returns truncated
stdout so the agent's context window stays manageable.

Two env vars, set by the session/orchestrator, control per-run state:

  DAPPER_HTTP_STATE_DIR  - root for named curl cookie jars (cookies/<name>.txt)
  DAPPER_HTTP_TRACE_DIR  - if set, every http_* call appends to
                           <dir>/http-trace.jsonl AND writes a per-call file
                           under <dir>/exchanges/NNNN-<method>-<host>.txt
                           so the report agent can cite individual probes.
"""
from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlsplit

from langchain_core.tools import tool

MAX_OUTPUT = 12_000
MAX_TRACE_BYTES = 256_000  # full body cap per exchange file
_TRACE_SEQ_LOCK = threading.Lock()
_TRACE_SEQ = 0


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


_JAR_NAME_RE = re.compile(r"[^A-Za-z0-9._-]")


def _cookie_jar_path(name: str) -> Optional[str]:
    """Resolve a named cookie jar to an absolute file path. Returns None for
    empty names (stateless mode). Sanitises the name to keep it inside
    DAPPER_HTTP_STATE_DIR/cookies/."""
    if not name:
        return None
    safe = _JAR_NAME_RE.sub("_", name)[:64] or "default"
    root = os.environ.get("DAPPER_HTTP_STATE_DIR") or "/tmp/dapper-http-state"
    jar_dir = Path(root) / "cookies"
    jar_dir.mkdir(parents=True, exist_ok=True)
    return str(jar_dir / f"{safe}.txt")


def _next_trace_seq() -> int:
    global _TRACE_SEQ
    with _TRACE_SEQ_LOCK:
        _TRACE_SEQ += 1
        return _TRACE_SEQ


def _safe_host(url: str) -> str:
    try:
        host = urlsplit(url).hostname or "unknown"
    except ValueError:
        host = "unknown"
    return _JAR_NAME_RE.sub("_", host)[:64] or "unknown"


def _log_exchange(
    method: str,
    url: str,
    headers: dict[str, Any],
    body: str,
    response: str,
    cookie_jar: str,
) -> None:
    """Append one exchange to the JSONL trace + write a human-readable per-call
    file. No-op when DAPPER_HTTP_TRACE_DIR is unset."""
    trace_dir = os.environ.get("DAPPER_HTTP_TRACE_DIR")
    if not trace_dir:
        return
    try:
        seq = _next_trace_seq()
        root = Path(trace_dir)
        ex_dir = root / "exchanges"
        ex_dir.mkdir(parents=True, exist_ok=True)
        resp_for_trace = response[:MAX_TRACE_BYTES]
        body_for_trace = body[:MAX_TRACE_BYTES]
        record = {
            "seq": seq,
            "ts": time.time(),
            "method": method,
            "url": url,
            "headers": headers,
            "body_bytes": len(body),
            "response_bytes": len(response),
            "cookie_jar": cookie_jar or None,
        }
        with (root / "http-trace.jsonl").open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
        ex_path = ex_dir / f"{seq:04d}-{method}-{_safe_host(url)}.txt"
        hdr_lines = "\n".join(f"{k}: {v}" for k, v in headers.items())
        ex_path.write_text(
            f"# REQUEST\n{method} {url}\n{hdr_lines}\n\n{body_for_trace}\n\n"
            f"# RESPONSE\n{resp_for_trace}\n"
        )
    except Exception:
        # Trace logging must never break a probe.
        pass


def _curl_invoke(
    method: str,
    url: str,
    headers: dict[str, Any],
    body: Optional[str],
    cookie_jar: str,
    extra_args: Optional[list[str]] = None,
    timeout: int = 45,
) -> str:
    """Build and run a curl command with cookie-jar + trace plumbing. Returns
    the same string the @tool callers return to the agent."""
    cmd = ["curl", "-sSL", "-D", "-", "--max-time", "30", "-X", method]
    jar = _cookie_jar_path(cookie_jar)
    if jar:
        cmd += ["-b", jar, "-c", jar]
    for k, v in headers.items():
        cmd += ["-H", f"{k}: {v}"]
    if extra_args:
        cmd += extra_args
    if body:
        cmd += ["--data-raw", body]
    cmd.append(url)
    out = _run(cmd, timeout=timeout)
    _log_exchange(method, url, headers, body or "", out, cookie_jar)
    return out


@tool
def http_get(url: str, headers_json: str = "{}", cookie_jar: str = "") -> str:
    """Fetch a URL with curl.

    Args:
      url: full target URL.
      headers_json: JSON object of extra headers.
      cookie_jar: optional name (e.g. "admin", "victim"). When set, cookies
        are loaded from and saved to a per-name jar file so subsequent
        http_get/http_request/http_upload calls with the same name share
        session state. Leave empty for stateless requests.
    """
    try:
        headers = json.loads(headers_json or "{}")
    except json.JSONDecodeError as exc:
        return f"ERROR: headers_json is not valid JSON: {exc}"
    return _curl_invoke("GET", url, headers, None, cookie_jar)


@tool
def http_request(
    method: str,
    url: str,
    headers_json: str = "{}",
    body: str = "",
    cookie_jar: str = "",
) -> str:
    """Send an HTTP request with any verb (POST/PUT/PATCH/DELETE/OPTIONS/HEAD/GET).

    Args:
      method: HTTP verb, case-insensitive (e.g. "POST").
      url: full target URL.
      headers_json: JSON object of extra headers, e.g.
        '{"Content-Type":"application/json","Authorization":"Bearer ..."}'.
      body: raw request body. For JSON, pass the serialized string and set
        Content-Type in headers_json.
      cookie_jar: optional named jar; see http_get for semantics.

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
    return _curl_invoke(verb, url, headers, body or None, cookie_jar)


@tool
def http_upload(
    url: str,
    fields_json: str = "{}",
    files_json: str = "{}",
    headers_json: str = "{}",
    method: str = "POST",
    cookie_jar: str = "",
) -> str:
    """Send a multipart/form-data request (file upload).

    Args:
      url: full target URL.
      fields_json: JSON object of non-file form fields, e.g.
        '{"title":"avatar","public":"true"}'.
      files_json: JSON object mapping field name -> local file path, e.g.
        '{"file":"/tmp/payload.svg","extra":"/tmp/notes.txt"}'. Paths must
        exist; the file's content-type is auto-detected by curl.
      headers_json: extra headers (do NOT set Content-Type — curl picks the
        right multipart boundary).
      method: POST (default) or PUT.
      cookie_jar: optional named jar; see http_get for semantics.

    Useful for testing upload endpoints for unrestricted-file-upload,
    path-traversal in filename, SSRF via uploaded SVG/XML, etc.
    """
    verb = (method or "POST").upper()
    if verb not in {"POST", "PUT"}:
        return f"ERROR: http_upload only supports POST or PUT, got {verb!r}"
    try:
        fields = json.loads(fields_json or "{}")
        files = json.loads(files_json or "{}")
        headers = json.loads(headers_json or "{}")
    except json.JSONDecodeError as exc:
        return f"ERROR: invalid JSON: {exc}"
    if not isinstance(fields, dict) or not isinstance(files, dict):
        return "ERROR: fields_json and files_json must be JSON objects"
    for fname, fpath in files.items():
        if not Path(fpath).is_file():
            return f"ERROR: upload file not found: {fname} -> {fpath}"

    extra: list[str] = []
    for name, value in fields.items():
        extra += ["-F", f"{name}={value}"]
    for name, path in files.items():
        extra += ["-F", f"{name}=@{path}"]

    out = _curl_invoke(verb, url, headers, None, cookie_jar, extra_args=extra, timeout=120)
    # Hand-roll a trace body that names the files, since _curl_invoke saw no body.
    if os.environ.get("DAPPER_HTTP_TRACE_DIR"):
        try:
            (Path(os.environ["DAPPER_HTTP_TRACE_DIR"]) / "exchanges").mkdir(parents=True, exist_ok=True)
        except Exception:
            pass
    return out


@tool
def clear_cookie_jar(name: str) -> str:
    """Delete a named cookie jar so the next call with that jar starts fresh.
    Useful for re-logging-in as the same user or switching identities."""
    jar = _cookie_jar_path(name)
    if not jar:
        return "ERROR: provide a non-empty jar name"
    p = Path(jar)
    if p.exists():
        p.unlink()
        return f"cleared {jar}"
    return f"no jar at {jar} (nothing to clear)"


@tool
def list_cookie_jars() -> str:
    """List the named cookie jars created so far in this run. Each line is
    `name  size_bytes  mtime_iso`."""
    root = os.environ.get("DAPPER_HTTP_STATE_DIR") or "/tmp/dapper-http-state"
    jar_dir = Path(root) / "cookies"
    if not jar_dir.is_dir():
        return "(no jars yet)"
    rows = []
    for p in sorted(jar_dir.glob("*.txt")):
        st = p.stat()
        rows.append(f"{p.stem}\t{st.st_size}\t{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(st.st_mtime))}")
    return "\n".join(rows) or "(no jars yet)"


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
    http_upload,
    clear_cookie_jar,
    list_cookie_jars,
    nuclei_scan,
    nmap_scan,
    subfinder_scan,
    whatweb_fingerprint,
    sqlmap_probe,
    ffuf_dirfuzz,
    write_finding,
    read_file,
]
