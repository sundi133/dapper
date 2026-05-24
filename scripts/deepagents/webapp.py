"""FastAPI web app for the Dapper DeepAgents orchestrator.

Run:
    uvicorn scripts.deepagents.webapp:app --host 0.0.0.0 --port 8000
or:
    ./dapper web
"""
from __future__ import annotations

import hashlib
import hmac
import io
import json
import os
import secrets
import subprocess
import time
import zipfile
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response, StreamingResponse
from pydantic import BaseModel

from . import db
from .session import (
    drain_events,
    get_session,
    list_sessions,
    start_session,
    submit_answer,
    submit_message,
)

load_dotenv()

REPO_ROOT = Path(__file__).resolve().parents[2]
REPOS_DIR = REPO_ROOT / "repos"
CONFIGS_DIR = REPO_ROOT / "configs"
AUDIT_DIR = REPO_ROOT / "audit-logs"

app = FastAPI(title="Dapper DeepAgents")


# ---------------------------------------------------------------------------
# Browser auth: a single shared password from $DAPPER_WEB_PASSWORD. When the
# env var is unset, the gate is disabled and the app stays fully open (this
# preserves local Docker-compose use where there's nothing to protect).
#
# Sessions are stateless HMAC-signed cookies — no DB row per session. The
# signing key comes from $DAPPER_SESSION_SECRET; if absent we generate a
# random one at startup, which means all cookies are invalidated on restart
# (acceptable for an admin tool, and safer than a hardcoded default).
# ---------------------------------------------------------------------------

COOKIE_NAME = "dapper_session"
SESSION_TTL_SECONDS = 7 * 24 * 3600

_SESSION_SECRET = (
    os.environ.get("DAPPER_SESSION_SECRET")
    or secrets.token_urlsafe(32)
).encode()


def _auth_required() -> Optional[str]:
    pw = os.environ.get("DAPPER_WEB_PASSWORD") or ""
    return pw if pw else None


def _sign_session(exp_unix: int) -> str:
    payload = str(exp_unix).encode()
    sig = hmac.new(_SESSION_SECRET, payload, hashlib.sha256).hexdigest()
    return f"{exp_unix}.{sig}"


def _valid_cookie(value: Optional[str]) -> bool:
    if not value or "." not in value:
        return False
    try:
        exp_str, sig = value.rsplit(".", 1)
        exp = int(exp_str)
    except (ValueError, TypeError):
        return False
    if exp < int(time.time()):
        return False
    expected = hmac.new(_SESSION_SECRET, exp_str.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, sig)


def _wants_html(request: Request) -> bool:
    """True if this looks like a browser navigation (so we 302 to /login
    instead of returning 401 JSON)."""
    accept = request.headers.get("accept", "")
    return "text/html" in accept and request.method == "GET"


# Paths that bypass the cookie gate entirely. /api/scans has its own
# Bearer-token auth for CI callers and is checked separately below.
_AUTH_EXEMPT_PATHS = {"/login", "/api/login", "/api/logout", "/api/health", "/api/auth-status"}


@app.middleware("http")
async def _password_gate(request: Request, call_next):
    pw = _auth_required()
    if pw is None:
        return await call_next(request)

    path = request.url.path
    if path in _AUTH_EXEMPT_PATHS:
        return await call_next(request)

    # The CI scan-trigger endpoint authenticates via Authorization: Bearer
    # against the api_keys table — let that path through so the cookie gate
    # doesn't double-gate it.
    if path == "/api/scans" and request.method == "POST":
        if (request.headers.get("authorization") or "").lower().startswith("bearer "):
            return await call_next(request)

    if _valid_cookie(request.cookies.get(COOKIE_NAME)):
        return await call_next(request)

    if _wants_html(request):
        return RedirectResponse(url=f"/login?next={path}", status_code=302)
    return JSONResponse(
        {"detail": "authentication required"},
        status_code=401,
        headers={"WWW-Authenticate": 'Cookie realm="dapper"'},
    )


class LoginRequest(BaseModel):
    password: str


@app.post("/api/login")
def login(req: LoginRequest):
    pw = _auth_required()
    if pw is None:
        # Login endpoint is meaningless when auth is disabled — return 204
        # so the UI can detect "no password set" and skip the login page.
        return Response(status_code=204)
    if not hmac.compare_digest(req.password.encode(), pw.encode()):
        raise HTTPException(status_code=401, detail="invalid password")
    exp = int(time.time()) + SESSION_TTL_SECONDS
    resp = JSONResponse({"ok": True})
    resp.set_cookie(
        COOKIE_NAME,
        _sign_session(exp),
        max_age=SESSION_TTL_SECONDS,
        httponly=True,
        samesite="lax",
        secure=False,  # Set True behind HTTPS-only proxies; lax default works for both.
        path="/",
    )
    return resp


@app.post("/api/logout")
def logout():
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(COOKIE_NAME, path="/")
    return resp


@app.get("/api/auth-status")
def auth_status(request: Request):
    """Lets the UI know whether auth is enabled, and if so, whether the
    current cookie is valid. Always cheap and never 401s."""
    if _auth_required() is None:
        return {"required": False, "authenticated": True}
    return {
        "required": True,
        "authenticated": _valid_cookie(request.cookies.get(COOKIE_NAME)),
    }


@app.on_event("startup")
def _startup() -> None:
    db.init()
    if _auth_required() is not None:
        if not os.environ.get("DAPPER_SESSION_SECRET"):
            import logging
            logging.getLogger(__name__).warning(
                "DAPPER_WEB_PASSWORD is set but DAPPER_SESSION_SECRET is not — "
                "cookies will be invalidated on every restart. Set "
                "DAPPER_SESSION_SECRET to a stable random value to persist logins."
            )


# ---------------------------------------------------------------------------
# JSON API
# ---------------------------------------------------------------------------

@app.get("/api/health")
def health():
    return {
        "ok": True,
        "anthropic_key_set": bool(os.environ.get("ANTHROPIC_API_KEY")),
    }


@app.get("/api/repos")
def list_repos():
    if not REPOS_DIR.exists():
        return {"repos": []}
    return {"repos": sorted(p.name for p in REPOS_DIR.iterdir() if p.is_dir())}


@app.get("/api/configs")
def list_configs():
    if not CONFIGS_DIR.exists():
        return {"configs": []}
    return {"configs": sorted(p.name for p in CONFIGS_DIR.glob("*.yaml"))}


@app.get("/api/configs/{name}")
def get_config(name: str):
    """Return the raw YAML so the UI can prefill the editor when a built-in
    config is picked."""
    path = CONFIGS_DIR / name
    if ".." in name or not path.exists():
        raise HTTPException(status_code=404, detail="config not found")
    return JSONResponse({"name": name, "content": path.read_text()})


class StartRequest(BaseModel):
    url: str
    repo: Optional[str] = None
    repo_git_url: Optional[str] = None
    repo_git_token: Optional[str] = None  # one-shot; never stored or logged
    config: Optional[str] = None
    config_yaml: Optional[str] = None  # paste-your-own YAML
    classes: Optional[list[str]] = None
    skip_exploit: bool = False
    model: str = "claude-opus-4-7"
    initial_message: Optional[str] = None


@app.post("/api/sessions")
def create_session(req: StartRequest):
    if not os.environ.get("ANTHROPIC_API_KEY"):
        raise HTTPException(status_code=400, detail="ANTHROPIC_API_KEY not set on server")
    if not req.url.startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="url must start with http:// or https://")

    repo_name = req.repo or ""
    if req.repo_git_url:
        if not repo_name:
            tail = req.repo_git_url.rstrip("/").rsplit("/", 1)[-1]
            repo_name = tail[:-4] if tail.endswith(".git") else tail
        REPOS_DIR.mkdir(parents=True, exist_ok=True)
        target = REPOS_DIR / repo_name
        if not target.exists():
            # Build a one-shot Authorization header rather than embedding the
            # token in the URL — keeps the token out of .git/config, out of
            # `ps aux` URL substrings, and out of any error path that echoes
            # the clone URL back. The header is set via `-c` so it lives for
            # this git invocation only.
            cmd = ["git"]
            if req.repo_git_token:
                import base64 as _b64
                hdr = _b64.b64encode(f"x-access-token:{req.repo_git_token}".encode()).decode()
                cmd += ["-c", f"http.extraheader=Authorization: Basic {hdr}"]
            cmd += ["clone", "--depth", "1", req.repo_git_url, str(target)]
            env = {
                **os.environ,
                # Block interactive credential prompts so a bad token fails
                # fast instead of hanging the request.
                "GIT_TERMINAL_PROMPT": "0",
                "GIT_ASKPASS": "/bin/true",
                "GCM_INTERACTIVE": "never",
            }
            proc = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=300)
            if proc.returncode != 0:
                # Strip the header (and any token-looking string) from stderr
                # before bubbling it back to the client.
                stderr = proc.stderr
                if req.repo_git_token:
                    stderr = stderr.replace(req.repo_git_token, "***")
                stderr = stderr.replace(hdr, "***") if req.repo_git_token else stderr
                raise HTTPException(
                    status_code=400,
                    detail=f"git clone failed: {stderr[-500:]}",
                )
    elif repo_name:
        if not (REPOS_DIR / repo_name).is_dir():
            raise HTTPException(status_code=400, detail=f"./repos/{repo_name} does not exist")

    config_path: Optional[str] = None
    if req.config:
        candidate = CONFIGS_DIR / req.config
        if not candidate.exists():
            candidate = Path(req.config)
        if not candidate.exists():
            raise HTTPException(status_code=400, detail=f"config not found: {req.config}")
        config_path = str(candidate)

    host = req.url.split("://", 1)[-1].split("/", 1)[0].replace(":", "_")
    deliverables = str(AUDIT_DIR / f"{host}_deepagent-{int(time.time())}" / "deliverables")

    session = start_session(
        url=req.url,
        repo=repo_name,
        config_path=config_path,
        deliverables=deliverables,
        model=req.model,
        classes=req.classes,
        skip_exploit=req.skip_exploit,
        initial_message=req.initial_message,
        config_yaml_text=req.config_yaml,
    )
    return {
        "id": session.id,
        "url": session.url,
        "repo": session.repo,
        "deliverables": session.deliverables,
        "status": session.status,
    }


@app.get("/api/sessions")
def get_sessions():
    return {"sessions": list_sessions()}


@app.get("/api/sessions/{sid}")
def get_session_info(sid: str):
    s = get_session(sid)
    if not s:
        raise HTTPException(status_code=404, detail="session not found")
    return {
        "id": s.id,
        "url": s.url,
        "repo": s.repo,
        "config_path": s.config_path,
        "deliverables": s.deliverables,
        "status": s.status,
        "error": s.error,
        "pending_question": (
            {"qid": s.pending_question.qid, "question": s.pending_question.question}
            if s.pending_question else None
        ),
    }


@app.get("/api/sessions/{sid}/events")
def stream_events(sid: str):
    s = get_session(sid)
    if not s:
        raise HTTPException(status_code=404, detail="session not found")

    def gen():
        for evt in drain_events(s):
            yield f"data: {json.dumps(evt)}\n\n"

    return StreamingResponse(gen(), media_type="text/event-stream")


class MessageRequest(BaseModel):
    message: str


@app.post("/api/sessions/{sid}/messages")
def post_message(sid: str, req: MessageRequest):
    """Single chat endpoint: routes to ask_user if the agent is blocked,
    otherwise queues as a follow-up turn."""
    s = get_session(sid)
    if not s:
        raise HTTPException(status_code=404, detail="session not found")
    if not req.message.strip():
        raise HTTPException(status_code=400, detail="empty message")
    return submit_message(s, req.message)


class AnswerRequest(BaseModel):
    qid: str
    answer: str


@app.post("/api/sessions/{sid}/answer")
def answer(sid: str, req: AnswerRequest):
    """Legacy endpoint kept for compatibility."""
    s = get_session(sid)
    if not s:
        raise HTTPException(status_code=404, detail="session not found")
    ok = submit_answer(s, req.qid, req.answer)
    if not ok:
        raise HTTPException(status_code=409, detail="no matching pending question")
    return {"ok": True}


@app.get("/api/sessions/{sid}/deliverables")
def list_deliverables(sid: str):
    s = get_session(sid)
    if not s:
        raise HTTPException(status_code=404, detail="session not found")
    p = Path(s.deliverables)
    # Best-effort sync to Postgres so historical lookups see the same files
    # the agent just wrote. No-op when the DB is disabled.
    if db.enabled():
        db.sync_from_disk(s.id, str(p))
    if not p.exists():
        return {"files": []}
    files = []
    for f in sorted(p.glob("**/*")):
        if f.is_file():
            files.append({"path": str(f.relative_to(p)), "bytes": f.stat().st_size})
    return {"files": files}


# ---------------------------------------------------------------------------
# Historical scans
#
# Two sources, transparently merged:
#   1. Postgres (preferred) — survives container restarts.
#   2. The audit-logs/ directory — works for legacy scans pre-DB and for
#      local dev when DATABASE_URL isn't set.
#
# The URL key is whichever identifier the frontend hands back: a DB scan id
# (session UUID, 12 hex) or a disk folder name (host_deepagent-<epoch>).
# ---------------------------------------------------------------------------

def _scan_folder(name: str) -> Optional[Path]:
    """Return the matching folder under AUDIT_DIR if one exists, else None."""
    if "/" in name or ".." in name:
        raise HTTPException(status_code=400, detail="invalid scan id")
    p = (AUDIT_DIR / name).resolve()
    if not str(p).startswith(str(AUDIT_DIR.resolve())):
        raise HTTPException(status_code=400, detail="path traversal")
    return p if p.is_dir() else None


def _resolve_scan_folder_for_db_id(scan_id: str) -> Optional[Path]:
    """If the DB knows a scan_folder for this id, try resolving it on disk."""
    if not db.enabled():
        return None
    for s in db.list_scans():
        if s["id"] == scan_id and s.get("scan_folder"):
            return _scan_folder(s["scan_folder"])
    return None


def _disk_scans() -> list[dict]:
    """Walk AUDIT_DIR for scan folders with meta.json or deliverables/."""
    if not AUDIT_DIR.exists():
        return []
    live_ids = {s["id"] for s in list_sessions()}
    out: list[dict] = []
    for d in AUDIT_DIR.iterdir():
        if not d.is_dir():
            continue
        deliv = d / "deliverables"
        meta_path = d / "meta.json"
        has_deliv = deliv.exists() and any(deliv.iterdir())
        if not (has_deliv or meta_path.exists()):
            continue
        meta: dict = {}
        if meta_path.exists():
            try:
                meta = json.loads(meta_path.read_text())
            except Exception:
                meta = {}
        started_at = meta.get("started_at")
        if started_at is None:
            tail = d.name.rsplit("-", 1)[-1]
            started_at = int(tail) if tail.isdigit() else d.stat().st_mtime
        file_count = sum(1 for _ in deliv.glob("**/*") if _.is_file()) if deliv.exists() else 0
        # Prefer the session id as the canonical scan_id when meta has it —
        # that's what Postgres uses, so both sources align on the same key.
        scan_id = meta.get("id") or d.name
        out.append({
            "scan_id": scan_id,
            "scan_folder": d.name,
            "url": meta.get("url"),
            "repo": meta.get("repo"),
            "started_at": started_at,
            "file_count": file_count,
            "live": meta.get("id") in live_ids,
        })
    return out


@app.get("/api/scans")
def list_scans_endpoint():
    """Merged scan list from Postgres + disk. DB rows take precedence."""
    live_ids = {s["id"] for s in list_sessions()}
    by_id: dict[str, dict] = {}
    # Postgres is the source of truth when present.
    for s in db.list_scans():
        by_id[s["id"]] = {
            "scan_id": s["id"],
            "scan_folder": s.get("scan_folder"),
            "url": s.get("url"),
            "repo": s.get("repo"),
            "started_at": s.get("started_at"),
            "file_count": s.get("file_count", 0),
            "live": s["id"] in live_ids,
            "status": s.get("status"),
        }
    # Backfill anything found on disk that the DB doesn't know about
    # (legacy scans, or DB-disabled mode).
    for s in _disk_scans():
        by_id.setdefault(s["scan_id"], s)
    out = sorted(by_id.values(), key=lambda r: r.get("started_at") or 0, reverse=True)
    return {"scans": out}


@app.get("/api/scans/{name}/deliverables")
def list_scan_deliverables(name: str):
    if db.enabled() and db.scan_exists(name):
        return {"files": db.list_deliverables(name)}
    folder = _resolve_scan_folder_for_db_id(name) or _scan_folder(name)
    if not folder:
        raise HTTPException(status_code=404, detail="scan not found")
    deliv = folder / "deliverables"
    if not deliv.exists():
        return {"files": []}
    files = []
    for f in sorted(deliv.glob("**/*")):
        if f.is_file():
            files.append({"path": str(f.relative_to(deliv)), "bytes": f.stat().st_size})
    return {"files": files}


@app.get("/api/scans/{name}/deliverables/{path:path}")
def read_scan_deliverable(name: str, path: str):
    if db.enabled() and db.scan_exists(name):
        content = db.get_deliverable(name, path)
        if content is None:
            raise HTTPException(status_code=404, detail="not found")
        return JSONResponse({"path": path, "content": content})
    folder = _resolve_scan_folder_for_db_id(name) or _scan_folder(name)
    if not folder:
        raise HTTPException(status_code=404, detail="scan not found")
    base = (folder / "deliverables").resolve()
    target = (base / path).resolve()
    if not str(target).startswith(str(base)):
        raise HTTPException(status_code=400, detail="path traversal")
    if not target.is_file():
        raise HTTPException(status_code=404, detail="not found")
    return JSONResponse({"path": path, "content": target.read_text(errors="replace")})


@app.get("/api/scans/{name}/deliverables.zip")
def download_scan_zip(name: str):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        if db.enabled() and db.scan_exists(name):
            for f in db.list_deliverables(name):
                content = db.get_deliverable(name, f["path"]) or ""
                zf.writestr(f["path"], content)
        else:
            folder = _resolve_scan_folder_for_db_id(name) or _scan_folder(name)
            if not folder:
                raise HTTPException(status_code=404, detail="scan not found")
            base = folder / "deliverables"
            if base.exists():
                for f in base.glob("**/*"):
                    if f.is_file():
                        zf.write(f, arcname=str(f.relative_to(base)))
    return Response(
        content=buf.getvalue(),
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="dapper-{name}.zip"'},
    )


@app.get("/api/sessions/{sid}/deliverables.zip")
def download_deliverables_zip(sid: str):
    s = get_session(sid)
    if not s:
        raise HTTPException(status_code=404, detail="session not found")
    base = Path(s.deliverables)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        if base.exists():
            for f in base.glob("**/*"):
                if f.is_file():
                    zf.write(f, arcname=str(f.relative_to(base)))
    host = (s.url.split("://", 1)[-1].split("/", 1)[0].replace(":", "_") or "session")
    filename = f"dapper-{host}-{sid[:8]}.zip"
    return Response(
        content=buf.getvalue(),
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/api/sessions/{sid}/deliverables/{path:path}")
def read_deliverable(sid: str, path: str):
    s = get_session(sid)
    if not s:
        raise HTTPException(status_code=404, detail="session not found")
    base = Path(s.deliverables).resolve()
    target = (base / path).resolve()
    if not str(target).startswith(str(base)):
        raise HTTPException(status_code=400, detail="path traversal")
    if not target.is_file():
        raise HTTPException(status_code=404, detail="not found")
    return JSONResponse({"path": path, "content": target.read_text(errors="replace")})


# ---------------------------------------------------------------------------
# API keys (CI/CD callers) — list / mint / revoke. The plaintext token is
# returned exactly once on mint; thereafter only the prefix is visible.
# ---------------------------------------------------------------------------

class CreateKeyRequest(BaseModel):
    label: Optional[str] = None


@app.get("/api/keys")
def list_keys():
    if not db.enabled():
        raise HTTPException(status_code=503, detail="DATABASE_URL not configured")
    return {"keys": db.list_api_keys()}


@app.post("/api/keys")
def create_key(req: CreateKeyRequest):
    if not db.enabled():
        raise HTTPException(status_code=503, detail="DATABASE_URL not configured")
    label = (req.label or "").strip() or None
    out = db.create_api_key(label)
    if not out:
        raise HTTPException(status_code=500, detail="failed to create key")
    return out


@app.delete("/api/keys/{key_id}")
def delete_key(key_id: str):
    if not db.enabled():
        raise HTTPException(status_code=503, detail="DATABASE_URL not configured")
    if not db.revoke_api_key(key_id):
        raise HTTPException(status_code=404, detail="key not found or already revoked")
    return {"ok": True}


def _require_bearer(authorization: Optional[str]) -> str:
    """Validate a Bearer token from the Authorization header. Returns the
    key id on success; raises 401 otherwise. Used by /api/scans (the CI-
    facing trigger endpoint)."""
    if not db.enabled():
        raise HTTPException(status_code=503, detail="API keys require DATABASE_URL")
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(
            status_code=401,
            detail="missing Authorization: Bearer <token> header",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = authorization.split(" ", 1)[1].strip()
    key_id = db.verify_api_key(token)
    if not key_id:
        raise HTTPException(
            status_code=401,
            detail="invalid or revoked API key",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return key_id


@app.post("/api/scans")
def create_scan_ci(req: StartRequest, authorization: Optional[str] = Header(None)):
    """CI/CD-facing alias of POST /api/sessions. Requires a valid Bearer
    token from a key minted in the CI/CD tab. The browser UI keeps using
    /api/sessions unauthenticated; this endpoint exists so we can require
    auth on the CI path without breaking local use."""
    _require_bearer(authorization)
    return create_session(req)


# ---------------------------------------------------------------------------
# Single-page UI
# ---------------------------------------------------------------------------

INDEX_HTML = r"""<!doctype html>
<html>
<head>
<meta charset="utf-8" />
<title>Dapper DeepAgents</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; background:#0b0d10; color:#d8dee9; margin:0; }
  header { padding:14px 22px; border-bottom:1px solid #1f2937; display:flex; gap:20px; align-items:center; }
  header h1 { margin:0; font-size:18px; }
  header .status { color:#9aa5b1; font-size:12px; margin-left:auto; }
  header nav { display:flex; gap:4px; }
  header nav a {
    color:#9aa5b1; text-decoration:none; font-size:12px; padding:6px 12px;
    border-radius:4px; border:1px solid transparent; cursor:pointer;
  }
  header nav a:hover { color:#d8dee9; background:#11151b; }
  header nav a.active { color:#d8dee9; background:#11151b; border-color:#233040; }
  main { display:grid; grid-template-columns: 380px 1fr; height:calc(100vh - 51px); }
  .page { padding:22px 28px; overflow:auto; height:calc(100vh - 51px); }
  .page h2 { margin:0 0 4px 0; font-size:16px; }
  .page .sub { color:#6b7280; font-size:12px; margin-bottom:18px; }
  .page section { margin-bottom:28px; }
  .runs-toolbar { display:flex; gap:10px; margin-bottom:12px; align-items:center; flex-wrap:wrap; }
  .runs-toolbar input, .runs-toolbar select {
    width:auto; margin:0; font-size:12px; padding:6px 10px;
  }
  .runs-toolbar .stretch { flex:1; min-width:200px; }
  table.runs { width:100%; border-collapse:collapse; font-size:12px; }
  table.runs th, table.runs td {
    text-align:left; padding:8px 10px; border-bottom:1px solid #1f2937;
    vertical-align:top;
  }
  table.runs th {
    color:#9aa5b1; font-weight:normal; font-size:11px; text-transform:uppercase;
    letter-spacing:0.05em; cursor:pointer; user-select:none; white-space:nowrap;
  }
  table.runs th.sorted-asc::after  { content:" ↑"; color:#6b7280; }
  table.runs th.sorted-desc::after { content:" ↓"; color:#6b7280; }
  table.runs tbody tr { cursor:pointer; }
  table.runs tbody tr:hover { background:#11151b; }
  table.runs td.url { word-break:break-all; max-width:0; }
  table.runs .pill {
    display:inline-block; padding:1px 7px; border-radius:8px;
    font-size:10px; border:1px solid;
  }
  .pill.running   { color:#60a5fa; border-color:#60a5fa; }
  .pill.completed { color:#10b981; border-color:#10b981; }
  .pill.error     { color:#f87171; border-color:#f87171; }
  .pill.unknown   { color:#9aa5b1; border-color:#374151; }
  .keys-table { width:100%; border-collapse:collapse; font-size:12px; margin-top:8px; }
  .keys-table th, .keys-table td { padding:8px 10px; border-bottom:1px solid #1f2937; text-align:left; }
  .keys-table th { color:#9aa5b1; font-weight:normal; font-size:11px; }
  .keys-table code { font-family: inherit; color:#d8dee9; }
  .keys-table tr.revoked td { color:#6b7280; }
  .key-reveal {
    background:#0e1217; border:1px solid #f59e0b; border-radius:6px;
    padding:12px 14px; margin-top:10px;
  }
  .key-reveal .warn { color:#f59e0b; font-size:11px; margin-bottom:6px; }
  .key-reveal code {
    display:block; padding:8px 10px; background:#000; border-radius:4px;
    word-break:break-all; user-select:all; font-size:12px;
  }
  .snippet {
    background:#0e1217; border:1px solid #233040; border-radius:6px;
    padding:12px 14px; position:relative; margin-bottom:14px;
  }
  .snippet .lbl { font-size:11px; color:#9aa5b1; margin-bottom:6px; }
  .snippet pre {
    margin:0; font-size:11px; color:#d8dee9; white-space:pre-wrap;
    word-break:break-word;
  }
  .snippet .copy {
    position:absolute; top:8px; right:8px; width:auto;
    font-size:10px; padding:3px 8px; margin:0;
  }
  .inline-form { display:flex; gap:8px; align-items:flex-end; max-width:520px; }
  .inline-form input { margin:0; }
  .inline-form button { width:auto; margin:0; padding:8px 14px; }
  aside { border-right:1px solid #1f2937; padding:18px; overflow:auto; }
  section.chat { display:flex; flex-direction:column; min-width:0; }
  label { display:block; margin-top:12px; font-size:12px; color:#9aa5b1; }
  input, select, button, textarea {
    width:100%; padding:8px 10px; margin-top:4px;
    background:#11151b; color:#d8dee9; border:1px solid #233040; border-radius:4px;
    font: inherit;
  }
  textarea { font-size:12px; }
  button { background:#2563eb; border-color:#2563eb; color:white; cursor:pointer; margin-top:14px; }
  button:disabled { opacity:0.5; cursor:not-allowed; }
  .chips { display:flex; flex-wrap:wrap; gap:4px; margin-top:6px; }
  .chip { font-size:11px; background:#1f2937; padding:3px 8px; border-radius:12px; cursor:pointer; }
  .chip.on { background:#2563eb; color:white; }
  .feed { flex:1; overflow:auto; padding:14px 18px; font-size:13px; }
  .msg { padding:10px 14px; margin-bottom:10px; border-radius:8px; word-break:break-word; line-height:1.5; }
  .msg.user { background:#0f2742; border:1px solid #1d3a5f; }
  .msg.agent { background:#0f141a; border:1px solid #1f2937; border-left:3px solid #2563eb; }
  .msg.question { background:#1f1809; border-left:3px solid #f59e0b; }
  .msg.error { background:#1a0d0d; border-left:3px solid #ef4444; color:#fecaca; white-space:pre-wrap; font-family:ui-monospace,monospace; font-size:12px; }
  .msg.status { color:#6b7280; font-size:11px; padding:2px 12px; background:transparent; text-align:center; }
  .msg .meta { font-size:10px; color:#6b7280; margin-bottom:4px; text-transform:uppercase; letter-spacing:0.04em; }
  .msg .body { font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif; }
  .msg .body p { margin:0 0 8px 0; } .msg .body p:last-child { margin-bottom:0; }
  .msg .body code { background:#1a2230; padding:1px 5px; border-radius:3px; font-family:ui-monospace,monospace; font-size:0.92em; }
  .msg .body pre { background:#070a0e; border:1px solid #1f2937; padding:10px 12px; border-radius:5px; overflow:auto; font-family:ui-monospace,monospace; font-size:12px; margin:6px 0; }
  .msg .body pre code { background:transparent; padding:0; }
  .msg .body h1,.msg .body h2,.msg .body h3 { margin:10px 0 4px 0; font-size:1em; color:#e5e7eb; }
  .msg .body ul,.msg .body ol { margin:4px 0; padding-left:20px; }
  .msg .body a { color:#60a5fa; }
  .msg .body strong { color:#f3f4f6; }
  .msg .body em { color:#cbd5e1; }
  .tool { background:#0c1014; border:1px solid #1f2937; border-left:2px solid #374151; margin-bottom:8px; border-radius:6px; font-size:12px; }
  .tool summary { cursor:pointer; padding:6px 10px; user-select:none; color:#9aa5b1; display:flex; gap:8px; align-items:center; list-style:none; }
  .tool summary::-webkit-details-marker { display:none; }
  .tool summary::before { content:"▸"; transition:transform 0.1s; }
  .tool[open] summary::before { transform:rotate(90deg); }
  .tool .name { color:#60a5fa; font-weight:600; }
  .tool .args { color:#6b7280; font-size:11px; flex:1; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
  .tool .pending { color:#f59e0b; font-size:11px; }
  .tool .done { color:#10b981; font-size:11px; }
  .tool pre { margin:0; padding:10px 12px; background:#070a0e; border-top:1px solid #1f2937; overflow:auto; max-height:300px; font-family:ui-monospace,monospace; font-size:11px; color:#cbd5e1; white-space:pre-wrap; word-break:break-all; }
  .typing { display:inline-block; margin-left:6px; color:#6b7280; }
  .typing::after { content:"●"; animation:blink 1s infinite; }
  @keyframes blink { 0%,40%{opacity:0.2} 50%{opacity:1} 100%{opacity:0.2} }
  .composer { border-top:1px solid #1f2937; padding:12px 18px; background:#0f141a; }
  .composer .pending { color:#f59e0b; font-size:11px; margin-bottom:6px; }
  .composer .row { display:flex; gap:8px; }
  .composer textarea { flex:1; min-height:50px; max-height:160px; resize:vertical; margin:0; }
  .composer button { width:auto; align-self:stretch; margin:0; padding:0 18px; }
  .composer .hint { font-size:10px; color:#6b7280; margin-top:4px; }
  .deliverables { padding:14px 0 0 0; margin-top:14px; border-top:1px solid #1f2937; font-size:12px; }
  .deliverables .head { display:flex; align-items:center; justify-content:space-between; margin-bottom:8px; }
  .deliverables h3 { margin:0; font-size:13px; color:#9aa5b1; }
  .deliverables .dl-zip { width:auto; padding:4px 10px; margin:0; font-size:11px; background:#1f2937; border-color:#374151; }
  .deliverables .dl-zip:disabled { opacity:0.4; }
  .deliverables .empty { color:#6b7280; font-size:11px; padding:8px 0; line-height:1.5; }
  .deliverables .file-row { display:flex; align-items:center; gap:6px; padding:4px 6px; border-radius:4px; cursor:pointer; word-break:break-all; }
  .deliverables .file-row:hover { background:#11151b; }
  .deliverables .file-row .name { color:#60a5fa; flex:1; }
  .deliverables .file-row .size { color:#6b7280; font-size:10px; }
  .deliverables .file-row.exec-summary { background:#0f2742; border:1px solid #1d3a5f; margin-bottom:6px; padding:8px 10px; }
  .deliverables .file-row.exec-summary .name { color:#93c5fd; font-weight:600; }
  .deliverables .file-row.exec-summary::before { content:"★"; color:#fbbf24; margin-right:2px; }
  .session-info { padding:10px 12px; background:#0f141a; border:1px solid #1f2937; border-radius:6px; font-size:11px; color:#9aa5b1; }
  .session-info .row { display:flex; justify-content:space-between; gap:8px; }
  .session-info .row + .row { margin-top:4px; }
  .session-info .row .k { color:#6b7280; }
  .session-info .row .v { color:#d8dee9; word-break:break-all; text-align:right; }
  .session-info .actions { display:flex; gap:6px; margin-top:10px; }
  .session-info .actions button { flex:1; margin:0; padding:5px 8px; font-size:11px; background:#1f2937; border-color:#374151; }
  .recent-scans { margin-top:18px; padding-top:14px; border-top:1px solid #1f2937; }
  .recent-scans h3 { margin:0 0 8px 0; font-size:13px; color:#9aa5b1; display:flex; align-items:center; gap:6px; }
  .recent-scans h3 .count { color:#6b7280; font-size:11px; font-weight:normal; }
  .recent-scans .empty { color:#6b7280; font-size:11px; }
  .recent-scans .scan-row { padding:8px 10px; margin-bottom:4px; border:1px solid #1f2937; border-radius:5px; cursor:pointer; font-size:11px; }
  .recent-scans .scan-row:hover { background:#11151b; border-color:#374151; }
  .recent-scans .scan-row .top { display:flex; justify-content:space-between; gap:6px; align-items:baseline; }
  .recent-scans .scan-row .url { color:#d8dee9; word-break:break-all; flex:1; font-size:12px; }
  .recent-scans .scan-row .badge { font-size:10px; color:#10b981; border:1px solid #10b981; padding:1px 5px; border-radius:8px; flex-shrink:0; }
  .recent-scans .scan-row .meta { color:#6b7280; margin-top:3px; display:flex; justify-content:space-between; }
  details.setup-collapse { margin-top:10px; }
  details.setup-collapse > summary { cursor:pointer; font-size:11px; color:#9aa5b1; list-style:none; padding:4px 0; }
  details.setup-collapse > summary::-webkit-details-marker { display:none; }
  details.setup-collapse > summary::before { content:"▸ "; }
  details.setup-collapse[open] > summary::before { content:"▾ "; }
  /* Markdown viewer overlay */
  .viewer-backdrop { position:fixed; inset:0; background:rgba(0,0,0,0.6); z-index:50; display:flex; align-items:stretch; justify-content:flex-end; }
  .viewer { width:min(820px, 92vw); height:100vh; background:#0b0d10; border-left:1px solid #1f2937; display:flex; flex-direction:column; }
  .viewer .vhead { display:flex; align-items:center; gap:10px; padding:12px 18px; border-bottom:1px solid #1f2937; }
  .viewer .vhead .title { flex:1; font-size:13px; color:#d8dee9; word-break:break-all; }
  .viewer .vhead button { width:auto; margin:0; padding:5px 10px; font-size:11px; background:#1f2937; border-color:#374151; }
  .viewer .vbody { flex:1; overflow:auto; padding:20px 28px; font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif; font-size:14px; line-height:1.6; color:#e5e7eb; }
  .viewer .vbody.raw { font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:12px; white-space:pre-wrap; word-break:break-all; }
  .viewer .vbody h1 { font-size:1.5em; margin:0 0 12px 0; padding-bottom:6px; border-bottom:1px solid #1f2937; }
  .viewer .vbody h2 { font-size:1.25em; margin:18px 0 8px 0; color:#f3f4f6; }
  .viewer .vbody h3 { font-size:1.1em; margin:14px 0 6px 0; color:#e5e7eb; }
  .viewer .vbody p { margin:0 0 10px 0; }
  .viewer .vbody ul,.viewer .vbody ol { margin:6px 0 10px 0; padding-left:24px; }
  .viewer .vbody code { background:#11151b; padding:2px 5px; border-radius:3px; font-family:ui-monospace,monospace; font-size:0.9em; }
  .viewer .vbody pre { background:#070a0e; border:1px solid #1f2937; padding:12px 14px; border-radius:5px; overflow:auto; font-size:12px; }
  .viewer .vbody pre code { background:transparent; padding:0; }
  .viewer .vbody a { color:#60a5fa; }
  .viewer .vbody strong { color:#f3f4f6; }
  .hidden { display:none !important; }
</style>
</head>
<body>
<header>
  <h1>Dapper × DeepAgents</h1>
  <nav>
    <a id="nav-start" data-tab="start" class="active">Start</a>
    <a id="nav-runs"  data-tab="runs">Runs</a>
    <a id="nav-cicd"  data-tab="cicd">CI/CD</a>
  </nav>
  <span class="status" id="hdr-status">disconnected</span>
  <a id="logout-link" href="#" class="hidden" style="margin-left:12px;color:#9aa5b1;font-size:12px;text-decoration:none;">Sign out</a>
</header>
<main id="page-start">
  <aside>
    <div id="session-info" class="session-info hidden">
      <div class="row"><span class="k">Target</span><span class="v" id="si-url"></span></div>
      <div class="row"><span class="k">Repo</span><span class="v" id="si-repo"></span></div>
      <div class="row"><span class="k">Status</span><span class="v" id="si-status">starting…</span></div>
      <div class="actions">
        <button id="new-session-btn">New pentest</button>
      </div>
      <details class="setup-collapse">
        <summary>Show pentest config</summary>
        <div id="setup-readonly" style="margin-top:6px;color:#6b7280;font-size:11px;"></div>
      </details>
    </div>
    <div id="setup">
      <label>Target URL</label>
      <input id="url" placeholder="https://target.example" />
      <label>Repo (optional — pure DAST if blank)</label>
      <select id="repo"><option value="">(none — pure DAST)</option></select>
      <label>Or clone a repo by git URL</label>
      <input id="repo-git" placeholder="https://github.com/owner/repo.git" />
      <label>GitHub token (only needed for private repos)</label>
      <input id="repo-git-token" type="password" autocomplete="off" spellcheck="false"
             placeholder="ghp_… or github_pat_… (used once for this clone, not stored)" />
      <div style="font-size:11px;color:#6b7280;margin-top:-6px;margin-bottom:10px;">
        Personal access token with <code>repo</code> scope, or a GitHub App
        installation token. Sent once over TLS, used only for this <code>git
        clone</code>, never logged or written to disk.
      </div>

      <label>Config source</label>
      <select id="config-mode">
        <option value="none">(none)</option>
        <option value="builtin">Built-in config</option>
        <option value="custom">Paste your own YAML</option>
      </select>
      <select id="config" class="hidden"></select>
      <textarea id="config-yaml" class="hidden" rows="10" placeholder="# paste your dapper YAML config here&#10;auth:&#10;  type: form&#10;  ..."></textarea>

      <label>Vuln classes</label>
      <div id="classes" class="chips"></div>
      <label><input type="checkbox" id="skip-exploit" style="width:auto;margin-right:6px"/>Skip exploitation phase</label>

      <label>Initial instruction (optional)</label>
      <textarea id="initial-msg" rows="3" placeholder="e.g. Focus on the /api/v2 endpoints and skip nmap"></textarea>

      <button id="start">Start pentest</button>
      <div id="warn" style="color:#f87171;font-size:12px;margin-top:8px"></div>
    </div>
    <div class="deliverables hidden" id="del-panel">
      <div class="head">
        <h3>Reports &amp; Findings</h3>
        <button id="dl-zip" class="dl-zip" disabled title="Download all deliverables as a zip">⤓ .zip</button>
      </div>
      <div id="del-list">
        <div class="empty" id="del-empty">
          No reports yet. The agent will write findings here as it works — the
          <strong>executive summary</strong> appears when the run completes.
        </div>
      </div>
    </div>
  </aside>
  <div id="viewer-backdrop" class="viewer-backdrop hidden">
    <div class="viewer">
      <div class="vhead">
        <span class="title" id="viewer-title"></span>
        <button id="viewer-download">⤓ download</button>
        <button id="viewer-close">✕ close</button>
      </div>
      <div class="vbody" id="viewer-body"></div>
    </div>
  </div>
  <section class="chat">
    <div class="feed" id="feed">
      <div class="msg status">Configure on the left and click "Start pentest" to begin a chat with the agent.</div>
    </div>
    <div class="composer">
      <div class="pending hidden" id="pending">Agent is asking:</div>
      <div class="row">
        <textarea id="composer-input" placeholder="Chat with the agent..." disabled></textarea>
        <button id="send" disabled>Send</button>
      </div>
      <div class="hint">Cmd/Ctrl+Enter to send · Your messages answer pending questions or queue as follow-up instructions for the agent's next turn.</div>
    </div>
  </section>
</main>

<div id="page-runs" class="page hidden">
  <h2>Runs</h2>
  <div class="sub">All pentests this instance has executed. Click any row to open its reports.</div>
  <div class="runs-toolbar">
    <input id="runs-filter" class="stretch" placeholder="Filter by URL or repo…" />
    <select id="runs-status-filter">
      <option value="">All statuses</option>
      <option value="running">Running</option>
      <option value="completed">Completed</option>
      <option value="error">Error</option>
    </select>
    <button id="runs-refresh" style="width:auto;margin:0;padding:6px 14px;">Refresh</button>
  </div>
  <table class="runs" id="runs-table">
    <thead>
      <tr>
        <th data-sort="started_at" class="sorted-desc">Started</th>
        <th data-sort="url">Target</th>
        <th data-sort="repo">Repo</th>
        <th data-sort="status">Status</th>
        <th data-sort="duration">Duration</th>
        <th data-sort="file_count">Files</th>
      </tr>
    </thead>
    <tbody id="runs-tbody">
      <tr><td colspan="6" style="color:#6b7280;">Loading…</td></tr>
    </tbody>
  </table>
</div>

<div id="page-cicd" class="page hidden">
  <h2>CI/CD</h2>
  <div class="sub">
    Trigger Dapper from your pipeline. Mint an API key below, store it as a
    secret in your CI provider, then <code>POST</code> to
    <code>/api/scans</code> with a <code>Bearer</code> token.
  </div>

  <section>
    <h3 style="font-size:13px;color:#9aa5b1;margin:0 0 8px 0;">API keys</h3>
    <div class="inline-form">
      <div style="flex:1;">
        <label style="margin-top:0;">Label (e.g. "github-actions-staging")</label>
        <input id="newkey-label" placeholder="Descriptive label so you remember what uses it" />
      </div>
      <button id="newkey-btn">Mint key</button>
    </div>
    <div id="newkey-warn" style="color:#f87171;font-size:12px;margin-top:8px;"></div>
    <div id="newkey-reveal" class="key-reveal hidden">
      <div class="warn">Copy this key now. It will never be shown again.</div>
      <code id="newkey-plaintext"></code>
    </div>
    <table class="keys-table">
      <thead>
        <tr>
          <th>Prefix</th>
          <th>Label</th>
          <th>Created</th>
          <th>Last used</th>
          <th>Status</th>
          <th></th>
        </tr>
      </thead>
      <tbody id="keys-tbody">
        <tr><td colspan="6" style="color:#6b7280;">Loading…</td></tr>
      </tbody>
    </table>
  </section>

  <section>
    <h3 style="font-size:13px;color:#9aa5b1;margin:0 0 8px 0;">Trigger a scan</h3>
    <div class="snippet">
      <button class="copy" data-copy="snippet-curl">Copy</button>
      <div class="lbl">cURL</div>
      <pre id="snippet-curl"></pre>
    </div>
    <div class="snippet">
      <button class="copy" data-copy="snippet-gha">Copy</button>
      <div class="lbl">GitHub Actions (<code>.github/workflows/dapper.yml</code>)</div>
      <pre id="snippet-gha"></pre>
    </div>
    <div class="snippet">
      <button class="copy" data-copy="snippet-gitlab">Copy</button>
      <div class="lbl">GitLab CI (<code>.gitlab-ci.yml</code>)</div>
      <pre id="snippet-gitlab"></pre>
    </div>
    <div class="snippet">
      <button class="copy" data-copy="snippet-circle">Copy</button>
      <div class="lbl">CircleCI (<code>.circleci/config.yml</code>)</div>
      <pre id="snippet-circle"></pre>
    </div>
  </section>
</div>

<script>
const CLASSES = ["injection","xss","auth","authz","ssrf","client-side","session-mgmt","api-testing","business-logic","crypto","config-deploy","error-handling","info-gathering","web-attacks"];
let session = null;
let pendingQid = null;

const $ = (id) => document.getElementById(id);

function renderClasses() {
  const el = $("classes");
  el.innerHTML = "";
  for (const c of CLASSES) {
    const chip = document.createElement("span");
    chip.className = "chip on";
    chip.textContent = c;
    chip.dataset.cls = c;
    chip.onclick = () => chip.classList.toggle("on");
    el.appendChild(chip);
  }
}
const selectedClasses = () => Array.from(document.querySelectorAll("#classes .chip.on")).map(c => c.dataset.cls);

async function loadOptions() {
  const repos = await (await fetch("/api/repos")).json();
  const repoSel = $("repo");
  for (const r of repos.repos) {
    const o = document.createElement("option");
    o.value = r; o.textContent = r;
    repoSel.appendChild(o);
  }
  const configs = await (await fetch("/api/configs")).json();
  const cfgSel = $("config");
  cfgSel.innerHTML = "";
  for (const c of configs.configs) {
    const o = document.createElement("option");
    o.value = c; o.textContent = c;
    cfgSel.appendChild(o);
  }
  if (!configs.configs.length) {
    const o = document.createElement("option");
    o.value = ""; o.textContent = "(no built-in configs)";
    cfgSel.appendChild(o);
  }
  const health = await (await fetch("/api/health")).json();
  if (!health.anthropic_key_set) {
    $("warn").textContent = "WARN: ANTHROPIC_API_KEY not set on server.";
  }
}

$("config-mode").onchange = async (e) => {
  const mode = e.target.value;
  $("config").classList.toggle("hidden", mode !== "builtin");
  $("config-yaml").classList.toggle("hidden", mode !== "custom");
  if (mode === "builtin" && $("config").value) {
    // Prefill custom area in case the user wants to fork it later
    try {
      const data = await (await fetch(`/api/configs/${$("config").value}`)).json();
      $("config-yaml").value = data.content;
    } catch {}
  }
};
$("config").onchange = async (e) => {
  if (!e.target.value) return;
  try {
    const data = await (await fetch(`/api/configs/${e.target.value}`)).json();
    $("config-yaml").value = data.content;
  } catch {}
};

// ---- minimal markdown renderer (safe-ish: escapes HTML first) ----
function escapeHtml(s) {
  return s.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
}
function renderMd(src) {
  let s = escapeHtml(src);
  // fenced code blocks ```lang\n...\n```
  s = s.replace(/```(\w*)\n([\s\S]*?)```/g, (_, lang, code) => `<pre><code>${code.replace(/\n$/, "")}</code></pre>`);
  // inline code `x`
  s = s.replace(/`([^`\n]+)`/g, "<code>$1</code>");
  // headers
  s = s.replace(/^### (.+)$/gm, "<h3>$1</h3>")
       .replace(/^## (.+)$/gm, "<h2>$1</h2>")
       .replace(/^# (.+)$/gm, "<h1>$1</h1>");
  // bold/italic
  s = s.replace(/\*\*([^*\n]+)\*\*/g, "<strong>$1</strong>")
       .replace(/(?<![*\w])\*([^*\n]+)\*(?!\w)/g, "<em>$1</em>");
  // links [text](url)
  s = s.replace(/\[([^\]]+)\]\((https?:\/\/[^\s)]+)\)/g, '<a href="$2" target="_blank" rel="noopener">$1</a>');
  // lists: contiguous lines starting with "- " or "* "
  s = s.replace(/((?:^[-*] .+\n?)+)/gm, m => "<ul>" + m.trim().split(/\n/).map(li => "<li>" + li.replace(/^[-*] /, "") + "</li>").join("") + "</ul>");
  // numbered lists
  s = s.replace(/((?:^\d+\. .+\n?)+)/gm, m => "<ol>" + m.trim().split(/\n/).map(li => "<li>" + li.replace(/^\d+\. /, "") + "</li>").join("") + "</ol>");
  // paragraphs: split on double newline
  s = s.split(/\n\n+/).map(block => /^\s*<(h\d|ul|ol|pre)/.test(block) ? block : "<p>" + block.replace(/\n/g, "<br>") + "</p>").join("");
  return s;
}

// ---- message + tool-call rendering ----
const liveMessages = new Map(); // message_id -> {bubble, body, raw}
const liveToolCalls = new Map(); // call_id -> {el, pre}

function feedScroll() {
  const feed = $("feed");
  feed.scrollTop = feed.scrollHeight;
}

function newBubble(cls, metaText) {
  const div = document.createElement("div");
  div.className = "msg " + cls;
  if (metaText) {
    const m = document.createElement("div");
    m.className = "meta";
    m.textContent = metaText;
    div.appendChild(m);
  }
  const body = document.createElement("div");
  body.className = "body";
  div.appendChild(body);
  $("feed").appendChild(div);
  feedScroll();
  return {bubble: div, body};
}

function addPlainBubble(cls, text, metaText) {
  const {body} = newBubble(cls, metaText);
  if (cls === "agent" || cls === "user" || cls === "question") {
    body.innerHTML = renderMd(text);
  } else {
    body.textContent = text;
  }
  feedScroll();
}

function appendToken(mid, role, delta) {
  let entry = liveMessages.get(mid);
  if (!entry) {
    const {bubble, body} = newBubble("agent", role);
    const typing = document.createElement("span");
    typing.className = "typing";
    bubble.appendChild(typing);
    entry = {bubble, body, raw: "", typing};
    liveMessages.set(mid, entry);
  }
  entry.raw += delta;
  entry.body.innerHTML = renderMd(entry.raw);
  feedScroll();
}

function finalizeMessage(mid) {
  const entry = liveMessages.get(mid);
  if (entry && entry.typing) entry.typing.remove();
}

function addToolCall(callId, name, argsJson) {
  const det = document.createElement("details");
  det.className = "tool";
  const sum = document.createElement("summary");
  sum.innerHTML = `<span class="name">${escapeHtml(name)}</span><span class="args">${escapeHtml(argsJson)}</span><span class="pending">running…</span>`;
  det.appendChild(sum);
  const pre = document.createElement("pre");
  pre.textContent = "(awaiting result)";
  det.appendChild(pre);
  $("feed").appendChild(det);
  feedScroll();
  liveToolCalls.set(callId, {el: det, pre, sum});
}

function addToolResult(callId, name, content) {
  const entry = liveToolCalls.get(callId);
  if (!entry) {
    // result without matching call — render standalone
    const det = document.createElement("details");
    det.className = "tool";
    const sum = document.createElement("summary");
    sum.innerHTML = `<span class="name">${escapeHtml(name)}</span><span class="done">done</span>`;
    det.appendChild(sum);
    const pre = document.createElement("pre");
    pre.textContent = content;
    det.appendChild(pre);
    $("feed").appendChild(det);
    feedScroll();
    return;
  }
  entry.pre.textContent = content;
  const status = entry.sum.querySelector(".pending");
  if (status) { status.textContent = "done"; status.className = "done"; }
}

function setPending(question) {
  if (question) {
    pendingQid = true;
    $("pending").classList.remove("hidden");
    $("pending").textContent = "Agent is asking — your next message will reply.";
    $("composer-input").placeholder = "Reply to the agent's question...";
    $("composer-input").focus();
  } else {
    pendingQid = null;
    $("pending").classList.add("hidden");
    $("composer-input").placeholder = "Chat with the agent...";
  }
}

function handleEvent(evt) {
  const ts = new Date(evt.ts * 1000).toLocaleTimeString();
  if (evt.kind === "heartbeat") return;
  if (evt.kind === "token") {
    appendToken(evt.message_id, evt.role || "agent", evt.delta);
  } else if (evt.kind === "message_end") {
    finalizeMessage(evt.message_id);
  } else if (evt.kind === "tool_call") {
    addToolCall(evt.call_id, evt.name || "tool", evt.args || "");
  } else if (evt.kind === "tool_result") {
    addToolResult(evt.call_id, evt.name || "tool", evt.content || "");
  } else if (evt.kind === "question") {
    addPlainBubble("question", evt.question, `${ts} · agent question`);
    setPending(evt.question);
  } else if (evt.kind === "user") {
    addPlainBubble("user", evt.message, `${ts} · you${evt.subkind === "answer" ? " (answer)" : ""}`);
    if (evt.subkind === "answer") setPending(null);
  } else if (evt.kind === "subagent") {
    addPlainBubble("status", `↳ subagent ${evt.name} ${evt.action || ""}`, "");
  } else if (evt.kind === "log") {
    addPlainBubble("status", evt.line, "");
  } else if (evt.kind === "status") {
    addPlainBubble("status", `— ${evt.status} —`, "");
    if (evt.status === "running") $("composer-input").placeholder = "Agent is working... your message queues for the next turn.";
    if (evt.status === "idle") { $("composer-input").placeholder = "Chat with the agent..."; setPending(null); }
  } else if (evt.kind === "error") {
    addPlainBubble("error", evt.message + (evt.traceback ? "\n\n" + evt.traceback : ""), `${ts} · error`);
  }
}

function fmtBytes(n) {
  if (n < 1024) return n + "b";
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + "kb";
  return (n / 1024 / 1024).toFixed(1) + "mb";
}

function isExecSummary(path) {
  return /(^|\/)0*0[-_].*executive[-_]?summary/i.test(path) || /executive[-_]?summary\.md$/i.test(path);
}

function makeFileRow(f) {
  const row = document.createElement("div");
  row.className = "file-row" + (isExecSummary(f.path) ? " exec-summary" : "");
  row.onclick = () => openViewer(f.path);
  const name = document.createElement("span");
  name.className = "name";
  name.textContent = isExecSummary(f.path) ? `Executive summary — ${f.path}` : f.path;
  const size = document.createElement("span");
  size.className = "size";
  size.textContent = fmtBytes(f.bytes);
  row.appendChild(name);
  row.appendChild(size);
  return row;
}

// Source of deliverable files: either a live session or a historical scan.
// Set to `/api/sessions/<sid>` while a session is active, or
// `/api/scans/<folder>` when viewing a historical scan in read-only mode.
let deliverablesBase = null;
let viewingHistorical = false;

async function refreshDeliverables() {
  if (!deliverablesBase) return;
  const data = await (await fetch(`${deliverablesBase}/deliverables`)).json();
  const list = $("del-list");
  list.innerHTML = "";
  if (!data.files.length) {
    const empty = document.createElement("div");
    empty.className = "empty";
    empty.innerHTML = viewingHistorical
      ? 'This scan completed with no deliverables on disk.'
      : 'No reports yet. The agent will write findings here as it works — the <strong>executive summary</strong> appears when the run completes.';
    list.appendChild(empty);
    $("dl-zip").disabled = true;
    return;
  }
  $("dl-zip").disabled = false;
  // Pin executive summary at the top; sort the rest by path.
  const sorted = data.files.slice().sort((a, b) => {
    const ea = isExecSummary(a.path), eb = isExecSummary(b.path);
    if (ea !== eb) return ea ? -1 : 1;
    return a.path.localeCompare(b.path);
  });
  for (const f of sorted) list.appendChild(makeFileRow(f));
}

let currentViewerPath = null;
async function openViewer(path) {
  if (!deliverablesBase) return;
  currentViewerPath = path;
  $("viewer-title").textContent = path;
  $("viewer-backdrop").classList.remove("hidden");
  const body = $("viewer-body");
  body.className = "vbody";
  body.textContent = "Loading…";
  try {
    const data = await (await fetch(`${deliverablesBase}/deliverables/${encodeURIComponent(path)}`)).json();
    if (/\.md$/i.test(path)) {
      body.innerHTML = renderMd(data.content || "(empty)");
    } else {
      body.className = "vbody raw";
      body.textContent = data.content || "(empty)";
    }
  } catch (e) {
    body.textContent = "Failed to load: " + e;
  }
}
function closeViewer() {
  $("viewer-backdrop").classList.add("hidden");
  currentViewerPath = null;
}
$("viewer-close").onclick = closeViewer;
$("viewer-backdrop").onclick = (e) => { if (e.target.id === "viewer-backdrop") closeViewer(); };
$("viewer-download").onclick = () => {
  if (!currentViewerPath || !deliverablesBase) return;
  const a = document.createElement("a");
  a.href = `${deliverablesBase}/deliverables/${encodeURIComponent(currentViewerPath)}`;
  a.target = "_blank";
  a.click();
};
$("dl-zip").onclick = () => {
  if (!deliverablesBase) return;
  window.location.href = `${deliverablesBase}/deliverables.zip`;
};

function resetToSetup() {
  session = null;
  deliverablesBase = null;
  viewingHistorical = false;
  $("session-info").classList.add("hidden");
  $("setup").classList.remove("hidden");
  $("del-panel").classList.add("hidden");
  $("hdr-status").textContent = "disconnected";
  $("feed").innerHTML = '<div class="msg status">Configure on the left and click "Start pentest" to begin a chat with the agent.</div>';
  $("composer-input").disabled = true;
  $("send").disabled = true;
  $("start").disabled = false;
  if (!$("page-runs").classList.contains("hidden")) loadRuns();
}

$("new-session-btn").onclick = () => {
  if (!confirm("Return to the home screen? Any running scan keeps running in the background — you can find it on the Runs tab.")) return;
  resetToSetup();
};

// ---- Historical scans ----
function fmtRelTime(epochSec) {
  if (!epochSec) return "";
  const d = new Date(epochSec * 1000);
  const diff = (Date.now() / 1000) - epochSec;
  if (diff < 60) return "just now";
  if (diff < 3600) return Math.floor(diff / 60) + "m ago";
  if (diff < 86400) return Math.floor(diff / 3600) + "h ago";
  if (diff < 86400 * 30) return Math.floor(diff / 86400) + "d ago";
  return d.toLocaleDateString();
}

// ---- Runs tab ----
let runsCache = [];
let runsSort = { key: "started_at", dir: "desc" };

function fmtDuration(startedSec, finishedSec) {
  if (!startedSec) return "—";
  const end = finishedSec || (Date.now() / 1000);
  const s = Math.max(0, Math.floor(end - startedSec));
  if (s < 60) return s + "s";
  if (s < 3600) return Math.floor(s / 60) + "m " + (s % 60) + "s";
  return Math.floor(s / 3600) + "h " + Math.floor((s % 3600) / 60) + "m";
}

function effectiveStatus(s) {
  if (s.live) return "running";
  return s.status || "unknown";
}

function renderRuns() {
  const tbody = $("runs-tbody");
  const q = $("runs-filter").value.trim().toLowerCase();
  const statusF = $("runs-status-filter").value;
  let rows = runsCache.filter(s => {
    const status = effectiveStatus(s);
    if (statusF && status !== statusF) return false;
    if (!q) return true;
    return (s.url || "").toLowerCase().includes(q)
        || (s.repo || "").toLowerCase().includes(q)
        || (s.scan_id || "").toLowerCase().includes(q);
  });
  const k = runsSort.key, dir = runsSort.dir === "asc" ? 1 : -1;
  rows.sort((a, b) => {
    let av = a[k], bv = b[k];
    if (k === "duration") { av = (a.finished_at || Date.now()/1000) - (a.started_at || 0);
                             bv = (b.finished_at || Date.now()/1000) - (b.started_at || 0); }
    if (k === "status")   { av = effectiveStatus(a); bv = effectiveStatus(b); }
    if (av == null) av = "";
    if (bv == null) bv = "";
    if (typeof av === "string") return av.localeCompare(bv) * dir;
    return (av - bv) * dir;
  });
  document.querySelectorAll("#runs-table th[data-sort]").forEach(th => {
    th.classList.remove("sorted-asc", "sorted-desc");
    if (th.dataset.sort === runsSort.key) {
      th.classList.add(runsSort.dir === "asc" ? "sorted-asc" : "sorted-desc");
    }
  });
  tbody.innerHTML = "";
  if (!rows.length) {
    tbody.innerHTML = '<tr><td colspan="6" style="color:#6b7280;">No runs match the current filter.</td></tr>';
    return;
  }
  for (const s of rows) {
    const tr = document.createElement("tr");
    tr.onclick = () => { switchTab("start"); openHistoricalScan(s); };
    const status = effectiveStatus(s);
    tr.innerHTML = `
      <td title="${new Date((s.started_at || 0) * 1000).toLocaleString()}">${fmtRelTime(s.started_at)}</td>
      <td class="url">${escapeHtml(s.url || s.scan_id)}</td>
      <td>${escapeHtml(s.repo || "")}</td>
      <td><span class="pill ${status}">${status}</span></td>
      <td>${fmtDuration(s.started_at, s.finished_at)}</td>
      <td>${s.file_count || 0}</td>
    `;
    tbody.appendChild(tr);
  }
}

function escapeHtml(s) {
  return String(s == null ? "" : s)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

async function loadRuns() {
  try {
    const data = await (await fetch("/api/scans")).json();
    runsCache = data.scans || [];
    renderRuns();
  } catch (e) {
    $("runs-tbody").innerHTML = '<tr><td colspan="6" style="color:#f87171;">Failed to load runs.</td></tr>';
  }
}

document.querySelectorAll("#runs-table th[data-sort]").forEach(th => {
  th.onclick = () => {
    const k = th.dataset.sort;
    if (runsSort.key === k) runsSort.dir = runsSort.dir === "asc" ? "desc" : "asc";
    else { runsSort.key = k; runsSort.dir = "desc"; }
    renderRuns();
  };
});
$("runs-filter").oninput = renderRuns;
$("runs-status-filter").onchange = renderRuns;
$("runs-refresh").onclick = loadRuns;

// ---- Tab routing ----
function switchTab(name) {
  const valid = ["start", "runs", "cicd"];
  if (!valid.includes(name)) name = "start";
  document.querySelectorAll("header nav a").forEach(a => {
    a.classList.toggle("active", a.dataset.tab === name);
  });
  $("page-start").classList.toggle("hidden", name !== "start");
  $("page-runs").classList.toggle("hidden",  name !== "runs");
  $("page-cicd").classList.toggle("hidden",  name !== "cicd");
  if (name !== "start") {
    // Hide the start-page header status while we're on another tab.
  }
  if (location.hash.slice(1) !== name) {
    history.replaceState(null, "", "#" + name);
  }
  if (name === "runs") loadRuns();
  if (name === "cicd") { loadKeys(); renderSnippets(); }
}
document.querySelectorAll("header nav a").forEach(a => {
  a.onclick = (e) => { e.preventDefault(); switchTab(a.dataset.tab); };
});
window.addEventListener("hashchange", () => switchTab(location.hash.slice(1)));

// ---- CI/CD tab ----
async function loadKeys() {
  const tbody = $("keys-tbody");
  try {
    const res = await fetch("/api/keys");
    if (!res.ok) {
      const err = await res.json().catch(() => ({detail: "request failed"}));
      tbody.innerHTML = `<tr><td colspan="6" style="color:#f87171;">${escapeHtml(err.detail || "failed")}</td></tr>`;
      return;
    }
    const data = await res.json();
    const keys = data.keys || [];
    if (!keys.length) {
      tbody.innerHTML = '<tr><td colspan="6" style="color:#6b7280;">No keys yet. Mint one above to trigger scans from CI.</td></tr>';
      return;
    }
    tbody.innerHTML = "";
    for (const k of keys) {
      const revoked = !!k.revoked_at;
      const tr = document.createElement("tr");
      if (revoked) tr.className = "revoked";
      tr.innerHTML = `
        <td><code>${escapeHtml(k.prefix)}…</code></td>
        <td>${escapeHtml(k.label || "")}</td>
        <td title="${new Date((k.created_at || 0) * 1000).toLocaleString()}">${fmtRelTime(k.created_at)}</td>
        <td>${k.last_used_at ? fmtRelTime(k.last_used_at) : "never"}</td>
        <td>${revoked ? "revoked" : "active"}</td>
        <td></td>
      `;
      if (!revoked) {
        const btn = document.createElement("button");
        btn.textContent = "Revoke";
        btn.style.width = "auto"; btn.style.margin = "0"; btn.style.padding = "4px 10px";
        btn.style.fontSize = "11px";
        btn.onclick = async () => {
          if (!confirm(`Revoke key ${k.prefix}…? CI jobs using it will start failing immediately.`)) return;
          const r = await fetch(`/api/keys/${encodeURIComponent(k.id)}`, {method: "DELETE"});
          if (r.ok) loadKeys();
        };
        tr.querySelector("td:last-child").appendChild(btn);
      }
      tbody.appendChild(tr);
    }
  } catch (e) {
    tbody.innerHTML = '<tr><td colspan="6" style="color:#f87171;">Failed to load keys.</td></tr>';
  }
}

$("newkey-btn").onclick = async () => {
  const label = $("newkey-label").value.trim();
  $("newkey-warn").textContent = "";
  const r = await fetch("/api/keys", {
    method: "POST",
    headers: {"content-type": "application/json"},
    body: JSON.stringify({label}),
  });
  if (!r.ok) {
    const err = await r.json().catch(() => ({detail: "request failed"}));
    $("newkey-warn").textContent = err.detail || "Failed to mint key";
    return;
  }
  const out = await r.json();
  $("newkey-plaintext").textContent = out.plaintext;
  $("newkey-reveal").classList.remove("hidden");
  $("newkey-label").value = "";
  loadKeys();
};

function renderSnippets() {
  const origin = location.origin;
  const curl =
`curl -X POST "${origin}/api/scans" \\
  -H "Authorization: Bearer $DAPPER_API_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{
    "url": "https://staging.example.com",
    "repo_git_url": "https://github.com/your-org/your-repo.git",
    "skip_exploit": true
  }'`;
  const gha =
`name: dapper-pentest
on:
  pull_request:
    branches: [main]
jobs:
  pentest:
    runs-on: ubuntu-latest
    steps:
      - name: Trigger Dapper scan
        env:
          DAPPER_API_KEY: \${{ secrets.DAPPER_API_KEY }}
        run: |
          curl -fsS -X POST "${origin}/api/scans" \\
            -H "Authorization: Bearer $DAPPER_API_KEY" \\
            -H "Content-Type: application/json" \\
            -d "{\\"url\\":\\"https://staging.example.com\\",\\"repo_git_url\\":\\"https://github.com/\${{ github.repository }}.git\\",\\"skip_exploit\\":true}"`;
  const gitlab =
`dapper-pentest:
  stage: test
  image: curlimages/curl:latest
  script:
    - |
      curl -fsS -X POST "${origin}/api/scans" \\
        -H "Authorization: Bearer $DAPPER_API_KEY" \\
        -H "Content-Type: application/json" \\
        -d "{\\"url\\":\\"https://staging.example.com\\",\\"repo_git_url\\":\\"$CI_REPOSITORY_URL\\",\\"skip_exploit\\":true}"
  only: [merge_requests]`;
  const circle =
`version: 2.1
jobs:
  dapper-pentest:
    docker:
      - image: cimg/base:stable
    steps:
      - run:
          name: Trigger Dapper scan
          command: |
            curl -fsS -X POST "${origin}/api/scans" \\
              -H "Authorization: Bearer $DAPPER_API_KEY" \\
              -H "Content-Type: application/json" \\
              -d "{\\"url\\":\\"https://staging.example.com\\",\\"repo_git_url\\":\\"$CIRCLE_REPOSITORY_URL\\",\\"skip_exploit\\":true}"
workflows:
  pentest:
    jobs: [dapper-pentest]`;
  $("snippet-curl").textContent = curl;
  $("snippet-gha").textContent = gha;
  $("snippet-gitlab").textContent = gitlab;
  $("snippet-circle").textContent = circle;
}
document.querySelectorAll(".snippet .copy").forEach(btn => {
  btn.onclick = async () => {
    const id = btn.dataset.copy;
    try {
      await navigator.clipboard.writeText($(id).textContent);
      const old = btn.textContent;
      btn.textContent = "Copied!";
      setTimeout(() => { btn.textContent = old; }, 1200);
    } catch (e) {}
  };
});

function openHistoricalScan(scan) {
  // Read-only view: no SSE stream, no composer, just the deliverables panel.
  session = null;
  deliverablesBase = `/api/scans/${encodeURIComponent(scan.scan_id)}`;
  viewingHistorical = true;
  $("setup").classList.add("hidden");
  $("session-info").classList.remove("hidden");
  $("del-panel").classList.remove("hidden");
  $("si-url").textContent = scan.url || scan.scan_id;
  $("si-repo").textContent = scan.repo || "(none — pure DAST)";
  $("si-status").textContent = scan.live ? "live (read-only view)" : "finished";
  $("setup-readonly").textContent = `scan id: ${scan.scan_id}\nstarted: ${new Date((scan.started_at || 0) * 1000).toLocaleString()}`;
  $("hdr-status").textContent = `viewing ${scan.scan_id}`;
  $("feed").innerHTML = '<div class="msg status">Read-only view of a past scan. Open the reports on the left, or click "New pentest" to return to the home screen.</div>';
  $("composer-input").disabled = true;
  $("send").disabled = true;
  $("composer-input").placeholder = "Chat is disabled for historical scans.";
  refreshDeliverables();
}

$("start").onclick = async () => {
  const url = $("url").value.trim();
  if (!url) { $("warn").textContent = "Target URL is required"; return; }
  const mode = $("config-mode").value;
  const body = {
    url,
    repo: $("repo").value || null,
    repo_git_url: $("repo-git").value.trim() || null,
    repo_git_token: $("repo-git-token").value || null,
    config: mode === "builtin" ? ($("config").value || null) : null,
    config_yaml: mode === "custom" ? ($("config-yaml").value.trim() || null) : null,
    classes: selectedClasses(),
    skip_exploit: $("skip-exploit").checked,
    initial_message: $("initial-msg").value.trim() || null,
  };
  // Wipe the token field immediately so it doesn't sit in DOM memory after
  // the request. The backend uses it once and discards it.
  $("repo-git-token").value = "";
  $("warn").textContent = "";
  $("start").disabled = true;
  $("feed").innerHTML = "";

  const res = await fetch("/api/sessions", {
    method: "POST",
    headers: {"content-type":"application/json"},
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({detail: res.statusText}));
    $("warn").textContent = "ERROR: " + (err.detail || res.statusText);
    $("start").disabled = false;
    return;
  }
  const data = await res.json();
  session = data.id;
  deliverablesBase = `/api/sessions/${session}`;
  viewingHistorical = false;
  $("hdr-status").textContent = `session ${session.slice(0, 12)}`;
  // Swap sidebar into session mode.
  $("setup").classList.add("hidden");
  $("session-info").classList.remove("hidden");
  $("del-panel").classList.remove("hidden");
  $("si-url").textContent = data.url || url;
  $("si-repo").textContent = data.repo || "(none — pure DAST)";
  $("si-status").textContent = "running";
  $("setup-readonly").textContent = `classes: ${(body.classes || []).join(", ") || "(all)"}\nskip_exploit: ${body.skip_exploit}\nconfig: ${body.config || (body.config_yaml ? "(inline yaml)" : "(none)")}`;
  refreshDeliverables();
  if (body.initial_message) addPlainBubble("user", body.initial_message, `you · initial`);
  $("composer-input").disabled = false;
  $("send").disabled = false;

  const es = new EventSource(`/api/sessions/${session}/events`);
  es.onmessage = (m) => {
    const evt = JSON.parse(m.data);
    handleEvent(evt);
    if (evt.kind === "step" || evt.kind === "status" || evt.kind === "tool_result") refreshDeliverables();
    if (evt.kind === "status") $("si-status").textContent = evt.status;
    if (evt.kind === "status" && evt.status === "error") es.close();
  };
  es.onerror = () => { $("hdr-status").textContent = `session ${session.slice(0, 12)} · stream closed`; };
};

async function sendChat() {
  const msg = $("composer-input").value.trim();
  if (!msg || !session) return;
  $("composer-input").value = "";
  // Optimistic local echo handled by the server's "user" event broadcast.
  const res = await fetch(`/api/sessions/${session}/messages`, {
    method: "POST",
    headers: {"content-type":"application/json"},
    body: JSON.stringify({message: msg}),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({detail: res.statusText}));
    addPlainBubble("error", "Send failed: " + (err.detail || res.statusText));
  }
}

$("send").onclick = sendChat;
$("composer-input").addEventListener("keydown", (e) => {
  if ((e.metaKey || e.ctrlKey) && e.key === "Enter") {
    e.preventDefault();
    sendChat();
  }
});

renderClasses();
loadOptions();
switchTab(location.hash.slice(1) || "start");
// Show the sign-out link only when password auth is configured on the server.
fetch("/api/auth-status").then(r => r.json()).then(s => {
  if (s.required) $("logout-link").classList.remove("hidden");
}).catch(() => {});
$("logout-link").onclick = async (e) => {
  e.preventDefault();
  await fetch("/api/logout", {method: "POST"});
  location.href = "/login";
};
// Refresh the runs table every 30s while it's the active tab, so scans
// running in another browser tab or another worker eventually show up.
setInterval(() => {
  if (!session && !viewingHistorical && !$("page-runs").classList.contains("hidden")) loadRuns();
}, 30000);
</script>
</body>
</html>
"""


LOGIN_HTML = """<!doctype html>
<html><head>
<meta charset="utf-8" />
<title>Dapper · sign in</title>
<style>
  :root { color-scheme: dark; }
  body {
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    background:#0b0d10; color:#d8dee9; margin:0;
    display:flex; align-items:center; justify-content:center; min-height:100vh;
  }
  .card {
    background:#11151b; border:1px solid #233040; border-radius:8px;
    padding:28px 32px; width:340px;
  }
  h1 { margin:0 0 4px 0; font-size:18px; }
  .sub { color:#6b7280; font-size:12px; margin-bottom:20px; }
  label { display:block; font-size:12px; color:#9aa5b1; margin-top:12px; }
  input {
    width:100%; padding:8px 10px; margin-top:4px; box-sizing:border-box;
    background:#0b0d10; color:#d8dee9; border:1px solid #233040; border-radius:4px;
    font-family:inherit; font-size:13px;
  }
  button {
    width:100%; margin-top:18px; padding:9px;
    background:#1f2937; color:#d8dee9; border:1px solid #374151;
    border-radius:4px; cursor:pointer; font-family:inherit; font-size:13px;
  }
  button:hover { background:#233040; }
  button:disabled { opacity:0.5; cursor:wait; }
  .err { color:#f87171; font-size:12px; margin-top:10px; min-height:1em; }
</style>
</head><body>
<form class="card" id="f">
  <h1>Dapper × DeepAgents</h1>
  <div class="sub">This instance requires a password.</div>
  <label for="pw">Password</label>
  <input id="pw" type="password" autocomplete="current-password" autofocus />
  <button id="btn" type="submit">Sign in</button>
  <div class="err" id="err"></div>
</form>
<script>
const params = new URLSearchParams(location.search);
const next = params.get("next") || "/";
const form = document.getElementById("f");
form.onsubmit = async (e) => {
  e.preventDefault();
  const pw = document.getElementById("pw").value;
  const btn = document.getElementById("btn");
  const err = document.getElementById("err");
  err.textContent = "";
  btn.disabled = true;
  try {
    const r = await fetch("/api/login", {
      method: "POST",
      headers: {"content-type": "application/json"},
      body: JSON.stringify({password: pw}),
    });
    if (r.ok) { location.href = next; return; }
    if (r.status === 204) { location.href = next; return; }
    const j = await r.json().catch(() => ({detail: "sign-in failed"}));
    err.textContent = j.detail || "sign-in failed";
  } catch (e2) {
    err.textContent = "network error";
  } finally {
    btn.disabled = false;
  }
};
</script>
</body></html>"""


@app.get("/login", response_class=HTMLResponse)
def login_page():
    return LOGIN_HTML


@app.get("/", response_class=HTMLResponse)
def index():
    return INDEX_HTML
