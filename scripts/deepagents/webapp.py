"""FastAPI web app for the Dapper DeepAgents orchestrator.

Run:
    uvicorn scripts.deepagents.webapp:app --host 0.0.0.0 --port 8000
or:
    ./dapper web
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel

from .session import (
    drain_events,
    get_session,
    list_sessions,
    start_session,
    submit_answer,
)

load_dotenv()

REPO_ROOT = Path(__file__).resolve().parents[2]
REPOS_DIR = REPO_ROOT / "repos"
CONFIGS_DIR = REPO_ROOT / "configs"
AUDIT_DIR = REPO_ROOT / "audit-logs"

app = FastAPI(title="Dapper DeepAgents")


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


class StartRequest(BaseModel):
    url: str
    repo: Optional[str] = None
    repo_git_url: Optional[str] = None
    config: Optional[str] = None
    classes: Optional[list[str]] = None
    skip_exploit: bool = False
    model: str = "claude-opus-4-7"


@app.post("/api/sessions")
def create_session(req: StartRequest):
    import subprocess
    if not os.environ.get("ANTHROPIC_API_KEY"):
        raise HTTPException(status_code=400, detail="ANTHROPIC_API_KEY not set on server")
    if not req.url.startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="url must start with http:// or https://")

    repo_name = req.repo or ""
    if req.repo_git_url:
        # Clone-on-demand: derive repo name from URL if not provided.
        if not repo_name:
            tail = req.repo_git_url.rstrip("/").rsplit("/", 1)[-1]
            repo_name = tail[:-4] if tail.endswith(".git") else tail
        REPOS_DIR.mkdir(parents=True, exist_ok=True)
        target = REPOS_DIR / repo_name
        if not target.exists():
            proc = subprocess.run(
                ["git", "clone", "--depth", "1", req.repo_git_url, str(target)],
                capture_output=True, text=True, timeout=300,
            )
            if proc.returncode != 0:
                raise HTTPException(status_code=400, detail=f"git clone failed: {proc.stderr[-500:]}")
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
    import time
    deliverables = str(AUDIT_DIR / f"{host}_deepagent-{int(time.time())}" / "deliverables")

    session = start_session(
        url=req.url,
        repo=repo_name,
        config_path=config_path,
        deliverables=deliverables,
        model=req.model,
        classes=req.classes,
        skip_exploit=req.skip_exploit,
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


class AnswerRequest(BaseModel):
    qid: str
    answer: str


@app.post("/api/sessions/{sid}/answer")
def answer(sid: str, req: AnswerRequest):
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
    if not p.exists():
        return {"files": []}
    files = []
    for f in sorted(p.glob("**/*")):
        if f.is_file():
            files.append({"path": str(f.relative_to(p)), "bytes": f.stat().st_size})
    return {"files": files}


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
# Single-page UI
# ---------------------------------------------------------------------------

INDEX_HTML = r"""<!doctype html>
<html>
<head>
<meta charset="utf-8" />
<title>Dapper DeepAgents</title>
<style>
  :root { color-scheme: dark; }
  body { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; background:#0b0d10; color:#d8dee9; margin:0; }
  header { padding:14px 22px; border-bottom:1px solid #1f2937; display:flex; gap:16px; align-items:baseline; }
  header h1 { margin:0; font-size:18px; }
  header .status { color:#9aa5b1; font-size:12px; }
  main { display:grid; grid-template-columns: 360px 1fr; gap:0; height:calc(100vh - 51px); }
  aside { border-right:1px solid #1f2937; padding:18px; overflow:auto; }
  section.feed { padding:0; display:flex; flex-direction:column; }
  label { display:block; margin-top:12px; font-size:12px; color:#9aa5b1; }
  input, select, button, textarea {
    width:100%; box-sizing:border-box; padding:8px 10px; margin-top:4px;
    background:#11151b; color:#d8dee9; border:1px solid #233040; border-radius:4px;
    font: inherit;
  }
  button { background:#2563eb; border-color:#2563eb; color:white; cursor:pointer; margin-top:14px; }
  button:disabled { opacity:0.5; cursor:not-allowed; }
  button.secondary { background:transparent; color:#9aa5b1; border-color:#233040; margin-top:6px; }
  .chips { display:flex; flex-wrap:wrap; gap:4px; margin-top:6px; }
  .chip { font-size:11px; background:#1f2937; padding:3px 8px; border-radius:12px; cursor:pointer; }
  .chip.on { background:#2563eb; color:white; }
  .events { flex:1; overflow:auto; padding:14px 18px; font-size:12px; }
  .event { padding:6px 10px; margin-bottom:6px; border-left:3px solid #1f2937; background:#0f141a; white-space:pre-wrap; word-break:break-word; }
  .event.kind-step { border-left-color:#2563eb; }
  .event.kind-question { border-left-color:#f59e0b; background:#1f1809; }
  .event.kind-error { border-left-color:#ef4444; color:#fecaca; }
  .event.kind-status { color:#9aa5b1; }
  .event .meta { font-size:10px; color:#6b7280; margin-bottom:2px; }
  .qbar { border-top:1px solid #1f2937; padding:12px 18px; background:#0f141a; display:none; }
  .qbar.on { display:block; }
  .qbar .q { color:#f59e0b; margin-bottom:6px; }
  .row { display:flex; gap:8px; }
  .row textarea { flex:1; min-height:60px; }
  .row button { width:auto; margin-top:0; align-self:stretch; }
  .deliverables { padding:14px 18px; border-top:1px solid #1f2937; font-size:12px; }
  .deliverables h3 { margin:0 0 8px 0; font-size:13px; color:#9aa5b1; }
  .deliverables a { color:#60a5fa; text-decoration:none; display:block; padding:2px 0; }
</style>
</head>
<body>
<header>
  <h1>Dapper × DeepAgents</h1>
  <span class="status" id="hdr-status">disconnected</span>
</header>
<main>
  <aside>
    <div id="setup">
      <label>Target URL</label>
      <input id="url" placeholder="https://target.example" />
      <label>Repo (./repos/... — optional for pure DAST)</label>
      <select id="repo"><option value="">(none — pure DAST)</option></select>
      <label>Or clone a repo by git URL</label>
      <input id="repo-git" placeholder="https://github.com/owner/repo.git (optional)" />
      <label>Config (./configs/*.yaml)</label>
      <select id="config"><option value="">(none)</option></select>
      <label>Vuln classes</label>
      <div id="classes" class="chips"></div>
      <label><input type="checkbox" id="skip-exploit" style="width:auto;margin-right:6px"/>Skip exploitation phase</label>
      <button id="start">Start pentest</button>
      <div id="warn" style="color:#f87171;font-size:12px;margin-top:8px"></div>
    </div>
    <div class="deliverables" id="del-panel" style="display:none">
      <h3>Deliverables</h3>
      <div id="del-list"></div>
    </div>
  </aside>
  <section class="feed">
    <div class="events" id="events"></div>
    <div class="qbar" id="qbar">
      <div class="q" id="qtext"></div>
      <div class="row">
        <textarea id="qans" placeholder="Your answer..."></textarea>
        <button id="qsend">Send</button>
      </div>
    </div>
  </section>
</main>

<script>
const CLASSES = ["injection","xss","auth","authz","ssrf","client-side","session-mgmt","api-testing","business-logic","crypto","config-deploy","error-handling","info-gathering","web-attacks"];
let session = null;
let currentQid = null;

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
function selectedClasses() {
  return Array.from(document.querySelectorAll("#classes .chip.on")).map(c => c.dataset.cls);
}

async function loadOptions() {
  const repos = await (await fetch("/api/repos")).json();
  const repoSel = $("repo");
  repoSel.innerHTML = "";
  if (!repos.repos.length) {
    const o = document.createElement("option");
    o.value = ""; o.textContent = "(no repos under ./repos/ — create one first)";
    repoSel.appendChild(o);
  }
  for (const r of repos.repos) {
    const o = document.createElement("option");
    o.value = r; o.textContent = r;
    repoSel.appendChild(o);
  }
  const configs = await (await fetch("/api/configs")).json();
  const cfgSel = $("config");
  for (const c of configs.configs) {
    const o = document.createElement("option");
    o.value = c; o.textContent = c;
    cfgSel.appendChild(o);
  }
  const health = await (await fetch("/api/health")).json();
  if (!health.anthropic_key_set) {
    $("warn").textContent = "WARN: ANTHROPIC_API_KEY not set on server. Add it to .env and restart.";
  }
}

function addEvent(evt) {
  const div = document.createElement("div");
  div.className = "event kind-" + evt.kind;
  const meta = document.createElement("div");
  meta.className = "meta";
  const ts = new Date(evt.ts * 1000).toLocaleTimeString();
  meta.textContent = `[${ts}] ${evt.kind}` + (evt.role ? ` · ${evt.role}` : "");
  div.appendChild(meta);
  const body = document.createElement("div");
  let text = "";
  if (evt.kind === "step") text = evt.content;
  else if (evt.kind === "question") text = evt.question;
  else if (evt.kind === "answer") text = evt.answer;
  else if (evt.kind === "error") text = evt.message + "\n\n" + (evt.traceback || "");
  else if (evt.kind === "status") text = "status: " + evt.status;
  else if (evt.kind === "log") text = evt.line;
  else text = JSON.stringify(evt);
  body.textContent = text;
  div.appendChild(body);
  const feed = $("events");
  feed.appendChild(div);
  feed.scrollTop = feed.scrollHeight;
}

function showQuestion(qid, question) {
  currentQid = qid;
  $("qtext").textContent = question;
  $("qans").value = "";
  $("qbar").classList.add("on");
  $("qans").focus();
}
function hideQuestion() {
  currentQid = null;
  $("qbar").classList.remove("on");
}

async function refreshDeliverables() {
  if (!session) return;
  const data = await (await fetch(`/api/sessions/${session}/deliverables`)).json();
  const list = $("del-list");
  list.innerHTML = "";
  for (const f of data.files) {
    const a = document.createElement("a");
    a.href = `/api/sessions/${session}/deliverables/${encodeURIComponent(f.path)}`;
    a.target = "_blank";
    a.textContent = `${f.path} (${f.bytes}b)`;
    list.appendChild(a);
  }
  $("del-panel").style.display = data.files.length ? "block" : "none";
}

$("start").onclick = async () => {
  const url = $("url").value.trim();
  const repo = $("repo").value || null;
  const repo_git_url = $("repo-git").value.trim() || null;
  const config = $("config").value || null;
  const classes = selectedClasses();
  const skip_exploit = $("skip-exploit").checked;
  if (!url) { $("warn").textContent = "URL is required"; return; }
  $("warn").textContent = "";
  $("start").disabled = true;
  $("events").innerHTML = "";
  const res = await fetch("/api/sessions", {
    method: "POST",
    headers: {"content-type":"application/json"},
    body: JSON.stringify({url, repo, repo_git_url, config, classes, skip_exploit}),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({detail: res.statusText}));
    $("warn").textContent = "ERROR: " + (err.detail || res.statusText);
    $("start").disabled = false;
    return;
  }
  const data = await res.json();
  session = data.id;
  $("hdr-status").textContent = `session ${session} · ${data.deliverables}`;
  const es = new EventSource(`/api/sessions/${session}/events`);
  es.onmessage = (m) => {
    const evt = JSON.parse(m.data);
    if (evt.kind === "heartbeat") return;
    addEvent(evt);
    if (evt.kind === "question") showQuestion(evt.qid, evt.question);
    if (evt.kind === "answer") hideQuestion();
    if (evt.kind === "status" && (evt.status === "done" || evt.status === "error")) {
      es.close();
      $("start").disabled = false;
      refreshDeliverables();
    }
    if (evt.kind === "step") refreshDeliverables();
  };
  es.onerror = () => { $("hdr-status").textContent = `session ${session} · stream closed`; };
};

$("qsend").onclick = async () => {
  if (!currentQid || !session) return;
  const ans = $("qans").value;
  await fetch(`/api/sessions/${session}/answer`, {
    method: "POST",
    headers: {"content-type":"application/json"},
    body: JSON.stringify({qid: currentQid, answer: ans}),
  });
  hideQuestion();
};

renderClasses();
loadOptions();
</script>
</body>
</html>
"""


@app.get("/", response_class=HTMLResponse)
def index():
    return INDEX_HTML
