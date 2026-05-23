"""FastAPI web app for the Dapper DeepAgents orchestrator.

Run:
    uvicorn scripts.deepagents.webapp:app --host 0.0.0.0 --port 8000
or:
    ./dapper web
"""
from __future__ import annotations

import json
import os
import subprocess
import time
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
    submit_message,
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
  * { box-sizing: border-box; }
  body { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; background:#0b0d10; color:#d8dee9; margin:0; }
  header { padding:14px 22px; border-bottom:1px solid #1f2937; display:flex; gap:16px; align-items:baseline; }
  header h1 { margin:0; font-size:18px; }
  header .status { color:#9aa5b1; font-size:12px; }
  main { display:grid; grid-template-columns: 380px 1fr; height:calc(100vh - 51px); }
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
  .deliverables { padding:14px 18px; border-top:1px solid #1f2937; font-size:12px; }
  .deliverables h3 { margin:0 0 8px 0; font-size:13px; color:#9aa5b1; }
  .deliverables a { color:#60a5fa; text-decoration:none; display:block; padding:2px 0; word-break:break-all; }
  .hidden { display:none !important; }
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
      <label>Repo (optional — pure DAST if blank)</label>
      <select id="repo"><option value="">(none — pure DAST)</option></select>
      <label>Or clone a repo by git URL</label>
      <input id="repo-git" placeholder="https://github.com/owner/repo.git" />

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
      <h3>Deliverables</h3>
      <div id="del-list"></div>
    </div>
  </aside>
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
    addPlainBubble("user", evt.message, `${ts} · you${evt.kind === "answer" ? " (answer)" : ""}`);
    if (evt.kind === "answer") setPending(null);
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
  $("del-panel").classList.toggle("hidden", !data.files.length);
}

$("start").onclick = async () => {
  const url = $("url").value.trim();
  if (!url) { $("warn").textContent = "Target URL is required"; return; }
  const mode = $("config-mode").value;
  const body = {
    url,
    repo: $("repo").value || null,
    repo_git_url: $("repo-git").value.trim() || null,
    config: mode === "builtin" ? ($("config").value || null) : null,
    config_yaml: mode === "custom" ? ($("config-yaml").value.trim() || null) : null,
    classes: selectedClasses(),
    skip_exploit: $("skip-exploit").checked,
    initial_message: $("initial-msg").value.trim() || null,
  };
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
  $("hdr-status").textContent = `session ${session}`;
  if (body.initial_message) addPlainBubble("user", body.initial_message, `you · initial`);
  $("composer-input").disabled = false;
  $("send").disabled = false;

  const es = new EventSource(`/api/sessions/${session}/events`);
  es.onmessage = (m) => {
    const evt = JSON.parse(m.data);
    handleEvent(evt);
    if (evt.kind === "step" || evt.kind === "status") refreshDeliverables();
    if (evt.kind === "status" && evt.status === "error") es.close();
  };
  es.onerror = () => { $("hdr-status").textContent = `session ${session} · stream closed`; };
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
</script>
</body>
</html>
"""


@app.get("/", response_class=HTMLResponse)
def index():
    return INDEX_HTML
