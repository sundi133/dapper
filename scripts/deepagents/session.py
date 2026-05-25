"""In-process session manager for web-driven DeepAgents runs.

Each Session runs the deep agent on a background thread, publishes events to
a thread-safe queue (consumed by an SSE endpoint), and supports two kinds of
human input over a single chat channel:

  1. Answers to `ask_user` tool calls (the agent is blocked waiting).
  2. Free-form follow-up messages from the operator after the agent finishes
     a turn — these get appended to the message history and the agent is
     re-invoked, giving a multi-turn chat experience.
"""
from __future__ import annotations

import json
import tempfile
import threading
import time
import traceback
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from queue import Empty, Queue
from typing import Any, Optional

from langchain_core.tools import tool

from . import db
from .dast_tools import ALL_TOOLS
from .prompt_loader import load_prompt

REPO_ROOT = Path(__file__).resolve().parents[2]


# ---------------------------------------------------------------------------
# Session state
# ---------------------------------------------------------------------------

@dataclass
class PendingQuestion:
    qid: str
    question: str
    answer_event: threading.Event = field(default_factory=threading.Event)
    answer: Optional[str] = None


@dataclass
class Session:
    id: str
    url: str
    repo: str
    config_path: Optional[str]
    deliverables: str
    model: str
    classes: list[str]
    skip_exploit: bool
    initial_message: str
    status: str = "pending"  # pending | running | idle | done | error
    error: Optional[str] = None
    events: Queue = field(default_factory=Queue)
    pending_question: Optional[PendingQuestion] = None
    followup_queue: Queue = field(default_factory=Queue)
    wakeup: threading.Event = field(default_factory=threading.Event)
    lock: threading.Lock = field(default_factory=threading.Lock)
    thread: Optional[threading.Thread] = None
    started_at: float = field(default_factory=time.time)

    def emit(self, kind: str, **payload: Any) -> None:
        evt = {"ts": time.time(), "kind": kind, **payload}
        self.events.put(evt)
        # Mirror lifecycle changes into Postgres so historical scans survive
        # an ephemeral container restart.
        if kind == "status":
            db.update_status(self.id, payload.get("status", ""))
        elif kind == "error":
            db.update_status(self.id, "error", error=payload.get("message"))


_sessions: dict[str, Session] = {}
_sessions_lock = threading.Lock()


def get_session(sid: str) -> Optional[Session]:
    with _sessions_lock:
        return _sessions.get(sid)


def list_sessions() -> list[dict[str, Any]]:
    with _sessions_lock:
        return [
            {
                "id": s.id,
                "url": s.url,
                "repo": s.repo,
                "status": s.status,
                "started_at": s.started_at,
            }
            for s in _sessions.values()
        ]


def register_session(s: Session) -> None:
    with _sessions_lock:
        _sessions[s.id] = s


# ---------------------------------------------------------------------------
# Chat input — routes either to a pending question or the followup queue
# ---------------------------------------------------------------------------

def submit_message(session: Session, message: str) -> dict[str, Any]:
    """Send a user message. If the agent is blocked on ask_user, answer it.
    Otherwise queue as a follow-up for the next agent turn.
    """
    with session.lock:
        pq = session.pending_question
    if pq:
        pq.answer = message
        pq.answer_event.set()
        session.emit("user", message=message, subkind="answer", qid=pq.qid)
        return {"routed": "answer"}
    session.followup_queue.put(message)
    session.wakeup.set()
    session.emit("user", message=message, subkind="followup")
    return {"routed": "followup"}


def submit_answer(session: Session, qid: str, answer: str) -> bool:
    """Backwards-compat shim for the old answer endpoint."""
    with session.lock:
        pq = session.pending_question
    if not pq or pq.qid != qid:
        return False
    pq.answer = answer
    pq.answer_event.set()
    session.emit("user", message=answer, subkind="answer", qid=qid)
    return True


# ---------------------------------------------------------------------------
# ask_user tool (routes through the web UI's chat channel)
# ---------------------------------------------------------------------------

def make_ask_user_tool(session: Session):
    @tool
    def ask_user(question: str) -> str:
        """Ask the human operator a question via the web UI and wait for a reply.

        Use this when you need information you don't have: credentials, an OTP,
        scope clarification, permission to run an intrusive probe, etc. Keep
        questions short and specific. The call blocks until the operator
        sends a chat message.
        """
        pq = PendingQuestion(qid=uuid.uuid4().hex[:12], question=question)
        with session.lock:
            session.pending_question = pq
        session.emit("question", qid=pq.qid, question=question)
        answered = pq.answer_event.wait(timeout=3600)
        with session.lock:
            session.pending_question = None
        if not answered:
            return "(no answer — operator timed out)"
        return pq.answer or "(no answer)"

    return ask_user


# ---------------------------------------------------------------------------
# Agent execution
# ---------------------------------------------------------------------------

VULN_CLASSES = [
    "injection", "xss", "auth", "authz", "ssrf", "client-side",
    "session-mgmt", "api-testing", "business-logic", "crypto",
    "config-deploy", "error-handling", "info-gathering", "web-attacks",
]


def _build_subagents(classes: list[str], skip_exploit: bool, vars_: dict[str, str], tool_names: list[str]) -> list[dict]:
    subs: list[dict] = []
    prompts_dir = REPO_ROOT / "prompts"
    for vc in classes:
        if not (prompts_dir / f"vuln-{vc}.txt").exists():
            continue
        subs.append({
            "name": f"{vc}-vuln",
            "description": f"Hunt for {vc} vulnerabilities.",
            "system_prompt": load_prompt(f"vuln-{vc}", vars_),
        })
        if skip_exploit:
            continue
        if (prompts_dir / f"exploit-{vc}.txt").exists():
            subs.append({
                "name": f"{vc}-exploit",
                "description": f"Exploit confirmed {vc} vulnerabilities (proof only).",
                "system_prompt": load_prompt(f"exploit-{vc}", vars_),
            })
    return subs


def _stream_turn(session: Session, agent, messages: list[dict[str, Any]]) -> list[Any]:
    """Run one agent turn, emit fine-grained chat events, return final messages.

    Uses LangGraph multi-mode streaming:
      - "messages" -> token-by-token AI message chunks
      - "updates"  -> per-node updates (so we see tool calls/results)
      - "values"   -> full state snapshots (to capture the final message list)

    Emits to the SSE feed:
      token        {message_id, role, delta}      streaming text
      message_end  {message_id}                   message complete
      tool_call    {call_id, name, args}          model invoked a tool
      tool_result  {call_id, name, content}       tool returned
      subagent     {name, action}                 subagent dispatched/finished
    """
    final_messages: list[Any] = []
    seen_msg_ids: set[str] = set()
    seen_tool_call_ids: set[str] = set()

    try:
        stream = agent.stream(
            {"messages": messages},
            stream_mode=["messages", "updates", "values"],
        )
        for mode, data in stream:
            if mode == "messages":
                # data is (AIMessageChunk, metadata)
                chunk, _meta = data
                mid = getattr(chunk, "id", "") or ""
                content = getattr(chunk, "content", "")
                if isinstance(content, list):
                    # Tool-call-only chunks; skip.
                    content = ""
                if content:
                    session.emit("token", message_id=mid, role="ai", delta=str(content))
                    seen_msg_ids.add(mid)
                # Tool calls arrive on the chunk too.
                tcs = getattr(chunk, "tool_calls", None) or []
                for tc in tcs:
                    tc_id = tc.get("id") if isinstance(tc, dict) else getattr(tc, "id", None)
                    if not tc_id or tc_id in seen_tool_call_ids:
                        continue
                    seen_tool_call_ids.add(tc_id)
                    name = tc.get("name") if isinstance(tc, dict) else getattr(tc, "name", "")
                    args = tc.get("args") if isinstance(tc, dict) else getattr(tc, "args", {})
                    session.emit("tool_call", call_id=tc_id, name=name, args=_safe_json(args))
            elif mode == "updates":
                # data is {node_name: {messages: [...]}}
                if not isinstance(data, dict):
                    continue
                for node_name, node_update in data.items():
                    if not isinstance(node_update, dict):
                        continue
                    for m in node_update.get("messages", []) or []:
                        mtype = getattr(m, "type", "")
                        # Tool results
                        if mtype == "tool":
                            session.emit(
                                "tool_result",
                                call_id=getattr(m, "tool_call_id", "") or "",
                                name=getattr(m, "name", "") or "",
                                content=_truncate(getattr(m, "content", "")),
                            )
                        # Subagent dispatch hints
                        if "subagent" in (node_name or "").lower() or "task" in (node_name or "").lower():
                            session.emit("subagent", name=node_name, action="active")
            elif mode == "values":
                if isinstance(data, dict):
                    msgs = data.get("messages", [])
                    if msgs:
                        final_messages = msgs

        for mid in seen_msg_ids:
            session.emit("message_end", message_id=mid)

    except (TypeError, ValueError):
        # Older deepagents/langgraph: fall back to single-mode values stream.
        for chunk in agent.stream({"messages": messages}, stream_mode="values"):
            msgs = chunk.get("messages", []) if isinstance(chunk, dict) else []
            if msgs:
                final_messages = msgs
                last = msgs[-1]
                content = getattr(last, "content", "")
                if isinstance(content, list):
                    content = json.dumps(content)[:4000]
                if content:
                    session.emit("token", message_id="legacy", role="ai", delta=str(content)[:4000])
                    session.emit("message_end", message_id="legacy")
    except AttributeError:
        result = agent.invoke({"messages": messages})
        final_messages = result.get("messages", [])
        if final_messages:
            last = final_messages[-1]
            session.emit("token", message_id="legacy", role="ai", delta=str(getattr(last, "content", last))[:4000])
            session.emit("message_end", message_id="legacy")
    return final_messages


def _safe_json(v: Any) -> str:
    try:
        s = json.dumps(v, default=str)
    except Exception:
        s = str(v)
    return s[:1500]


def _truncate(v: Any, n: int = 2000) -> str:
    s = v if isinstance(v, str) else (json.dumps(v, default=str) if v is not None else "")
    return s if len(s) <= n else s[:n] + f"... (truncated, {len(s) - n} more)"


def _run_agent(session: Session) -> None:
    try:
        from deepagents import create_deep_agent

        session.status = "running"
        session.emit("status", status="running")

        config_context = ""
        login_instructions = ""
        if session.config_path:
            config_context = Path(session.config_path).read_text()
            shared_login = REPO_ROOT / "prompts" / "shared" / "login-instructions.txt"
            if shared_login.exists():
                login_instructions = shared_login.read_text()

        template_vars = {
            "WEB_URL": session.url,
            "TARGET_URL": session.url,
            "ADDITIONAL_TARGETS": "",
            "ACCOUNTS": "",
            "SEED_DATA": "",
            "EXPLORATION_LIMITS": "Stay strictly within scope. Read-only probing first.",
            "API_SCHEMAS": "",
            "CONFIG_CONTEXT": config_context,
            "LOGIN_INSTRUCTIONS": login_instructions,
            "REPO": session.repo or "(none)",
            "DELIVERABLES_DIR": session.deliverables,
        }

        ask_user_tool = make_ask_user_tool(session)
        tools = ALL_TOOLS + [ask_user_tool]
        tool_names = [t.name for t in tools]

        subagents = _build_subagents(session.classes, session.skip_exploit, template_vars, tool_names)
        session.emit("log", line=f"Spawned {len(subagents)} subagents.")

        planner_instructions = load_prompt("recon", template_vars) + f"""

# Orchestration rules
- Target: {session.url}
- Local repo (for code-assisted DAST): ./repos/{session.repo or '(none — pure DAST)'}
- Persist every finding via `write_finding` into: {session.deliverables}
- Phase 1: recon (whatweb, subfinder, nmap, nuclei, http_get).
- Non-GET HTTP (POST login/register, PUT password, PATCH/DELETE, OPTIONS,
  mass-assignment, BFLA writes) → use `http_request(method, url,
  headers_json, body)`. Do not ask the operator for a curl/shell helper.
- Phase 2: dispatch one vuln subagent per relevant class — in parallel.
- Phase 3: confirmed vulns → matching exploit subagent (unless skip_exploit).
- Phase 4: write 00-executive-summary.md in {session.deliverables}.

# Human in the loop
- Use the `ask_user` tool whenever you need creds, scope, OTPs, or
  confirmation before an intrusive probe. The operator is at a web UI; keep
  questions short and specific.
- The operator can also send free-form chat messages between turns to
  redirect, ask questions, or change priorities — treat them as authoritative
  instructions.

# Config (may be empty)
{config_context or '(no config provided)'}
"""

        agent = create_deep_agent(
            model=session.model,
            tools=tools,
            system_prompt=planner_instructions,
            subagents=subagents,
        )

        messages: list[Any] = [{"role": "user", "content": session.initial_message}]

        # Multi-turn loop: run agent, then wait for follow-up messages.
        while True:
            messages = _stream_turn(session, agent, messages)

            session.status = "idle"
            session.emit("status", status="idle")

            # Wait for a follow-up message or until the user closes the session.
            session.wakeup.clear()
            session.wakeup.wait()  # blocks until submit_message sets it

            # Drain queued follow-ups.
            followups: list[str] = []
            while True:
                try:
                    followups.append(session.followup_queue.get_nowait())
                except Empty:
                    break
            if not followups:
                continue

            for m in followups:
                messages.append({"role": "user", "content": m})

            session.status = "running"
            session.emit("status", status="running")

    except Exception as e:
        session.status = "error"
        session.error = f"{type(e).__name__}: {e}"
        session.emit("error", message=session.error, traceback=traceback.format_exc()[-2000:])
        session.emit("status", status="error")


def start_session(
    url: str,
    repo: str,
    config_path: Optional[str],
    deliverables: str,
    model: str = "claude-opus-4-7",
    classes: Optional[list[str]] = None,
    skip_exploit: bool = False,
    initial_message: Optional[str] = None,
    config_yaml_text: Optional[str] = None,
) -> Session:
    Path(deliverables).mkdir(parents=True, exist_ok=True)

    # If the user pasted YAML inline, persist it to a temp file alongside
    # deliverables so the run is reproducible.
    if config_yaml_text and not config_path:
        tmp = Path(deliverables) / "custom-config.yaml"
        tmp.write_text(config_yaml_text)
        config_path = str(tmp)

    if not initial_message:
        initial_message = (
            f"Conduct a full DAST pentest of {url}."
            + (f" Repo: {repo}." if repo else " (No local repo — pure DAST.)")
            + f" Write all deliverables to {deliverables}."
            " Start with recon, then dispatch the vulnerability subagents you judge"
            " relevant. Use `ask_user` whenever you need information from the operator."
            " End by writing 00-executive-summary.md."
        )

    session = Session(
        id=uuid.uuid4().hex[:12],
        url=url,
        repo=repo,
        config_path=config_path,
        deliverables=deliverables,
        model=model,
        classes=classes or VULN_CLASSES,
        skip_exploit=skip_exploit,
        initial_message=initial_message,
    )
    # Persist scan metadata next to deliverables/ so the run survives a server
    # restart and shows up in the historical scans list.
    scan_folder = Path(deliverables).parent.name
    try:
        meta_path = Path(deliverables).parent / "meta.json"
        meta_path.write_text(json.dumps({
            "id": session.id,
            "url": url,
            "repo": repo,
            "model": model,
            "classes": session.classes,
            "skip_exploit": skip_exploit,
            "started_at": session.started_at,
            "config_path": config_path,
        }, indent=2))
    except Exception:
        pass
    # Register in Postgres too (no-op if DATABASE_URL is unset). The agent's
    # write_finding writes happen on disk; webapp.list_deliverables syncs them
    # into the DB on each live-session refresh.
    db.upsert_scan(
        session.id,
        url=url,
        repo=repo,
        model=model,
        classes=session.classes,
        skip_exploit=skip_exploit,
        config_path=config_path,
        scan_folder=scan_folder,
        status="pending",
    )
    register_session(session)
    session.emit("status", status="pending")
    t = threading.Thread(target=_run_agent, args=(session,), daemon=True)
    session.thread = t
    t.start()
    return session


def drain_events(session: Session, timeout: float = 15.0):
    """Yield events as they arrive until the session terminates."""
    deadline = time.time() + timeout
    while True:
        try:
            evt = session.events.get(timeout=1.0)
            yield evt
            deadline = time.time() + timeout
            if evt.get("kind") == "status" and evt.get("status") == "error":
                return
        except Empty:
            if session.status == "error" and session.events.empty():
                return
            if time.time() > deadline:
                yield {"ts": time.time(), "kind": "heartbeat"}
                deadline = time.time() + timeout
