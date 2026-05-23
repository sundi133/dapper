"""In-process session manager for web-driven DeepAgents runs.

Each Session runs the deep agent on a background thread, publishes events to
a thread-safe queue (consumed by an SSE endpoint), and exposes a
question/answer channel so the agent's `ask_user` tool can pause for human
input via the web UI instead of stdin.
"""
from __future__ import annotations

import json
import threading
import time
import traceback
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from queue import Empty, Queue
from typing import Any, Optional

from langchain_core.tools import tool

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
    status: str = "pending"  # pending | running | done | error
    error: Optional[str] = None
    events: Queue = field(default_factory=Queue)
    pending_question: Optional[PendingQuestion] = None
    lock: threading.Lock = field(default_factory=threading.Lock)
    thread: Optional[threading.Thread] = None
    started_at: float = field(default_factory=time.time)

    def emit(self, kind: str, **payload: Any) -> None:
        evt = {"ts": time.time(), "kind": kind, **payload}
        self.events.put(evt)


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
# ask_user replacement that routes through the web UI
# ---------------------------------------------------------------------------

def make_ask_user_tool(session: Session):
    @tool
    def ask_user(question: str) -> str:
        """Ask the human operator a question via the web UI and wait for a reply.

        Use this when you need information you don't have: credentials, an OTP,
        scope clarification, permission to run an intrusive probe, etc. Keep
        questions short and specific. The call blocks until the operator
        answers in the UI.
        """
        pq = PendingQuestion(qid=uuid.uuid4().hex[:12], question=question)
        with session.lock:
            session.pending_question = pq
        session.emit("question", qid=pq.qid, question=question)
        # Block until the UI answers (or 1h timeout).
        answered = pq.answer_event.wait(timeout=3600)
        with session.lock:
            session.pending_question = None
        if not answered:
            return "(no answer — operator timed out)"
        return pq.answer or "(no answer)"

    return ask_user


def submit_answer(session: Session, qid: str, answer: str) -> bool:
    with session.lock:
        pq = session.pending_question
    if not pq or pq.qid != qid:
        return False
    pq.answer = answer
    pq.answer_event.set()
    session.emit("answer", qid=qid, answer=answer)
    return True


# ---------------------------------------------------------------------------
# Run the deep agent on a background thread
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
            "prompt": load_prompt(f"vuln-{vc}", vars_),
            "tools": tool_names,
        })
        if skip_exploit:
            continue
        if (prompts_dir / f"exploit-{vc}.txt").exists():
            subs.append({
                "name": f"{vc}-exploit",
                "description": f"Exploit confirmed {vc} vulnerabilities (proof only).",
                "prompt": load_prompt(f"exploit-{vc}", vars_),
                "tools": tool_names,
            })
    return subs


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
            "REPO": session.repo,
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
- Local repo (for code-assisted DAST): ./repos/{session.repo}
- Persist every finding via `write_finding` into: {session.deliverables}
- Phase 1: recon (whatweb, subfinder, nmap, nuclei, http_get).
- Phase 2: dispatch one vuln subagent per relevant class — in parallel.
- Phase 3: confirmed vulns → matching exploit subagent (unless skip_exploit).
- Phase 4: write 00-executive-summary.md in {session.deliverables}.

# Human in the loop
- Use the `ask_user` tool whenever you need creds, scope, OTPs, or
  confirmation before an intrusive probe. The operator is at a web UI; keep
  questions short and specific.

# Config (may be empty)
{config_context or '(no config provided)'}
"""

        agent = create_deep_agent(
            model=session.model,
            tools=tools,
            instructions=planner_instructions,
            subagents=subagents,
        )

        initial = (
            f"Conduct a full DAST pentest of {session.url}. Repo: {session.repo}. "
            f"Write all deliverables to {session.deliverables}. "
            "Start with recon, then dispatch the vulnerability subagents you judge "
            "relevant. Use `ask_user` whenever you need information from the "
            "operator. End by writing 00-executive-summary.md."
        )

        # Stream agent steps via .stream so the UI sees progress.
        try:
            for chunk in agent.stream({"messages": [{"role": "user", "content": initial}]}, stream_mode="values"):
                msgs = chunk.get("messages", []) if isinstance(chunk, dict) else []
                if not msgs:
                    continue
                last = msgs[-1]
                content = getattr(last, "content", "")
                role = getattr(last, "type", "msg")
                if isinstance(content, list):
                    content = json.dumps(content)[:4000]
                if content:
                    session.emit("step", role=role, content=str(content)[:4000])
        except AttributeError:
            # Fallback if the installed deepagents version lacks .stream
            result = agent.invoke({"messages": [{"role": "user", "content": initial}]})
            final = result["messages"][-1]
            session.emit("step", role="final", content=str(getattr(final, "content", final))[:4000])

        session.status = "done"
        session.emit("status", status="done")
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
) -> Session:
    Path(deliverables).mkdir(parents=True, exist_ok=True)
    session = Session(
        id=uuid.uuid4().hex[:12],
        url=url,
        repo=repo,
        config_path=config_path,
        deliverables=deliverables,
        model=model,
        classes=classes or VULN_CLASSES,
        skip_exploit=skip_exploit,
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
            if evt.get("kind") == "status" and evt.get("status") in ("done", "error"):
                return
        except Empty:
            if session.status in ("done", "error") and session.events.empty():
                return
            if time.time() > deadline:
                # heartbeat
                yield {"ts": time.time(), "kind": "heartbeat"}
                deadline = time.time() + timeout
