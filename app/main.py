"""
main.py — FastAPI app. One route that matters: POST /webhooks/agentmail.

All the actual logic lives in app/pipeline.py's handle_webhook() -- this
file's only job is HTTP plumbing: read the raw body (needed, unparsed,
for signature verification), read the three svix-* headers, construct
the real (credentialed) collaborators, and translate a WebhookOutcome
into an HTTP response.

Credentialed objects (the reader LLM, the Gmail client, the AgentMail
client) are built lazily, per request / per layer reached, rather than
once at import time -- importing this module (e.g. `uvicorn app.main:app
--reload` during development, or a test importing it) must not require
every credential to be present, only using the parts that need them
does. The two stores (state, audit) ARE built once at import time,
because InMemoryStateStore/JSONLAuditLog need no credentials and a
Sheets-backed prod deployment still only needs Google credentials, which
Cloud Run always has configured before the service starts serving
traffic.

Concurrency (made explicit 2026-09-22): the webhook route reads the raw
body asynchronously, then runs the blocking pipeline on the threadpool
(run_in_threadpool) under one process-wide lock. Requests are therefore
handled strictly one at a time -- which the state store's check-then-set
dedupe, the audit log's in-memory hash chain, and the cached
(non-thread-safe) Google service objects all rely on -- while the event
loop stays free and /health stays responsive. Before, the route called the
blocking pipeline directly from `async def`: the same one-at-a-time
behavior, but only by accident, and with /health stuck behind it.
Cloud Run's max-instances=1 extends the single-writer guarantee across
the service (except for a brief overlap during a revision rollout, which
scripts/verify_audit_chain.py would detect as a forked chain).

Nothing internal is echoed to the caller: rejections get an empty 202,
handled requests an "ok" 200. Reasons go to logs and the audit trail
only. The auto-generated /docs, /redoc and /openapi.json are disabled --
the one real endpoint is signature-gated and has no business being
self-describing to the public internet.
"""
from __future__ import annotations

import logging
import threading

from fastapi import FastAPI, Request, Response
from starlette.concurrency import run_in_threadpool

from app.agentmail_client import HttpAgentMailClient
from app.audit_log import AuditLog, JSONLAuditLog, SheetsAuditLog
from app.calendar_executor import GoogleCalendarClient
from app.config import (
    AUDIT_LOG_BACKEND,
    AUDIT_LOG_PATH,
    GOOGLE_SHEETS_LOG_SPREADSHEET_ID,
    GOOGLE_SHEETS_STATE_SPREADSHEET_ID,
    STATE_STORE_BACKEND,
    have_typesafe_key,
)
from app.drive_executor import GoogleDriveClient
from app.gmail_executor import GoogleGmailClient
from app.injection_screen import InjectionScreen, NoOpInjectionScreen, TypeSafeInjectionScreen
from app.output_screen import NoOpOutputScreen, OutputScreen, TypeSafeOutputScreen
from app.pipeline import handle_webhook
from app.reader_llm import AnthropicReaderLLM
from app.state_store import InMemoryStateStore, SheetsStateStore, StateStore

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("gatekeeper.main")

app = FastAPI(title="data-gatekeeper-agent", docs_url=None, redoc_url=None, openapi_url=None)

_request_lock = threading.Lock()


def _build_state_store() -> StateStore:
    if STATE_STORE_BACKEND == "sheets":
        return SheetsStateStore(spreadsheet_id=GOOGLE_SHEETS_STATE_SPREADSHEET_ID)
    return InMemoryStateStore()


def _build_audit_log() -> AuditLog:
    if AUDIT_LOG_BACKEND == "sheets":
        return SheetsAuditLog(spreadsheet_id=GOOGLE_SHEETS_LOG_SPREADSHEET_ID)
    return JSONLAuditLog(AUDIT_LOG_PATH)


def _build_injection_screen() -> InjectionScreen:
    # Falls back to a no-op (every request scores None, unused by
    # anything) until TYPESAFE_API_KEY is actually configured -- lets
    # this ship and deploy before the secret exists. See
    # app/injection_screen.py's module docstring.
    if have_typesafe_key():
        return TypeSafeInjectionScreen()
    return NoOpInjectionScreen()


def _build_output_screen() -> OutputScreen:
    # Same no-key fallback as the injection screen. In prod the key is
    # always set; see app/output_screen.py for the fail-closed behavior
    # when TypeSafe itself is unreachable.
    if have_typesafe_key():
        return TypeSafeOutputScreen()
    return NoOpOutputScreen()


# Built once at import time -- see module docstring for why this pair is
# the exception to "construct credentialed things lazily".
_state_store = _build_state_store()
_audit_log = _build_audit_log()


def _handle_locked(body: bytes, svix_id: str, svix_timestamp: str, svix_signature: str):
    with _request_lock:
        return handle_webhook(
            body,
            svix_id=svix_id,
            svix_timestamp=svix_timestamp,
            svix_signature=svix_signature,
            state_store=_state_store,
            reader_llm=AnthropicReaderLLM(),
            injection_screen=_build_injection_screen(),
            output_screen=_build_output_screen(),
            gmail_client_factory=GoogleGmailClient,
            calendar_client_factory=GoogleCalendarClient,
            drive_client_factory=GoogleDriveClient,
            agentmail_client=HttpAgentMailClient(),
            audit_log=_audit_log,
        )


@app.post("/webhooks/agentmail")
async def agentmail_webhook(request: Request) -> Response:
    body = await request.body()
    outcome = await run_in_threadpool(
        _handle_locked,
        body,
        request.headers.get("svix-id", ""),
        request.headers.get("svix-timestamp", ""),
        request.headers.get("svix-signature", ""),
    )
    # Always 2xx for anything Layer 0 rejects (202) or Layer 1+ handled
    # (200) -- AgentMail retries on failure statuses, and a rejected or
    # already-answered event should never trigger a retry storm. A genuine
    # 5xx means this service broke before the message was marked seen,
    # which is exactly when a retry is wanted. The body never carries the
    # internal reason (module docstring).
    return Response(status_code=outcome.http_status, content="ok" if outcome.http_status == 200 else "")


# Not /healthz: Cloud Run's front end reserves that path and answers 404 itself.
@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}
