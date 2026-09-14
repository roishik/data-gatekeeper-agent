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
"""
from __future__ import annotations

import logging

from fastapi import FastAPI, Request, Response

from app.agentmail_client import HttpAgentMailClient
from app.audit_log import AuditLog, JSONLAuditLog, SheetsAuditLog
from app.config import (
    AUDIT_LOG_BACKEND,
    AUDIT_LOG_PATH,
    GOOGLE_SHEETS_LOG_SPREADSHEET_ID,
    GOOGLE_SHEETS_STATE_SPREADSHEET_ID,
    STATE_STORE_BACKEND,
)
from app.gmail_executor import GoogleGmailClient
from app.pipeline import handle_webhook
from app.reader_llm import AnthropicReaderLLM
from app.state_store import InMemoryStateStore, SheetsStateStore, StateStore

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("gatekeeper.main")

app = FastAPI(title="data-gatekeeper-agent")


def _build_state_store() -> StateStore:
    if STATE_STORE_BACKEND == "sheets":
        return SheetsStateStore(spreadsheet_id=GOOGLE_SHEETS_STATE_SPREADSHEET_ID)
    return InMemoryStateStore()


def _build_audit_log() -> AuditLog:
    if AUDIT_LOG_BACKEND == "sheets":
        return SheetsAuditLog(spreadsheet_id=GOOGLE_SHEETS_LOG_SPREADSHEET_ID)
    return JSONLAuditLog(AUDIT_LOG_PATH)


# Built once at import time -- see module docstring for why this pair is
# the exception to "construct credentialed things lazily".
_state_store = _build_state_store()
_audit_log = _build_audit_log()


@app.post("/webhooks/agentmail")
async def agentmail_webhook(request: Request) -> Response:
    body = await request.body()
    outcome = handle_webhook(
        body,
        svix_id=request.headers.get("svix-id", ""),
        svix_timestamp=request.headers.get("svix-timestamp", ""),
        svix_signature=request.headers.get("svix-signature", ""),
        state_store=_state_store,
        reader_llm=AnthropicReaderLLM(),
        gmail_client_factory=GoogleGmailClient,
        agentmail_client=HttpAgentMailClient(),
        audit_log=_audit_log,
    )
    # Always 2xx-ish for anything Layer 0 rejects (202) or Layer 1+
    # handled without error (200) -- AgentMail retries on failure
    # statuses, and a rejected/ignored event should never trigger a
    # retry storm. A genuine 5xx here means this service itself broke,
    # not that the request was invalid.
    return Response(status_code=outcome.http_status, content=outcome.reason)


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}
