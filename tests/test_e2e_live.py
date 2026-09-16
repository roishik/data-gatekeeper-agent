"""
test_e2e_live.py — TRUE end-to-end tests that exercise the whole live
system, not the offline pipeline with fakes.

Every OTHER test in this suite is deliberately offline (fakes behind
Protocols, no network, no credentials). These are the opposite: they
send a REAL email from the owner's own Gmail account
(roishik10@gmail.com) to the deployed gatekeeper inbox, then read the
gatekeeper's REAL reply back out of Gmail and assert on it. That means
they cross AgentMail's webhook, the live Cloud Run service, the
quarantined reader LLM (or the deterministic block parser), the Google
executors, and the reply path -- the exact chain that the offline tests
can't see, and where the 2026-09-16 "Schema is too complex." outage
lived unnoticed because the reader LLM was only ever exercised against a
fake.

They are SKIPPED by default. To run them:

    RUN_E2E=1 uv run pytest tests/test_e2e_live.py -v

Requirements when RUN_E2E=1:
  * GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET / GOOGLE_REFRESH_TOKEN in the
    environment (or .env) -- the same owner-account OAuth credentials the
    service uses. The send step needs the gmail.compose scope (which the
    minted refresh token already covers -- see CLAUDE.md); the read step
    needs gmail.readonly. Both are subsets of the granted scopes.
  * OWNER_EMAIL (the account that sends, and that the reply comes back to)
    and GATEKEEPER_INBOX_ADDRESS (roi.shikler@agentmail.to).
  * The deployed service must be live, and OWNER_EMAIL must be in the
    service's ALLOWED_SENDERS (roishik10@gmail.com is, per CLAUDE.md).

Each test embeds a unique request_id in the outbound mail and waits for a
reply whose ---GATEKEEPER-RESPONSE--- block carries that same id, so
concurrent/old mail can't cause a false match. A round trip normally
takes well under a minute; the poll waits up to E2E_REPLY_TIMEOUT
seconds.

NOTE: these send real email and consume a slot against the service's
daily request cap -- run them deliberately, not in a tight loop.
"""
from __future__ import annotations

import base64
import os
import re
import time
import uuid

import pytest
import yaml

from app.config import GATEKEEPER_INBOX_ADDRESS, OWNER_EMAIL, have_google_credentials

RUN_E2E = os.environ.get("RUN_E2E") == "1"
E2E_REPLY_TIMEOUT = int(os.environ.get("E2E_REPLY_TIMEOUT", "180"))
E2E_POLL_INTERVAL = int(os.environ.get("E2E_POLL_INTERVAL", "10"))

pytestmark = [
    pytest.mark.e2e,
    pytest.mark.skipif(not RUN_E2E, reason="live end-to-end test; set RUN_E2E=1 to run"),
]

_GMAIL_COMPOSE_SCOPE = "https://www.googleapis.com/auth/gmail.compose"  # send
_GMAIL_READONLY_SCOPE = "https://www.googleapis.com/auth/gmail.readonly"  # read reply


def _require_config() -> None:
    missing = []
    if not have_google_credentials():
        missing.append("GOOGLE_CLIENT_ID/GOOGLE_CLIENT_SECRET/GOOGLE_REFRESH_TOKEN")
    if not OWNER_EMAIL:
        missing.append("OWNER_EMAIL")
    if not GATEKEEPER_INBOX_ADDRESS:
        missing.append("GATEKEEPER_INBOX_ADDRESS")
    if missing:
        pytest.skip(f"missing config for live e2e: {', '.join(missing)}")


def _gmail_service(scope: str):
    from googleapiclient.discovery import build

    from app.google_auth_helper import build_google_credentials

    creds = build_google_credentials(scopes=[scope])
    return build("gmail", "v1", credentials=creds, cache_discovery=False)


def _send_from_owner(subject: str, body: str) -> None:
    """Send a real email from the owner's account to the gatekeeper inbox.

    Uses gmail.compose (which grants send) rather than adding any send
    capability to the production app -- this is a test harness, kept
    entirely out of app/. The gatekeeper itself still never sends mail
    (it only ever creates drafts / replies via AgentMail)."""
    from email.mime.text import MIMEText

    message = MIMEText(body)
    message["to"] = GATEKEEPER_INBOX_ADDRESS
    message["from"] = OWNER_EMAIL
    message["subject"] = subject
    raw = base64.urlsafe_b64encode(message.as_bytes()).decode("ascii")

    service = _gmail_service(_GMAIL_COMPOSE_SCOPE)
    service.users().messages().send(userId="me", body={"raw": raw}).execute()


def _decode_body(payload: dict) -> str:
    """Pull the text/plain body out of a Gmail message payload (walking
    multipart parts if needed)."""
    def _walk(part: dict) -> str:
        if part.get("mimeType") == "text/plain":
            data = part.get("body", {}).get("data")
            if data:
                return base64.urlsafe_b64decode(data.encode("ascii")).decode("utf-8", "replace")
        for sub in part.get("parts", []) or []:
            text = _walk(sub)
            if text:
                return text
        # Single-part message: body may sit directly on the payload.
        data = part.get("body", {}).get("data")
        if data:
            return base64.urlsafe_b64decode(data.encode("ascii")).decode("utf-8", "replace")
        return ""

    return _walk(payload)


def _parse_response_block(body: str) -> dict | None:
    """Extract and YAML-parse the ---GATEKEEPER-RESPONSE--- block."""
    start = body.find("---GATEKEEPER-RESPONSE---")
    if start == -1:
        return None
    rest = body[start + len("---GATEKEEPER-RESPONSE---"):]
    end = rest.find("---END---")
    block = rest[:end] if end != -1 else rest
    try:
        data = yaml.safe_load(block)
    except yaml.YAMLError:
        return None
    return data if isinstance(data, dict) else None


def _wait_for_reply(request_id: str) -> tuple[dict, str]:
    """Poll the owner's Gmail for a gatekeeper reply whose response block
    carries `request_id`. Returns (parsed response block, full body text),
    or fails the test after E2E_REPLY_TIMEOUT seconds. The body is returned
    too so a caller can read prose the block omits (e.g. a `thread_id`)."""
    service = _gmail_service(_GMAIL_READONLY_SCOPE)
    query = f"from:{GATEKEEPER_INBOX_ADDRESS} newer_than:1d"
    deadline = time.monotonic() + E2E_REPLY_TIMEOUT

    while time.monotonic() < deadline:
        listed = service.users().messages().list(userId="me", q=query, maxResults=15).execute()
        for m in listed.get("messages", []):
            msg = service.users().messages().get(userId="me", id=m["id"], format="full").execute()
            body = _decode_body(msg.get("payload", {}))
            if request_id in body:
                block = _parse_response_block(body)
                if block and block.get("request_id") == request_id:
                    return block, body
        time.sleep(E2E_POLL_INTERVAL)

    pytest.fail(f"no gatekeeper reply for request_id={request_id} within {E2E_REPLY_TIMEOUT}s")


def _new_request_id(tag: str) -> str:
    return f"e2e-{tag}-{uuid.uuid4().hex[:8]}"


def test_e2e_fenced_block_gmail_search_completes():
    """The deterministic path: a well-formed ---GATEKEEPER-REQUEST--- block
    must round-trip to status=completed with no LLM involved."""
    _require_config()
    request_id = _new_request_id("block")
    body = (
        "Hi Gatekeeper,\n\n"
        "---GATEKEEPER-REQUEST---\n"
        f"request_id: {request_id}\n"
        "verb: gmail.search\n"
        "params:\n"
        "  query: newer_than:7d\n"
        "  max_results: 3\n"
        "---END---\n"
    )
    _send_from_owner(f"gatekeeper e2e block {request_id}", body)

    block, _body = _wait_for_reply(request_id)
    assert block["status"] == "completed", block


def test_e2e_freeform_gmail_search_completes_via_reader_llm():
    """The regression that mattered on 2026-09-16: a FREEFORM request (no
    fenced block, exactly like the AlphaSights email that failed) must go
    through the quarantined reader LLM and resolve to gmail.search =
    completed -- not 'unsupported'. This is the case that a fake-backed
    test can never catch."""
    _require_config()
    request_id = _new_request_id("freeform")
    body = (
        "Please search my Gmail for messages from wiz in the last 7 days and "
        "return the list.\n\n"
        f"Please use request_id {request_id} for this request.\n"
    )
    _send_from_owner(f"gatekeeper e2e freeform {request_id}", body)

    block, _body = _wait_for_reply(request_id)
    assert block["status"] == "completed", block


def test_e2e_freeform_calendar_list_completes_via_reader_llm():
    """A second reader-LLM path (a different verb + stage-2 schema) to
    confirm the two-stage extraction works for more than gmail.search."""
    _require_config()
    request_id = _new_request_id("cal")
    body = (
        "What's on my calendar tomorrow?\n\n"
        f"Please use request_id {request_id} for this request.\n"
    )
    _send_from_owner(f"gatekeeper e2e calendar {request_id}", body)

    block, _body = _wait_for_reply(request_id)
    assert block["status"] == "completed", block


def test_e2e_gmail_create_draft_replies_in_thread():
    """The Palantir-reply fix, end to end: gmail.search exposes a real
    thread_id, and a follow-up gmail.create_draft carrying that thread_id
    files the draft into that conversation (reply-in-thread) rather than a
    new email. Both halves must round-trip live through the deployed
    service."""
    _require_config()

    # Step 1: derive a real thread_id from a live gmail.search reply.
    search_id = _new_request_id("thread-search")
    search_req = (
        "---GATEKEEPER-REQUEST---\n"
        f"request_id: {search_id}\n"
        "verb: gmail.search\n"
        "params:\n"
        "  query: newer_than:30d\n"
        "  max_results: 1\n"
        "---END---\n"
    )
    _send_from_owner(f"gatekeeper e2e thread-search {search_id}", search_req)
    search_block, search_body = _wait_for_reply(search_id)
    assert search_block["status"] == "completed", search_block
    if search_block.get("result_count", 0) < 1:
        pytest.skip("no recent Gmail message to derive a thread_id from")
    match = re.search(r"thread_id:\s*([A-Za-z0-9_-]+)", search_body)
    assert match, f"gmail.search reply did not expose a thread_id:\n{search_body}"
    thread_id = match.group(1)

    # Step 2: create a draft filed into that thread.
    draft_id = _new_request_id("thread-draft")
    draft_req = (
        "---GATEKEEPER-REQUEST---\n"
        f"request_id: {draft_id}\n"
        "verb: gmail.create_draft\n"
        "params:\n"
        f"  to: {OWNER_EMAIL}\n"
        "  subject: '[gatekeeper-e2e] Re: thread test'\n"
        "  body: Automated e2e draft, safe to delete.\n"
        f"  thread_id: {thread_id}\n"
        "---END---\n"
    )
    _send_from_owner(f"gatekeeper e2e thread-draft {draft_id}", draft_req)
    draft_block, draft_body = _wait_for_reply(draft_id)

    assert draft_block["status"] == "completed", draft_block
    # The reply echoes the thread the draft ACTUALLY landed in (read back
    # from Gmail's API response in the executor), so this proves Gmail
    # accepted the threadId, not just that we sent it.
    assert f"as a reply in thread {thread_id}" in draft_body, draft_body
