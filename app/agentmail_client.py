"""
agentmail_client.py — the only module that sends outbound email.

Wraps AgentMail's reply-to-message endpoint:

    POST /v0/inboxes/{inbox_id}/messages/{message_id}/reply
    { "to": [...], "cc": [...], "bcc": [...], "text": "...", "html": "..." }
    -> { "message_id": "...", "thread_id": "..." }

behind an interface so app/pipeline.py and its tests never touch the
network -- see tests/fakes.py's FakeAgentMailClient.

Uses plain httpx rather than the `agentmail` PyPI package so this file
has exactly one documented shape to be wrong about (the REST endpoint)
instead of two (the endpoint AND an SDK wrapper's mapping onto it).

The endpoint path, method, and field names above were confirmed against
AgentMail's current published API reference (raw markdown fetched during
this build, not just an AI-summarized pass). NOT exercised against a
live AgentMail API call, though -- no network call this service would
make has actually been made. See the final build report's "could not
verify" section for what that leaves open (live delivery timing/retry
behavior, and the exact `agentmail` SDK's own wrapper, which this file
deliberately avoids depending on).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from app.config import AGENTMAIL_API_KEY

_BASE_URL = "https://api.agentmail.to/v0"


@dataclass(frozen=True)
class ReplyResult:
    message_id: str
    thread_id: str


class AgentMailClient(Protocol):
    def reply(self, inbox_id: str, message_id: str, to: str, bcc: str, text: str) -> ReplyResult: ...


class HttpAgentMailClient:
    """Real implementation, gated behind AGENTMAIL_API_KEY."""

    def __init__(self, api_key: str | None = None):
        self._api_key = api_key or AGENTMAIL_API_KEY
        if not self._api_key:
            raise RuntimeError("AGENTMAIL_API_KEY is not set -- cannot construct HttpAgentMailClient.")

    def reply(self, inbox_id: str, message_id: str, to: str, bcc: str, text: str) -> ReplyResult:
        import httpx  # lazy: keep this module importable without a live key at import time

        resp = httpx.post(
            f"{_BASE_URL}/inboxes/{inbox_id}/messages/{message_id}/reply",
            headers={"Authorization": f"Bearer {self._api_key}"},
            json={"to": [to], "bcc": [bcc], "text": text},
            timeout=30.0,
        )
        resp.raise_for_status()
        data = resp.json()
        return ReplyResult(message_id=data["message_id"], thread_id=data["thread_id"])
