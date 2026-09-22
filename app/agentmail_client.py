"""
agentmail_client.py — the only module that sends outbound email.

Wraps AgentMail's reply-to-message endpoint:

    POST /v0/inboxes/{inbox_id}/messages/{message_id}/reply
    { "to": [...], "text": "..." }
    -> { "message_id": "...", "thread_id": "..." }

behind an interface so app/pipeline.py and its tests never touch the
network -- see tests/fakes.py's FakeAgentMailClient.

Uses plain httpx rather than the `agentmail` PyPI package so this file
has exactly one documented shape to be wrong about (the REST endpoint)
instead of two (the endpoint AND an SDK wrapper's mapping onto it).

The endpoint path, method, and field names above were confirmed against
AgentMail's published API reference, and every reply this service has sent
since 2026-09-15 went through this code (tests/test_e2e_live.py exercises
it end to end).
"""
from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import quote
from typing import Protocol

from app.config import AGENTMAIL_API_KEY

_BASE_URL = "https://api.agentmail.to/v0"


@dataclass(frozen=True)
class ReplyResult:
    message_id: str
    thread_id: str


class AgentMailClient(Protocol):
    def reply(self, inbox_id: str, message_id: str, to: str, text: str) -> ReplyResult: ...


class HttpAgentMailClient:
    """Real implementation, gated behind AGENTMAIL_API_KEY."""

    def __init__(self, api_key: str | None = None):
        self._api_key = api_key or AGENTMAIL_API_KEY
        if not self._api_key:
            raise RuntimeError("AGENTMAIL_API_KEY is not set -- cannot construct HttpAgentMailClient.")

    def reply(self, inbox_id: str, message_id: str, to: str, text: str) -> ReplyResult:
        import httpx  # lazy: keep this module importable without a live key at import time

        # Both ids are percent-encoded as single path segments: an RFC 5322
        # Message-ID may legally contain '/', which would otherwise split
        # the path and turn a real reply into a 404.
        resp = httpx.post(
            f"{_BASE_URL}/inboxes/{quote(inbox_id, safe='')}/messages/{quote(message_id, safe='')}/reply",
            headers={"Authorization": f"Bearer {self._api_key}"},
            # No cc/bcc, ever: the reply goes to the verified sender only.
            # (Until 2026-09-22 the owner was BCC'd on every reply; dropped
            # at the owner's request -- AgentMail's thread history is the
            # human-readable record now.)
            json={"to": [to], "text": text},
            timeout=15.0,
        )
        resp.raise_for_status()
        data = resp.json()
        return ReplyResult(message_id=data["message_id"], thread_id=data["thread_id"])
