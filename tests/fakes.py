"""
fakes.py — test doubles for every interface app/pipeline.py depends on.

Every provider-boundary module in app/ (reader_llm, gmail_executor,
agentmail_client) is written against a Protocol precisely so tests never
touch the network, a real Google/AgentMail/Anthropic API, or a real
credential -- see each module's docstring. These fakes are the other
half of that contract.
"""
from __future__ import annotations

from app.agentmail_client import ReplyResult
from app.gmail_executor import GmailResult
from app.reader_llm import LLMExtraction


class FakeReaderLLM:
    """Scripted quarantined-LLM stand-in. Returns a fixed
    `response` (or None, simulating a call/parse failure) regardless of
    what `email_text` says -- this is the point: a REAL quarantined LLM
    is untrusted precisely because injected text in `email_text` might
    influence it, but this fake demonstrates that even a maximally
    naive stand-in can't leak anything beyond its scripted schema-shaped
    response, because ReaderLLM.extract()'s return type has no room for
    anything else. Records every call for assertions."""

    def __init__(self, response: LLMExtraction | None = None):
        self.response = response
        self.calls: list[str] = []
        self.last_usage: dict[str, int] | None = {"input_tokens": 42, "output_tokens": 7}

    def extract(self, email_text: str) -> LLMExtraction | None:
        self.calls.append(email_text)
        return self.response


class FakeGmailClient:
    """Returns a fixed list of GmailResult regardless of the query --
    tests that care about query construction assert against
    `self.calls` instead of branching behavior on the query string."""

    def __init__(self, results: list[GmailResult] | None = None):
        self.results = results if results is not None else []
        self.calls: list[dict] = []

    def search(self, query: str, max_results: int, newer_than_days: int | None) -> list[GmailResult]:
        self.calls.append({"query": query, "max_results": max_results, "newer_than_days": newer_than_days})
        return self.results[:max_results]


class FakeAgentMailClient:
    """Records every reply() call instead of sending anything -- tests
    assert on `self.calls` to check who got mailed and what BCC was
    set, which is exactly what the "reply only to the verified sender,
    with BCC set" test needs."""

    def __init__(self):
        self.calls: list[dict] = []
        self._next_id = 0

    def reply(self, inbox_id: str, message_id: str, to: str, bcc: str, text: str) -> ReplyResult:
        self._next_id += 1
        self.calls.append({"inbox_id": inbox_id, "message_id": message_id, "to": to, "bcc": bcc, "text": text})
        return ReplyResult(message_id=f"reply-{self._next_id}", thread_id=f"thread-{self._next_id}")
