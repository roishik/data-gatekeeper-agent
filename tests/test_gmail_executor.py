"""Layer 4 tests: the pure query-building helper, plus GoogleGmailClient's
create_draft against a fake googleapiclient service (the rest of
GoogleGmailClient needs live credentials and is exercised through the
fake in tests/test_pipeline_injection.py instead)."""
from __future__ import annotations

import base64
from email import message_from_bytes

from app.gmail_executor import GoogleGmailClient, build_search_query


def test_build_search_query_without_newer_than_days():
    assert build_search_query("invoice", None) == "invoice"


def test_build_search_query_with_newer_than_days():
    assert build_search_query("invoice", 7) == "invoice newer_than:7d"


class _Call:
    def __init__(self, result):
        self._result = result

    def execute(self):
        return self._result


class _Drafts:
    def __init__(self):
        self.created_bodies: list[dict] = []

    def create(self, userId, body):
        self.created_bodies.append(body)
        # Echo back the threadId the caller set (Gmail returns the draft's
        # message resource, which carries the thread it landed in), or None
        # for a new-email draft.
        thread_id = body.get("message", {}).get("threadId")
        return _Call({"id": "draft_abc", "message": {"id": "m1", "threadId": thread_id}})


class _Users:
    def __init__(self, drafts: "_Drafts"):
        self._drafts = drafts

    def drafts(self):
        return self._drafts


class _Service:
    def __init__(self):
        self._drafts = _Drafts()
        self._users = _Users(self._drafts)

    def users(self):
        return self._users


def test_create_draft_never_calls_send():
    """Structural proof the module docstring's guarantee holds: the fake
    service below exposes ONLY drafts().create() -- no send()/messages()
    method at all -- so if create_draft ever called a send endpoint, this
    test would fail with an AttributeError, not silently pass."""
    service = _Service()
    client = GoogleGmailClient()
    client._service = lambda scopes: service  # type: ignore[method-assign]

    result = client.create_draft(to="alice@example.com", subject="Hi", body="Hello there")

    assert result.draft_id == "draft_abc"
    assert result.to == "alice@example.com"
    assert result.subject == "Hi"


def test_create_draft_encodes_to_and_subject_and_body():
    service = _Service()
    client = GoogleGmailClient()
    client._service = lambda scopes: service  # type: ignore[method-assign]

    client.create_draft(to="alice@example.com", subject="Hi there", body="Hello there")

    raw = service._drafts.created_bodies[0]["message"]["raw"]
    decoded = base64.urlsafe_b64decode(raw.encode("ascii"))
    message = message_from_bytes(decoded)
    assert message["to"] == "alice@example.com"
    assert message["subject"] == "Hi there"
    assert message.get_payload() == "Hello there"


def test_create_draft_without_thread_id_starts_a_new_thread():
    """No thread_id -> the draft body carries no threadId, i.e. a plain new
    email, and the result reports no thread."""
    service = _Service()
    client = GoogleGmailClient()
    client._service = lambda scopes: service  # type: ignore[method-assign]

    result = client.create_draft(to="alice@example.com", subject="Hi", body="Hello")

    assert "threadId" not in service._drafts.created_bodies[0]["message"]
    assert result.thread_id is None


def test_create_draft_files_into_thread_when_thread_id_given():
    """A thread_id -> the draft is created with that threadId (reply-in-
    thread), and the result reflects the thread it landed in."""
    service = _Service()
    client = GoogleGmailClient()
    client._service = lambda scopes: service  # type: ignore[method-assign]

    result = client.create_draft(
        to="alice@example.com", subject="Re: Q3 review", body="Sounds good", thread_id="thread_xyz"
    )

    assert service._drafts.created_bodies[0]["message"]["threadId"] == "thread_xyz"
    assert result.thread_id == "thread_xyz"
    # Still never a send: the fake service exposes only drafts().create().
    assert result.draft_id == "draft_abc"
