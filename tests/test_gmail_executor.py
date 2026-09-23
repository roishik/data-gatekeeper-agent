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


class _Threads:
    """threads().get(format=metadata) -- returns a scripted thread and
    records the call, so tests can check it only ever asks for metadata."""

    def __init__(self, thread: dict | None):
        self._thread = thread
        self.calls: list[dict] = []

    def get(self, userId, id, format, metadataHeaders):
        self.calls.append({"id": id, "format": format, "metadataHeaders": metadataHeaders})
        return _Call(self._thread or {"messages": []})


class _Users:
    def __init__(self, drafts: "_Drafts", threads: "_Threads | None" = None):
        self._drafts = drafts
        self._threads = threads

    def drafts(self):
        return self._drafts

    def threads(self):
        if self._threads is None:
            raise AttributeError("threads")
        return self._threads


class _Service:
    """Exposes drafts() -- and threads() only when a thread is scripted --
    never messages().send() or drafts().send()."""

    def __init__(self, thread: dict | None = None):
        self._drafts = _Drafts()
        self._threads = _Threads(thread) if thread is not None else None
        self._users = _Users(self._drafts, self._threads)

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


def _msg(message_id: str, references: str | None = None, labels: list[str] | None = None) -> dict:
    headers = [{"name": "Message-ID", "value": message_id}]
    if references is not None:
        headers.append({"name": "References", "value": references})
    return {"labelIds": labels or ["INBOX"], "payload": {"headers": headers}}


def _draft_headers(service) -> dict:
    raw = service._drafts.created_bodies[0]["message"]["raw"]
    return message_from_bytes(base64.urlsafe_b64decode(raw.encode("ascii")))


def test_create_draft_files_into_thread_when_thread_id_given():
    """A thread_id -> the draft is created with that threadId (reply-in-
    thread), and the result reflects the thread it landed in."""
    service = _Service(thread={"messages": [_msg("<first@mail.example>")]})
    client = GoogleGmailClient()
    client._service = lambda scopes: service  # type: ignore[method-assign]

    result = client.create_draft(
        to="alice@example.com", subject="Re: Q3 review", body="Sounds good", thread_id="thread_xyz"
    )

    assert service._drafts.created_bodies[0]["message"]["threadId"] == "thread_xyz"
    assert result.thread_id == "thread_xyz"
    # Still never a send: the fake service exposes only drafts().create().
    assert result.draft_id == "draft_abc"


def test_reply_draft_sets_in_reply_to_and_references_from_the_last_real_message():
    """Without these headers the recipient's mail client shows the reply as
    a brand-new thread, whatever Gmail's threadId says."""
    thread = {"messages": [
        _msg("<a@mail.example>"),
        _msg("<b@mail.example>", references="<a@mail.example>"),
        _msg("<own-draft@mail.gmail.com>", labels=["DRAFT"]),  # an unsent draft is never replied to
    ]}
    service = _Service(thread=thread)
    client = GoogleGmailClient()
    client._service = lambda scopes: service  # type: ignore[method-assign]

    client.create_draft(to="bob@example.com", subject="Re: plan", body="ok", thread_id="thread_1")

    message = _draft_headers(service)
    assert message["In-Reply-To"] == "<b@mail.example>"
    assert message["References"] == "<a@mail.example> <b@mail.example>"
    # Metadata only -- never a message body.
    assert service._threads.calls == [{"id": "thread_1", "format": "metadata", "metadataHeaders": ["Message-ID", "References"]}]


def test_malformed_or_hostile_thread_headers_are_never_copied_into_the_draft():
    hostile = {"messages": [_msg("not-a-message-id\r\nBcc: attacker@evil.com")]}
    service = _Service(thread=hostile)
    client = GoogleGmailClient()
    client._service = lambda scopes: service  # type: ignore[method-assign]

    result = client.create_draft(to="bob@example.com", subject="Re: x", body="ok", thread_id="thread_1")

    message = _draft_headers(service)
    assert message["In-Reply-To"] is None and message["References"] is None and message["Bcc"] is None
    assert result.thread_id == "thread_1"  # still filed into the thread by threadId


def test_references_chain_is_capped():
    refs = " ".join(f"<r{i}@mail.example>" for i in range(50))
    service = _Service(thread={"messages": [_msg("<last@mail.example>", references=refs)]})
    client = GoogleGmailClient()
    client._service = lambda scopes: service  # type: ignore[method-assign]
    client.create_draft(to="bob@example.com", subject="Re: x", body="ok", thread_id="thread_1")
    chain = _draft_headers(service)["References"].split()
    assert len(chain) == 20 and chain[-1] == "<last@mail.example>"


# ── search: one batch request for all metadata ──────────────────────────


class _SearchMessages:
    def __init__(self, ids, metadata):
        self._ids = ids
        self._metadata = metadata
        self.get_calls: list[dict] = []

    def list(self, userId, q, maxResults):
        return _Call({"messages": [{"id": i} for i in self._ids]})

    def get(self, userId, id, format, metadataHeaders):
        self.get_calls.append({"id": id, "format": format, "metadataHeaders": metadataHeaders})
        return ("get", id)


class _Batch:
    def __init__(self, callback, metadata, fail_ids):
        self._callback = callback
        self._metadata = metadata
        self._fail_ids = fail_ids
        self.added: list[tuple] = []

    def add(self, request, request_id):
        self.added.append((request, request_id))

    def execute(self):
        for (_, message_id), request_id in reversed(self.added):  # out of order, like a real batch may answer
            if message_id in self._fail_ids:
                self._callback(request_id, None, RuntimeError(f"failed {message_id}"))
            else:
                self._callback(request_id, self._metadata[message_id], None)


class _SearchService:
    def __init__(self, ids, metadata, fail_ids=()):
        self.messages_api = _SearchMessages(ids, metadata)
        self._metadata = metadata
        self._fail_ids = set(fail_ids)
        self.batches: list[_Batch] = []

    def users(self):
        return self

    def messages(self):
        return self.messages_api

    def new_batch_http_request(self, callback):
        batch = _Batch(callback, self._metadata, self._fail_ids)
        self.batches.append(batch)
        return batch


def _meta(subject, thread_id):
    return {"threadId": thread_id, "snippet": f"snippet of {subject}",
            "payload": {"headers": [{"name": "Subject", "value": subject}, {"name": "From", "value": "x@example.com"}]}}


def test_search_fetches_all_metadata_in_one_batch_and_keeps_order():
    metadata = {"m1": _meta("first", "t1"), "m2": _meta("second", "t2"), "m3": _meta("third", "t3")}
    service = _SearchService(["m1", "m2", "m3"], metadata)
    client = GoogleGmailClient()
    client._service = lambda scopes: service  # type: ignore[method-assign]

    results = client.search(query="invoice", max_results=3, newer_than_days=None)

    assert [r.subject for r in results] == ["first", "second", "third"]
    assert [r.thread_id for r in results] == ["t1", "t2", "t3"]
    assert len(service.batches) == 1 and len(service.batches[0].added) == 3
    assert all(c["format"] == "metadata" and c["metadataHeaders"] == ["From", "Subject", "Date"]
               for c in service.messages_api.get_calls)


def test_search_raises_if_any_message_in_the_batch_fails():
    import pytest

    metadata = {"m1": _meta("first", "t1"), "m2": _meta("second", "t2")}
    service = _SearchService(["m1", "m2"], metadata, fail_ids={"m2"})
    client = GoogleGmailClient()
    client._service = lambda scopes: service  # type: ignore[method-assign]
    with pytest.raises(RuntimeError):
        client.search(query="invoice", max_results=2, newer_than_days=None)


def test_search_with_no_matches_makes_no_batch():
    service = _SearchService([], {})
    client = GoogleGmailClient()
    client._service = lambda scopes: service  # type: ignore[method-assign]
    assert client.search(query="nothing", max_results=5, newer_than_days=None) == []
    assert service.batches == []
