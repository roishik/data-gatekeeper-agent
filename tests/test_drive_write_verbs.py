"""End-to-end pipeline tests for drive.update_file / drive.append_file
(added 2026-10-21): policy -> executor -> reply, by file_id and by exact
name, plus the denial paths (unknown name, ambiguous identification).
Layer-4 details (newline rule, folder/mimeType vetting) live in
tests/test_drive_executor.py."""
from __future__ import annotations

from app.pipeline import handle_webhook
from app.reader_llm import LLMExtraction
from app.state_store import InMemoryStateStore
from tests.fakes import (
    FakeAgentMailClient,
    FakeCalendarClient,
    FakeDriveClient,
    FakeGmailClient,
    FakeInjectionScreen,
    FakeReaderLLM,
)
from tests.webhook_helpers import make_body, sign


def _run(text: str, audit_log, reader=None):
    body = make_body(text=text)
    svix_id, ts, sig = sign(body)
    drive = FakeDriveClient()
    agentmail = FakeAgentMailClient()
    handle_webhook(
        body, svix_id=svix_id, svix_timestamp=ts, svix_signature=sig,
        state_store=InMemoryStateStore(), reader_llm=reader or FakeReaderLLM(),
        injection_screen=FakeInjectionScreen(),
        gmail_client_factory=FakeGmailClient, calendar_client_factory=FakeCalendarClient,
        drive_client_factory=lambda: drive, agentmail_client=agentmail, audit_log=audit_log,
    )
    return drive, agentmail


def _block(request_id: str, verb: str, params: str) -> str:
    return f"---GATEKEEPER-REQUEST---\nrequest_id: {request_id}\nverb: {verb}\nparams:\n{params}---END---\n"


def test_update_file_by_id_end_to_end(configured_env, audit_log):
    drive, agentmail = _run(_block("req_up1", "drive.update_file", "  file_id: file_7\n  content: new text\n"), audit_log)

    assert drive.calls == [{"op": "update_file", "file_id": "file_7", "content": "new text"}]
    text = agentmail.calls[0]["text"]
    assert "Updated Drive file 'known.txt': https://drive.google.com/file/d/file_7/view." in text
    assert "status: completed" in text
    record = audit_log.all_entries()[0]["record"]
    assert record["drive_file_id"] == "file_7"


def test_append_file_by_name_end_to_end(configured_env, audit_log):
    drive, agentmail = _run(_block("req_ap1", "drive.append_file", "  name: known.txt\n  content: more\n"), audit_log)

    assert drive.calls == [
        {"op": "resolve_file_id", "name": "known.txt"},
        {"op": "append_file", "file_id": "file_known", "content": "more"},
    ]
    text = agentmail.calls[0]["text"]
    assert "Appended to Drive file 'known.txt': https://drive.google.com/file/d/file_known/view." in text
    assert "status: completed" in text


def test_append_file_unknown_name_is_denied_not_found(configured_env, audit_log):
    drive, agentmail = _run(_block("req_ap2", "drive.append_file", "  name: missing.txt\n  content: more\n"), audit_log)

    assert drive.calls == [{"op": "resolve_file_id", "name": "missing.txt"}]  # no write happened
    text = agentmail.calls[0]["text"]
    assert "status: denied" in text and "error_code: not_found" in text


def test_update_file_with_both_identifiers_is_denied_before_any_call(configured_env, audit_log):
    drive, agentmail = _run(
        _block("req_up2", "drive.update_file", "  file_id: file_7\n  name: known.txt\n  content: x\n"), audit_log
    )

    assert drive.calls == []
    text = agentmail.calls[0]["text"]
    assert "status: denied" in text and "error_code: invalid_params" in text


def test_update_file_freeform_request_through_the_reader_llm(configured_env, audit_log):
    reader = FakeReaderLLM(response=LLMExtraction(
        verb="drive.update_file", request_id="req_llm1", file_id="file_7", content="rewritten",
    ))
    drive, agentmail = _run("please rewrite my notes file", audit_log, reader=reader)

    assert drive.calls == [{"op": "update_file", "file_id": "file_7", "content": "rewritten"}]
    assert "status: completed" in agentmail.calls[0]["text"]


def test_batch_create_then_append_by_name(configured_env, audit_log):
    text = (
        "---GATEKEEPER-REQUEST---\nrequest_id: req_b1\nverb: batch\nparams:\n  requests:\n"
        "    - request_id: req_b1_create\n      verb: drive.create_file\n"
        "      params:\n        name: known.txt\n        content: first\n"
        "    - request_id: req_b1_append\n      verb: drive.append_file\n"
        "      params:\n        name: known.txt\n        content: second\n"
        "---END---\n"
    )
    drive, agentmail = _run(text, audit_log)

    assert [c["op"] for c in drive.calls] == ["create_file", "resolve_file_id", "append_file"]
    reply = agentmail.calls[0]["text"]
    assert reply.count("status: completed") == 3  # both items + the batch container
    assert "Created Drive file 'known.txt': https://drive.google.com/file/d/file_1/view." in reply
    assert "Appended to Drive file 'known.txt'" in reply
