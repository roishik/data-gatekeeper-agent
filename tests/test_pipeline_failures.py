"""Failure-path tests for app/pipeline.py (added 2026-09-22).

Until then, any exception after a message was marked seen escaped the
pipeline: no reply, no audit record, and -- because the message was already
marked seen -- no AgentMail retry either. These tests pin the replacement
guarantees from pipeline.py's module docstring: exactly one reply and one
audit record per request whatever breaks, a resend allowed only when it's
safe, and a write never repeated.
"""
from __future__ import annotations

import httplib2
import pytest
from googleapiclient.errors import HttpError

import app.pipeline as pipeline
from app.failures import GatekeeperDenied, classify_failure
from app.pipeline import handle_webhook
from app.state_store import REQUEST_COMPLETED, REQUEST_EFFECT_DONE, REQUEST_FAILED, InMemoryStateStore
from tests.fakes import (
    FakeAgentMailClient,
    FakeCalendarClient,
    FakeDriveClient,
    FakeGmailClient,
    FakeInjectionScreen,
    FakeReaderLLM,
)
from tests.webhook_helpers import make_body, sign

SEARCH = "---GATEKEEPER-REQUEST---\nrequest_id: {rid}\nverb: gmail.search\nparams:\n  query: invoice\n---END---\n"
DRAFT = (
    "---GATEKEEPER-REQUEST---\nrequest_id: {rid}\nverb: gmail.create_draft\nparams:\n"
    "  to: alice@example.com\n  subject: Hi\n  body: Hello\n---END---\n"
)


def _http_error(status: int) -> HttpError:
    return HttpError(resp=httplib2.Response({"status": status}), content=b"{}")


class _RaisingGmail(FakeGmailClient):
    def __init__(self, exc: BaseException):
        super().__init__()
        self._exc = exc

    def search(self, query, max_results, newer_than_days):
        raise self._exc


class _FailingAuditLog:
    def append(self, record):
        raise OSError("sheets unreachable")

    def append_many(self, records):
        raise OSError("sheets unreachable")

    def all_entries(self):
        return []


def _call(body, *, store=None, gmail=None, agentmail=None, audit_log=None, calendar=None):
    svix_id, ts, sig = sign(body)
    gmail = gmail or FakeGmailClient()
    calendar = calendar or FakeCalendarClient()
    return handle_webhook(
        body,
        svix_id=svix_id,
        svix_timestamp=ts,
        svix_signature=sig,
        state_store=store if store is not None else InMemoryStateStore(),
        reader_llm=FakeReaderLLM(),
        injection_screen=FakeInjectionScreen(),
        gmail_client_factory=lambda: gmail,
        calendar_client_factory=lambda: calendar,
        drive_client_factory=lambda: FakeDriveClient(),
        agentmail_client=agentmail or FakeAgentMailClient(),
        audit_log=audit_log,
    )


# ── classify_failure ────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "status, code, retryable",
    [(404, "not_found", False), (410, "not_found", False), (409, "conflict", False),
     (400, "upstream_rejected", False), (403, "upstream_rejected", False),
     (429, "upstream_unavailable", True), (500, "upstream_unavailable", True), (503, "upstream_unavailable", True)],
)
def test_google_http_errors_map_to_codes(status, code, retryable):
    failure = classify_failure(_http_error(status))
    assert (failure.code, failure.retryable, failure.type_name) == (code, retryable, "HttpError")


def test_network_failures_are_retryable_and_unknown_ones_are_not():
    assert classify_failure(TimeoutError()).code == "upstream_unavailable"
    assert classify_failure(ConnectionResetError()).retryable is True
    unknown = classify_failure(KeyError("x"))
    assert (unknown.code, unknown.retryable, unknown.type_name) == ("internal_error", False, "KeyError")


# ── executor failures ───────────────────────────────────────────────────


def test_executor_error_gets_an_error_reply_and_one_audit_record(configured_env, audit_log):
    agentmail = FakeAgentMailClient()
    store = InMemoryStateStore()
    outcome = _call(make_body(text=SEARCH.format(rid="req_404")), store=store,
                    gmail=_RaisingGmail(_http_error(404)), agentmail=agentmail, audit_log=audit_log)

    assert (outcome.http_status, outcome.reason) == (200, "failed")
    assert len(agentmail.calls) == 1
    text = agentmail.calls[0]["text"]
    assert "status: error" in text and "error_code: not_found" in text and "retryable: false" in text
    entries = audit_log.all_entries()
    assert len(entries) == 1
    record = entries[0]["record"]
    assert (record["failure_code"], record["failure_stage"], record["failure_type"]) == ("not_found", "layer4", "HttpError")
    assert record["reply_status"] == "error" and record["reply_message_id"]
    # Nothing was written, so the request may be resent.
    assert store.get_request_status("req_404") == REQUEST_FAILED


def test_a_stale_wedged_processing_request_is_resendable(configured_env, audit_log, monkeypatch):
    """Before this fix (Instinct's review, F2/M3): a process that died
    mid-request left its request_id stuck at `processing` forever, and
    every resend got `duplicate` claiming an earlier reply existed when
    none did. A `processing` row older than PROCESSING_STALE_AFTER_SECONDS
    must be treated as resendable, not wedged."""
    import app.state_store as state_store_module

    monkeypatch.setattr(state_store_module, "PROCESSING_STALE_AFTER_SECONDS", 0)

    store = InMemoryStateStore()
    # Simulate a crash: `processing` was recorded but the request never
    # reached _finalize_request_statuses -- no completed/effect_done/failed
    # row was ever written.
    store.set_request_status("req_wedged", "processing")

    healthy = FakeGmailClient()
    outcome = _call(
        make_body(message_id="msg_resend", text=SEARCH.format(rid="req_wedged")),
        store=store, gmail=healthy, audit_log=audit_log,
    )

    assert outcome.reason == "processed"
    assert len(healthy.calls) == 1  # it actually ran, not just re-replied
    assert store.get_request_status("req_wedged") == REQUEST_COMPLETED


def test_a_stale_processing_write_is_never_re_run(configured_env, audit_log, monkeypatch):
    """The counterpart of the test above: for a WRITE, a stale `processing`
    row may mean the side effect happened and only `effect_done` was lost
    (a crash between the two). Re-running it would repeat the write, so it
    stays a duplicate however old it is."""
    import app.state_store as state_store_module

    monkeypatch.setattr(state_store_module, "PROCESSING_STALE_AFTER_SECONDS", 0)

    store = InMemoryStateStore()
    store.set_request_status("req_wedged_write", "processing")

    gmail = FakeGmailClient()
    agentmail = FakeAgentMailClient()
    outcome = _call(
        make_body(message_id="msg_resend", text=DRAFT.format(rid="req_wedged_write")),
        store=store, gmail=gmail, agentmail=agentmail, audit_log=audit_log,
    )

    assert outcome.reason == "duplicate_request"
    assert gmail.calls == []  # no second draft
    assert "status: duplicate" in agentmail.calls[0]["text"]


def test_transient_error_says_retryable_and_a_resend_runs_again(configured_env, audit_log):
    store = InMemoryStateStore()
    agentmail = FakeAgentMailClient()
    text = SEARCH.format(rid="req_flaky")
    _call(make_body(message_id="msg_1", text=text), store=store, gmail=_RaisingGmail(TimeoutError()),
          agentmail=agentmail, audit_log=audit_log)
    assert "retryable: true" in agentmail.calls[0]["text"]

    healthy = FakeGmailClient()
    outcome = _call(make_body(message_id="msg_2", text=text), store=store, gmail=healthy,
                    agentmail=agentmail, audit_log=audit_log)
    assert outcome.reason == "processed"
    assert len(healthy.calls) == 1
    assert store.get_request_status("req_flaky") == REQUEST_COMPLETED


def test_reply_reports_requests_remaining_today(configured_env, audit_log):
    import app.pipeline as pipeline_module

    monkeypatch_value = 5
    original = pipeline_module.MAX_REQUESTS_PER_DAY
    pipeline_module.MAX_REQUESTS_PER_DAY = monkeypatch_value
    try:
        store = InMemoryStateStore()
        agentmail = FakeAgentMailClient()
        store.record_request("instinct@example.com", "req_prior_1")
        store.record_request("instinct@example.com", "req_prior_2")
        _call(make_body(text=SEARCH.format(rid="req_quota")), store=store, agentmail=agentmail, audit_log=audit_log)
        # 2 already used + this one = 3 of 5, leaving 2.
        assert "requests_remaining_today: 2" in agentmail.calls[0]["text"]
    finally:
        pipeline_module.MAX_REQUESTS_PER_DAY = original


def test_execution_time_denial_is_denied_not_error(configured_env, audit_log):
    agentmail = FakeAgentMailClient()
    _call(make_body(text=SEARCH.format(rid="req_no")), gmail=_RaisingGmail(GatekeeperDenied("not_gatekeeper_event")),
          agentmail=agentmail, audit_log=audit_log)
    text = agentmail.calls[0]["text"]
    assert "status: denied" in text and "error_code: not_gatekeeper_event" in text
    assert audit_log.all_entries()[0]["record"]["failure_code"] is None


# ── reply failures ──────────────────────────────────────────────────────


def test_failed_reply_after_a_read_is_audited_and_the_request_may_be_resent(configured_env, audit_log):
    store = InMemoryStateStore()
    agentmail = FakeAgentMailClient()
    agentmail.fail_with = ConnectionResetError()
    outcome = _call(make_body(text=SEARCH.format(rid="req_read")), store=store, agentmail=agentmail, audit_log=audit_log)

    assert outcome.http_status == 200
    record = audit_log.all_entries()[0]["record"]
    assert record["reply_error"] == "ConnectionResetError" and record["reply_message_id"] is None
    assert store.get_request_status("req_read") == REQUEST_FAILED


def test_failed_reply_after_a_write_never_lets_a_resend_repeat_the_write(configured_env, audit_log):
    store = InMemoryStateStore()
    gmail = FakeGmailClient()
    agentmail = FakeAgentMailClient()
    agentmail.fail_with = ConnectionResetError()
    text = DRAFT.format(rid="req_write")
    _call(make_body(message_id="msg_1", text=text), store=store, gmail=gmail, agentmail=agentmail, audit_log=audit_log)

    drafts = lambda: [c for c in gmail.calls if "to" in c]  # noqa: E731 -- FakeGmailClient logs drafts in .calls
    assert len(drafts()) == 1
    record = audit_log.all_entries()[0]["record"]
    assert record["draft_id"] and record["reply_error"] == "ConnectionResetError"
    assert store.get_request_status("req_write") == REQUEST_EFFECT_DONE

    agentmail.fail_with = None
    outcome = _call(make_body(message_id="msg_2", text=text), store=store, gmail=gmail, agentmail=agentmail, audit_log=audit_log)
    assert outcome.reason == "duplicate_request"
    assert len(drafts()) == 1  # the draft was NOT created twice


def test_render_failure_falls_back_to_a_minimal_status_reply(configured_env, audit_log, monkeypatch):
    def _boom(*args, **kwargs):
        raise RuntimeError("formatter bug")

    monkeypatch.setattr(pipeline, "render_reply", _boom)
    agentmail = FakeAgentMailClient()
    _call(make_body(text=SEARCH.format(rid="req_fmt")), agentmail=agentmail, audit_log=audit_log)
    text = agentmail.calls[0]["text"]
    assert "---GATEKEEPER-RESPONSE---" in text and "request_id: req_fmt" in text and "status: completed" in text


# ── audit and Layer 0/1 edges ───────────────────────────────────────────


def test_audit_append_failure_never_takes_the_request_down(configured_env):
    agentmail = FakeAgentMailClient()
    outcome = _call(make_body(text=SEARCH.format(rid="req_audit")), agentmail=agentmail, audit_log=_FailingAuditLog())
    assert (outcome.http_status, outcome.reason) == (200, "processed")
    assert len(agentmail.calls) == 1


def test_unsigned_webhooks_are_not_written_to_the_audit_log(configured_env, audit_log):
    body = make_body(text=SEARCH.format(rid="req_x"))
    svix_id, ts, _ = sign(body)
    outcome = handle_webhook(
        body, svix_id=svix_id, svix_timestamp=ts, svix_signature="v1,Zm9yZ2Vk",
        state_store=InMemoryStateStore(), reader_llm=FakeReaderLLM(), injection_screen=FakeInjectionScreen(),
        gmail_client_factory=FakeGmailClient, calendar_client_factory=FakeCalendarClient,
        drive_client_factory=FakeDriveClient, agentmail_client=FakeAgentMailClient(), audit_log=audit_log,
    )
    assert (outcome.http_status, outcome.reason) == (202, "signature_mismatch")
    assert audit_log.all_entries() == []


def test_signed_but_unrecognized_payload_is_still_audited(configured_env, audit_log):
    body = b'{"event_type": "message.received", "message": "not-an-object"}'
    _call(body, audit_log=audit_log)
    record = audit_log.all_entries()[0]["record"]
    assert record["layer0_verdict"] == "unrecognized_payload_shape"


def test_state_store_failure_before_marking_seen_propagates_so_agentmail_retries(configured_env, audit_log):
    class _DownStore(InMemoryStateStore):
        def is_duplicate_message(self, message_id):
            raise OSError("sheets unreachable")

    with pytest.raises(OSError):
        _call(make_body(text=SEARCH.format(rid="req_down")), store=_DownStore(), audit_log=audit_log)


def test_failure_after_a_write_still_reports_the_write_as_done(configured_env, audit_log):
    """If something breaks AFTER the side effect (here: recording
    effect_done), the reply must say what was done -- never "error,
    retryable", which would invite a resend of a write that succeeded."""
    from app.state_store import REQUEST_EFFECT_DONE

    class _FlakyStore(InMemoryStateStore):
        def set_request_status(self, request_id, status, sender=""):
            if status == REQUEST_EFFECT_DONE:
                raise OSError("sheets hiccup")
            super().set_request_status(request_id, status, sender)

    gmail = FakeGmailClient()
    agentmail = FakeAgentMailClient()
    store = _FlakyStore()
    outcome = _call(make_body(text=DRAFT.format(rid="req_after")), store=store, gmail=gmail, agentmail=agentmail, audit_log=audit_log)

    assert outcome.reason == "failed"
    text = agentmail.calls[0]["text"]
    assert "status: completed" in text and "retryable: false" in text and "Created a draft" in text
    record = audit_log.all_entries()[0]["record"]
    assert (record["failure_code"], record["failure_stage"]) == ("upstream_unavailable", "layer1")
    assert record["draft_id"]
    # The final status write succeeded, so a resend is a duplicate, not a second draft.
    assert store.get_request_status("req_after") == "completed"
