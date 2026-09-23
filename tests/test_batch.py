"""End-to-end tests for the `batch` verb (app/request_parser.py's
_parse_batch, app/pipeline.py's _run_batch/_run_batch_item,
app/reply_guard.py's render_batch_reply).

Each item runs as its own first-class request: own dedupe, own policy
decision, own execution, own daily-quota slot, own audit record (tagged
with the outer request's id as batch_id) -- a batch is purely a parsing
and reply-aggregation convenience, not a new execution model. These
tests pin that independence: one item's failure, denial, or duplicate
must not affect its siblings, and every item still gets audited even
though only ONE combined reply is ever sent.
"""
from __future__ import annotations

from app.pipeline import handle_webhook
from app.policy import BATCH_MAX_ITEMS
from app.state_store import REQUEST_COMPLETED, InMemoryStateStore
from tests.fakes import (
    FakeAgentMailClient,
    FakeCalendarClient,
    FakeDriveClient,
    FakeGmailClient,
    FakeInjectionScreen,
    FakeReaderLLM,
)
from tests.webhook_helpers import make_body, sign


def _call(
    body,
    *,
    state_store=None,
    injection_screen=None,
    gmail_results=None,
    agentmail_client=None,
    audit_log=None,
):
    svix_id, ts, sig = sign(body)
    fake_gmail = FakeGmailClient(results=gmail_results or [])
    fake_calendar = FakeCalendarClient()
    fake_drive = FakeDriveClient()
    outcome = handle_webhook(
        body,
        svix_id=svix_id,
        svix_timestamp=ts,
        svix_signature=sig,
        state_store=state_store or InMemoryStateStore(),
        reader_llm=FakeReaderLLM(),
        injection_screen=injection_screen or FakeInjectionScreen(),
        gmail_client_factory=lambda: fake_gmail,
        calendar_client_factory=lambda: fake_calendar,
        drive_client_factory=lambda: fake_drive,
        agentmail_client=agentmail_client or FakeAgentMailClient(),
        audit_log=audit_log,
    )
    return outcome, fake_gmail, fake_calendar, fake_drive


def _batch_text(batch_request_id: str, items: list[str]) -> str:
    return (
        f"---GATEKEEPER-REQUEST---\nrequest_id: {batch_request_id}\nverb: batch\nparams:\n  requests:\n"
        + "".join(items)
        + "---END---\n"
    )


def _batch_body(batch_request_id: str, items: list[str], **kwargs) -> bytes:
    return make_body(text=_batch_text(batch_request_id, items), **kwargs)


def _item(request_id: str, verb: str, params: dict) -> str:
    lines = [f"    - request_id: {request_id}\n", f"      verb: {verb}\n", "      params:\n"]
    if not params:
        lines[-1] = "      params: {}\n"
    else:
        for key, value in params.items():
            lines.append(f"        {key}: {value}\n")
    return "".join(lines)


def test_batch_happy_path_runs_every_item_and_gives_one_reply_with_one_audit_record_each(configured_env, audit_log):
    body = _batch_body("req_batch_1", [
        _item("req_item_search", "gmail.search", {"query": "invoice"}),
        _item("req_item_caps", "capabilities", {}),
        _item("req_item_draft", "gmail.create_draft", {"to": "a@example.com", "subject": "Hi", "body": "Hello"}),
    ])
    agentmail = FakeAgentMailClient()
    outcome, fake_gmail, _, _ = _call(body, agentmail_client=agentmail, audit_log=audit_log)

    assert outcome.http_status == 200
    assert len(agentmail.calls) == 1  # exactly one combined reply
    reply_text = agentmail.calls[0]["text"]
    assert "Item 1 (gmail.search" in reply_text
    assert "Item 2 (capabilities" in reply_text
    assert "Item 3 (gmail.create_draft" in reply_text
    assert "batch_results:" in reply_text
    assert "status: completed" in reply_text  # the outer batch's own status

    entries = audit_log.all_entries()
    # 1 container record (the outer "batch" verb) + 3 item records.
    assert len(entries) == 4
    container = next(e["record"] for e in entries if e["record"]["parsed_verb"] == "batch")
    assert container["batch_id"] is None
    assert container["parsed_request_id"] == "req_batch_1"

    item_records = {e["record"]["parsed_request_id"]: e["record"] for e in entries if e["record"]["parsed_verb"] != "batch"}
    assert set(item_records) == {"req_item_search", "req_item_caps", "req_item_draft"}
    for record in item_records.values():
        assert record["batch_id"] == "req_batch_1"
        assert record["reply_status"] == "completed"


def test_batch_over_the_item_cap_is_denied_wholesale(configured_env, audit_log):
    items = [_item(f"req_item_{i}", "capabilities", {}) for i in range(BATCH_MAX_ITEMS + 1)]
    body = _batch_body("req_batch_big", items)
    agentmail = FakeAgentMailClient()
    outcome, _, _, _ = _call(body, agentmail_client=agentmail, audit_log=audit_log)

    assert outcome.http_status == 200
    reply_text = agentmail.calls[0]["text"]
    assert "status: denied" in reply_text
    assert "error_code: invalid_request_block" in reply_text
    # Nothing ran: only the (denied) container gets audited.
    assert len(audit_log.all_entries()) == 1


def test_one_item_hitting_the_daily_cap_does_not_block_earlier_items(configured_env, audit_log, monkeypatch):
    import app.pipeline as pipeline_module

    monkeypatch.setattr(pipeline_module, "MAX_REQUESTS_PER_DAY", 2)
    body = _batch_body("req_batch_cap", [
        _item("req_item_1", "capabilities", {}),
        _item("req_item_2", "capabilities", {}),
        _item("req_item_3", "capabilities", {}),
    ])
    agentmail = FakeAgentMailClient()
    outcome, _, _, _ = _call(body, agentmail_client=agentmail, audit_log=audit_log)

    assert outcome.http_status == 200
    reply_text = agentmail.calls[0]["text"]
    assert "Item 1 (capabilities" in reply_text
    assert "Item 2 (capabilities" in reply_text
    assert "Item 3 (capabilities" in reply_text

    entries = {e["record"]["parsed_request_id"]: e["record"] for e in audit_log.all_entries()}
    assert entries["req_item_1"]["reply_status"] == "completed"
    assert entries["req_item_2"]["reply_status"] == "completed"
    assert entries["req_item_3"]["reply_status"] == "error"
    assert entries["req_item_3"]["reply_error_code"] == "rate_limited"


def test_one_item_denied_does_not_stop_its_siblings(configured_env, audit_log):
    body = _batch_body("req_batch_mixed", [
        _item("req_item_bad", "gmail.search", {}),  # missing required 'query' -> denied
        _item("req_item_good", "capabilities", {}),
    ])
    agentmail = FakeAgentMailClient()
    outcome, _, _, _ = _call(body, agentmail_client=agentmail, audit_log=audit_log)

    assert outcome.http_status == 200
    entries = {e["record"]["parsed_request_id"]: e["record"] for e in audit_log.all_entries()}
    assert entries["req_item_bad"]["reply_status"] == "denied"
    assert entries["req_item_bad"]["policy_error_code"] == "invalid_params"
    assert entries["req_item_good"]["reply_status"] == "completed"


def test_duplicate_request_id_within_one_batch_denies_only_that_item(configured_env, audit_log):
    """app/request_parser.py's _parse_batch already flags a repeated
    request_id within one batch as its own item-level parse error -- but
    the SECOND item still goes through _run_batch_item like any item
    (mirroring how a top-level parse-error request still runs the
    dedupe check before Layer 3 ever looks at parse_error), and the
    first occurrence has, by then, already recorded that request_id as
    processing/completed -- so the ordinary duplicate-request path
    catches it first. Either way, only the first occurrence actually runs."""
    body = _batch_body("req_batch_dup", [
        _item("req_dup", "capabilities", {}),
        _item("req_dup", "capabilities", {}),
    ])
    agentmail = FakeAgentMailClient()
    outcome, _, _, _ = _call(body, agentmail_client=agentmail, audit_log=audit_log)

    assert outcome.http_status == 200
    reply_text = agentmail.calls[0]["text"]
    assert "Item 2 (capabilities, request_id: req_dup):" in reply_text
    assert "status: duplicate" in reply_text

    entries = [e["record"] for e in audit_log.all_entries() if e["record"]["parsed_verb"] != "batch"]
    assert len(entries) == 2
    assert entries[0]["reply_status"] == "completed"
    assert entries[1]["reply_status"] == "duplicate"


def test_injected_content_denies_writes_across_the_whole_batch_but_not_reads(configured_env, audit_log):
    """The whole batch is screened as ONE block (see app/pipeline.py's
    module docstring on batch injection screening) -- a high score
    anywhere in it gates every WRITE item via apply_screen_gate, exactly
    as it would a single request, while reads stay log-only."""
    body = _batch_body("req_batch_injected", [
        _item("req_item_read", "gmail.search", {"query": "invoice"}),
        _item("req_item_write", "gmail.create_draft", {"to": "a@example.com", "subject": "Hi", "body": "Hello"}),
    ])
    agentmail = FakeAgentMailClient()
    outcome, fake_gmail, _, _ = _call(
        body, injection_screen=FakeInjectionScreen(score=0.95), agentmail_client=agentmail, audit_log=audit_log,
    )

    assert outcome.http_status == 200
    entries = {e["record"]["parsed_request_id"]: e["record"] for e in audit_log.all_entries()}
    assert entries["req_item_read"]["reply_status"] == "completed"
    assert len(fake_gmail.calls) == 1  # the read still ran
    assert entries["req_item_write"]["reply_status"] == "denied"
    assert entries["req_item_write"]["policy_error_code"] == "screened"


def test_batch_requires_a_non_empty_requests_list(configured_env, audit_log):
    body = _batch_body("req_batch_empty", [])
    agentmail = FakeAgentMailClient()
    outcome, _, _, _ = _call(body, agentmail_client=agentmail, audit_log=audit_log)

    assert outcome.http_status == 200
    reply_text = agentmail.calls[0]["text"]
    assert "status: denied" in reply_text
    assert "non-empty 'requests' list" in reply_text or "error_code: invalid_request_block" in reply_text


def test_a_batch_item_cannot_itself_be_a_batch(configured_env, audit_log):
    text = (
        "---GATEKEEPER-REQUEST---\nrequest_id: req_batch_nested\nverb: batch\nparams:\n  requests:\n"
        "    - request_id: req_inner\n      verb: batch\n      params:\n        requests: []\n"
        "---END---\n"
    )
    agentmail = FakeAgentMailClient()
    outcome, _, _, _ = _call(make_body(text=text), agentmail_client=agentmail, audit_log=audit_log)

    assert outcome.http_status == 200
    reply_text = agentmail.calls[0]["text"]
    assert "a batch cannot contain another batch" in reply_text


def test_resending_a_batch_email_does_not_repeat_already_completed_items(configured_env, audit_log):
    """The outer batch request_id is deduped like any request; a resend
    (new message_id, same batch request_id) is denied outright before
    any item runs again -- consistent with a standalone request's own
    resend semantics."""
    store = InMemoryStateStore()
    body1 = _batch_body("req_batch_resend", [_item("req_item_x", "capabilities", {})], message_id="msg_1")
    agentmail = FakeAgentMailClient()
    _call(body1, state_store=store, agentmail_client=agentmail, audit_log=audit_log)
    assert store.get_request_status("req_batch_resend") == REQUEST_COMPLETED

    body2 = _batch_body("req_batch_resend", [_item("req_item_x", "capabilities", {})], message_id="msg_2")
    outcome2, _, _, _ = _call(body2, state_store=store, agentmail_client=agentmail, audit_log=audit_log)
    assert outcome2.http_status == 200
    assert "status: duplicate" in agentmail.calls[1]["text"]
