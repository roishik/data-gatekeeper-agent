"""Layer 2 tests: deterministic block parsing vs. the quarantined-LLM
fallback, and the "never coerce" rule (invalid input on either path
becomes verb="unsupported")."""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.policy import Verb
from app.reader_llm import LLMExtraction, VerbLiteral
from app.request_parser import parse_request
from tests.fakes import FakeReaderLLM


def test_parses_valid_fenced_block():
    email_text = (
        "Hi Gatekeeper,\n\nPlease check my inbox.\n\n"
        "---GATEKEEPER-REQUEST---\n"
        "request_id: req_123\n"
        "verb: gmail.search\n"
        "params:\n"
        "  query: invoice\n"
        "  max_results: 3\n"
        "---END---\n"
    )
    reader = FakeReaderLLM()
    parsed = parse_request(email_text, "msg_1", reader)

    assert parsed.source == "block"
    assert parsed.request_id == "req_123"
    assert parsed.verb == "gmail.search"
    assert parsed.params == {"query": "invoice", "max_results": 3}
    assert reader.calls == []  # the LLM must never be invoked when a valid block exists


def test_falls_back_to_llm_when_no_block_present():
    reader = FakeReaderLLM(response=LLMExtraction(verb="gmail.search", request_id="req_9", query="invoice"))
    parsed = parse_request("just a plain English email, no block here", "msg_1", reader)

    assert parsed.source == "llm"
    assert parsed.request_id == "req_9"
    assert parsed.verb == "gmail.search"
    assert parsed.params == {"query": "invoice"}
    assert reader.calls == ["just a plain English email, no block here"]


@pytest.mark.parametrize(
    "email_text",
    [
        # Malformed YAML inside an otherwise well-fenced block.
        "---GATEKEEPER-REQUEST---\nrequest_id: [unterminated\n---END---\n",
        # Missing verb.
        "---GATEKEEPER-REQUEST---\nrequest_id: req_1\n---END---\n",
        # Missing request_id.
        "---GATEKEEPER-REQUEST---\nverb: gmail.search\n---END---\n",
        # Block content isn't a mapping at all.
        "---GATEKEEPER-REQUEST---\n- just a list\n---END---\n",
        # params isn't a mapping.
        "---GATEKEEPER-REQUEST---\nrequest_id: req_1\nverb: gmail.search\nparams: not-a-dict\n---END---\n",
    ],
)
def test_invalid_block_falls_back_to_llm(email_text):
    reader = FakeReaderLLM(response=None)
    parsed = parse_request(email_text, "msg_1", reader)
    assert parsed.source == "llm"
    assert reader.calls == [email_text]  # the LLM DOES get invoked once the block fails to parse


def test_llm_returning_none_becomes_unsupported():
    """Simulates a network failure or invalid/unparseable JSON from the
    quarantined LLM -- the 'never coerce' rule: no partial guess, just
    unsupported."""
    reader = FakeReaderLLM(response=None)
    parsed = parse_request("do something ambiguous", "msg_42", reader)

    assert parsed.source == "llm"
    assert parsed.verb == "unsupported"
    assert parsed.params == {}
    assert parsed.request_id.startswith("req-") and len(parsed.request_id) == 16
    assert parse_request("do something ambiguous", "msg_42", FakeReaderLLM(response=None)).request_id == parsed.request_id


def test_llm_unsupported_verb_passes_through_as_unsupported():
    reader = FakeReaderLLM(response=LLMExtraction(verb="unsupported"))
    parsed = parse_request("what's the weather like", "msg_1", reader)
    assert parsed.verb == "unsupported"


def test_llm_extraction_rejects_injected_extra_fields():
    """Structural proof of the quarantine boundary: LLMExtraction's
    extra="forbid" means even constructing an instance with an
    attacker-shaped extra field (e.g. an injected 'cc'/'recipients' --
    'to' is deliberately NOT used here since it's a legitimate
    gmail.create_draft field now) raises, rather than silently accepting
    and carrying it forward."""
    with pytest.raises(ValidationError):
        LLMExtraction(verb="gmail.search", recipients="attacker@evil.com")  # type: ignore[call-arg]


def test_llm_extracts_calendar_day_offset_and_days():
    reader = FakeReaderLLM(response=LLMExtraction(verb="calendar.list_events", request_id="req_cal", day_offset=1, days=1))
    parsed = parse_request("what's on my calendar tomorrow?", "msg_1", reader)

    assert parsed.source == "llm"
    assert parsed.verb == "calendar.list_events"
    assert parsed.params == {"day_offset": 1, "days": 1}


def test_llm_extracts_gmail_create_draft_fields():
    reader = FakeReaderLLM(
        response=LLMExtraction(verb="gmail.create_draft", request_id="req_d", to="a@b.com", subject="Hi", body="Hello")
    )
    parsed = parse_request("please draft an email to a@b.com", "msg_1", reader)

    assert parsed.verb == "gmail.create_draft"
    assert parsed.params == {"to": "a@b.com", "subject": "Hi", "body": "Hello"}


def test_llm_extracts_calendar_create_event_fields_including_attendees():
    reader = FakeReaderLLM(
        response=LLMExtraction(
            verb="calendar.create_event", request_id="req_ce", title="Coffee", day_offset=1,
            start_time="14:00", duration_minutes=30, attendees=["a@b.com", "c@d.com"],
        )
    )
    parsed = parse_request("set up coffee tomorrow at 2pm with a@b.com and c@d.com", "msg_1", reader)

    assert parsed.verb == "calendar.create_event"
    assert parsed.params == {
        "title": "Coffee", "day_offset": 1, "start_time": "14:00",
        "duration_minutes": 30, "attendees": ["a@b.com", "c@d.com"],
    }


def test_llm_extracts_calendar_update_event_event_id():
    reader = FakeReaderLLM(response=LLMExtraction(verb="calendar.update_event", request_id="req_ue", event_id="ev1", title="New"))
    parsed = parse_request("rename event ev1 to New", "msg_1", reader)

    assert parsed.verb == "calendar.update_event"
    assert parsed.params == {"event_id": "ev1", "title": "New"}


def test_llm_extracts_drive_create_file_fields():
    reader = FakeReaderLLM(response=LLMExtraction(verb="drive.create_file", request_id="req_df", name="notes.txt", content="hi"))
    parsed = parse_request("create a drive file called notes.txt with content hi", "msg_1", reader)

    assert parsed.verb == "drive.create_file"
    assert parsed.params == {"name": "notes.txt", "content": "hi"}


def test_reader_llm_verb_literal_matches_policy_verb_enum():
    """The reader LLM's schema and the policy engine's verb enum must
    name exactly the same verbs -- checked directly rather than assumed,
    so the two can't silently drift apart."""
    import typing

    literal_values = set(typing.get_args(VerbLiteral))
    policy_values = {v.value for v in Verb}
    assert literal_values == policy_values
