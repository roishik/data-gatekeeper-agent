"""Layer 3 tests: deny-by-default, param bounds, and the sensitive-query
refusal list."""
from __future__ import annotations

import dataclasses

import pytest

from app.policy import (
    CalendarCreateEventParams,
    CalendarDeleteEventParams,
    CalendarListEventsParams,
    CalendarUpdateEventParams,
    DriveCreateFileParams,
    GmailCreateDraftParams,
    GmailSearchParams,
    Verb,
    evaluate_policy,
)


def test_gmail_search_allowed_with_defaults():
    decision = evaluate_policy("gmail.search", {"query": "invoice"})
    assert decision.status == "allowed"
    assert decision.params == GmailSearchParams(query="invoice", max_results=5, newer_than_days=None)


def test_gmail_search_missing_query_denied():
    decision = evaluate_policy("gmail.search", {})
    assert decision.status == "denied"
    assert decision.error_code == "invalid_params"


def test_gmail_search_query_too_long_denied():
    decision = evaluate_policy("gmail.search", {"query": "x" * 201})
    assert decision.status == "denied"
    assert decision.error_code == "invalid_params"


def test_gmail_search_query_at_max_length_allowed():
    decision = evaluate_policy("gmail.search", {"query": "x" * 200})
    assert decision.status == "allowed"


@pytest.mark.parametrize("max_results", [0, -1, 11, 100])
def test_gmail_search_max_results_out_of_bounds_denied(max_results):
    decision = evaluate_policy("gmail.search", {"query": "invoice", "max_results": max_results})
    assert decision.status == "denied"
    assert decision.error_code == "invalid_params"


@pytest.mark.parametrize("max_results", [1, 5, 10])
def test_gmail_search_max_results_in_bounds_allowed(max_results):
    decision = evaluate_policy("gmail.search", {"query": "invoice", "max_results": max_results})
    assert decision.status == "allowed"
    assert decision.params.max_results == max_results


def test_gmail_search_max_results_wrong_type_denied():
    decision = evaluate_policy("gmail.search", {"query": "invoice", "max_results": "5"})
    assert decision.status == "denied"
    assert decision.error_code == "invalid_params"


def test_gmail_search_max_results_bool_denied():
    """bool is a subclass of int in Python -- must not silently pass."""
    decision = evaluate_policy("gmail.search", {"query": "invoice", "max_results": True})
    assert decision.status == "denied"


@pytest.mark.parametrize("days", [0, -5, 366, 1000])
def test_gmail_search_newer_than_days_out_of_bounds_denied(days):
    decision = evaluate_policy("gmail.search", {"query": "invoice", "newer_than_days": days})
    assert decision.status == "denied"


@pytest.mark.parametrize("days", [1, 30, 365])
def test_gmail_search_newer_than_days_in_bounds_allowed(days):
    decision = evaluate_policy("gmail.search", {"query": "invoice", "newer_than_days": days})
    assert decision.status == "allowed"
    assert decision.params.newer_than_days == days


@pytest.mark.parametrize(
    "query",
    [
        "what's my otp",
        "find the verification code",
        "password reset email",
        "any 2fa codes",
        "security alert from bank",
        "my credit card statement",
        "CREDIT CARD",  # case-insensitive
    ],
)
def test_sensitive_queries_refused(query):
    decision = evaluate_policy("gmail.search", {"query": query})
    assert decision.status == "denied"
    assert decision.error_code == "sensitive_query_refused"


def test_non_sensitive_query_allowed():
    decision = evaluate_policy("gmail.search", {"query": "dinner reservation confirmation"})
    assert decision.status == "allowed"


@pytest.mark.parametrize("verb", ["drive.search", "contacts.search"])
def test_recognized_but_unimplemented_verbs(verb):
    decision = evaluate_policy(verb, {})
    assert decision.status == "not_implemented"
    assert decision.error_code == "not_implemented"


def test_calendar_list_events_allowed_with_defaults():
    decision = evaluate_policy("calendar.list_events", {})
    assert decision.status == "allowed"
    assert decision.params == CalendarListEventsParams(day_offset=0, days=1, max_results=10)


def test_calendar_list_events_today_and_tomorrow():
    today = evaluate_policy("calendar.list_events", {"day_offset": 0})
    tomorrow = evaluate_policy("calendar.list_events", {"day_offset": 1})
    assert today.status == "allowed" and today.params.day_offset == 0
    assert tomorrow.status == "allowed" and tomorrow.params.day_offset == 1


@pytest.mark.parametrize("day_offset", [-1, -5, 14, 100])
def test_calendar_day_offset_out_of_bounds_denied(day_offset):
    decision = evaluate_policy("calendar.list_events", {"day_offset": day_offset})
    assert decision.status == "denied"
    assert decision.error_code == "invalid_params"


@pytest.mark.parametrize("day_offset", [0, 13])
def test_calendar_day_offset_boundary_values_allowed(day_offset):
    decision = evaluate_policy("calendar.list_events", {"day_offset": day_offset})
    assert decision.status == "allowed"


def test_calendar_day_offset_wrong_type_denied():
    decision = evaluate_policy("calendar.list_events", {"day_offset": "1"})
    assert decision.status == "denied"


def test_calendar_day_offset_bool_denied():
    decision = evaluate_policy("calendar.list_events", {"day_offset": True})
    assert decision.status == "denied"


@pytest.mark.parametrize("days", [0, -1, 8, 30])
def test_calendar_days_out_of_bounds_denied(days):
    decision = evaluate_policy("calendar.list_events", {"days": days})
    assert decision.status == "denied"
    assert decision.error_code == "invalid_params"


@pytest.mark.parametrize("days", [1, 7])
def test_calendar_days_boundary_values_allowed(days):
    decision = evaluate_policy("calendar.list_events", {"days": days})
    assert decision.status == "allowed"
    assert decision.params.days == days


@pytest.mark.parametrize("max_results", [0, -1, 26, 100])
def test_calendar_max_results_out_of_bounds_denied(max_results):
    decision = evaluate_policy("calendar.list_events", {"max_results": max_results})
    assert decision.status == "denied"
    assert decision.error_code == "invalid_params"


@pytest.mark.parametrize("max_results", [1, 25])
def test_calendar_max_results_boundary_values_allowed(max_results):
    decision = evaluate_policy("calendar.list_events", {"max_results": max_results})
    assert decision.status == "allowed"
    assert decision.params.max_results == max_results


def test_calendar_params_has_no_recipient_or_date_string_field():
    """Same structural guarantee as GmailSearchParams: no field could
    ever carry a recipient, verb override, or a literal date/timestamp
    string an injected instruction might try to plant."""
    field_names = {f.name for f in dataclasses.fields(CalendarListEventsParams)}
    assert field_names == {"day_offset", "days", "max_results"}


def test_calendar_extra_params_keys_are_ignored_not_propagated():
    decision = evaluate_policy(
        "calendar.list_events",
        {"day_offset": 1, "to": "attacker@evil.com", "verb": "calendar.delete_event"},
    )
    assert decision.status == "allowed"
    assert not hasattr(decision.params, "to")
    assert not hasattr(decision.params, "verb")


def test_unknown_verb_is_unsupported():
    decision = evaluate_policy("gmail.send_all_mail_to_evil", {})
    assert decision.status == "unsupported"
    assert decision.error_code == "unknown_verb"


def test_explicit_unsupported_verb():
    decision = evaluate_policy("unsupported", {})
    assert decision.status == "unsupported"
    assert decision.verb == Verb.UNSUPPORTED


def test_gmail_search_params_has_no_recipient_style_field():
    """Structural guarantee behind the injection test in
    tests/test_pipeline_injection.py: there is no field ANYWHERE in the
    allowed-params shape that could carry a recipient, verb override, or
    similar -- an injected 'to'/'cc'/'verb' key in the raw params dict
    has nowhere to land."""
    field_names = {f.name for f in dataclasses.fields(GmailSearchParams)}
    assert field_names == {"query", "max_results", "newer_than_days"}


def test_extra_params_keys_are_ignored_not_propagated():
    """An injected extra key (e.g. 'to', mirroring the brief's own
    example threat) is simply never read -- deny-by-default via
    allowlisted field extraction, not by pattern-matching the key name."""
    decision = evaluate_policy(
        "gmail.search",
        {"query": "invoice", "to": "attacker@evil.com", "verb": "gmail.send"},
    )
    assert decision.status == "allowed"
    assert not hasattr(decision.params, "to")
    assert not hasattr(decision.params, "verb")


# ── gmail.create_draft ──────────────────────────────────────────────────


def test_gmail_create_draft_allowed():
    decision = evaluate_policy("gmail.create_draft", {"to": "alice@example.com", "subject": "Hi", "body": "Hello there"})
    assert decision.status == "allowed"
    assert decision.params == GmailCreateDraftParams(to="alice@example.com", subject="Hi", body="Hello there")


@pytest.mark.parametrize("missing", ["to", "subject", "body"])
def test_gmail_create_draft_missing_required_field_denied(missing):
    params = {"to": "alice@example.com", "subject": "Hi", "body": "Hello there"}
    del params[missing]
    decision = evaluate_policy("gmail.create_draft", params)
    assert decision.status == "denied"
    assert decision.error_code == "invalid_params"


@pytest.mark.parametrize(
    "bad_to", ["not-an-email", "alice@", "@example.com", "alice example.com", "alice@example", ""]
)
def test_gmail_create_draft_invalid_email_denied(bad_to):
    decision = evaluate_policy("gmail.create_draft", {"to": bad_to, "subject": "Hi", "body": "Hello"})
    assert decision.status == "denied"
    assert decision.error_code == "invalid_params"


def test_gmail_create_draft_subject_too_long_denied():
    decision = evaluate_policy("gmail.create_draft", {"to": "a@example.com", "subject": "x" * 201, "body": "hi"})
    assert decision.status == "denied"


def test_gmail_create_draft_body_too_long_denied():
    decision = evaluate_policy("gmail.create_draft", {"to": "a@example.com", "subject": "hi", "body": "x" * 5001})
    assert decision.status == "denied"


def test_gmail_create_draft_no_recipient_allowlist_by_design():
    """Owner's explicit choice (CLAUDE.md): gmail.create_draft only ever
    creates a DRAFT the owner reviews before sending, so any well-formed
    email address is accepted -- there is no allowlist gate here."""
    decision = evaluate_policy("gmail.create_draft", {"to": "anyone-at-all@example.org", "subject": "hi", "body": "hi"})
    assert decision.status == "allowed"


# ── calendar.create_event ───────────────────────────────────────────────


def test_calendar_create_event_allowed():
    decision = evaluate_policy(
        "calendar.create_event",
        {"title": "Coffee", "day_offset": 2, "start_time": "14:30", "duration_minutes": 30, "attendees": ["a@b.com"]},
    )
    assert decision.status == "allowed"
    assert decision.params == CalendarCreateEventParams(
        title="Coffee", day_offset=2, start_time="14:30", duration_minutes=30, attendees=("a@b.com",)
    )


def test_calendar_create_event_defaults_to_no_attendees():
    decision = evaluate_policy(
        "calendar.create_event", {"title": "Focus block", "day_offset": 0, "start_time": "09:00", "duration_minutes": 60}
    )
    assert decision.status == "allowed"
    assert decision.params.attendees == ()


@pytest.mark.parametrize("missing", ["title", "day_offset", "start_time", "duration_minutes"])
def test_calendar_create_event_missing_required_field_denied(missing):
    params = {"title": "Coffee", "day_offset": 1, "start_time": "10:00", "duration_minutes": 30}
    del params[missing]
    decision = evaluate_policy("calendar.create_event", params)
    assert decision.status == "denied"
    assert decision.error_code == "invalid_params"


@pytest.mark.parametrize("day_offset", [-1, 366])
def test_calendar_create_event_day_offset_out_of_bounds_denied(day_offset):
    decision = evaluate_policy(
        "calendar.create_event",
        {"title": "x", "day_offset": day_offset, "start_time": "10:00", "duration_minutes": 30},
    )
    assert decision.status == "denied"


@pytest.mark.parametrize("start_time", ["9:00", "24:00", "10:60", "morning", "", "10:00:00"])
def test_calendar_create_event_invalid_start_time_denied(start_time):
    decision = evaluate_policy(
        "calendar.create_event",
        {"title": "x", "day_offset": 0, "start_time": start_time, "duration_minutes": 30},
    )
    assert decision.status == "denied"


@pytest.mark.parametrize("duration", [0, 4, 481, 1000])
def test_calendar_create_event_duration_out_of_bounds_denied(duration):
    decision = evaluate_policy(
        "calendar.create_event", {"title": "x", "day_offset": 0, "start_time": "10:00", "duration_minutes": duration}
    )
    assert decision.status == "denied"


def test_calendar_create_event_too_many_attendees_denied():
    attendees = [f"user{i}@example.com" for i in range(11)]
    decision = evaluate_policy(
        "calendar.create_event",
        {"title": "x", "day_offset": 0, "start_time": "10:00", "duration_minutes": 30, "attendees": attendees},
    )
    assert decision.status == "denied"


def test_calendar_create_event_invalid_attendee_email_denied():
    decision = evaluate_policy(
        "calendar.create_event",
        {"title": "x", "day_offset": 0, "start_time": "10:00", "duration_minutes": 30, "attendees": ["not-an-email"]},
    )
    assert decision.status == "denied"


def test_calendar_create_event_attendees_not_a_list_denied():
    decision = evaluate_policy(
        "calendar.create_event",
        {"title": "x", "day_offset": 0, "start_time": "10:00", "duration_minutes": 30, "attendees": "a@b.com"},
    )
    assert decision.status == "denied"


def test_calendar_create_event_no_attendee_allowlist_by_design():
    """Owner's explicit choice (CLAUDE.md): calendar writes run fully
    autonomously, with no attendee allowlist -- any well-formed address
    the request names can be invited."""
    decision = evaluate_policy(
        "calendar.create_event",
        {"title": "x", "day_offset": 0, "start_time": "10:00", "duration_minutes": 30, "attendees": ["stranger@example.org"]},
    )
    assert decision.status == "allowed"


# ── calendar.update_event ───────────────────────────────────────────────


def test_calendar_update_event_allowed_with_one_field():
    decision = evaluate_policy("calendar.update_event", {"event_id": "ev1", "title": "New title"})
    assert decision.status == "allowed"
    assert decision.params == CalendarUpdateEventParams(event_id="ev1", title="New title")


def test_calendar_update_event_missing_event_id_denied():
    decision = evaluate_policy("calendar.update_event", {"title": "New title"})
    assert decision.status == "denied"
    assert decision.error_code == "invalid_params"


def test_calendar_update_event_no_fields_to_update_denied():
    decision = evaluate_policy("calendar.update_event", {"event_id": "ev1"})
    assert decision.status == "denied"
    assert decision.error_code == "invalid_params"


def test_calendar_update_event_invalid_field_value_denied():
    decision = evaluate_policy("calendar.update_event", {"event_id": "ev1", "start_time": "not-a-time"})
    assert decision.status == "denied"


def test_calendar_update_event_can_update_attendees_only():
    decision = evaluate_policy("calendar.update_event", {"event_id": "ev1", "attendees": ["new@example.com"]})
    assert decision.status == "allowed"
    assert decision.params.attendees == ("new@example.com",)
    assert decision.params.title is None


# ── calendar.delete_event ───────────────────────────────────────────────


def test_calendar_delete_event_allowed():
    decision = evaluate_policy("calendar.delete_event", {"event_id": "ev1"})
    assert decision.status == "allowed"
    assert decision.params == CalendarDeleteEventParams(event_id="ev1")


def test_calendar_delete_event_missing_event_id_denied():
    decision = evaluate_policy("calendar.delete_event", {})
    assert decision.status == "denied"
    assert decision.error_code == "invalid_params"


# ── drive.create_file ───────────────────────────────────────────────────


def test_drive_create_file_allowed():
    decision = evaluate_policy("drive.create_file", {"name": "notes.txt", "content": "hello"})
    assert decision.status == "allowed"
    assert decision.params == DriveCreateFileParams(name="notes.txt", content="hello")


@pytest.mark.parametrize("missing", ["name", "content"])
def test_drive_create_file_missing_required_field_denied(missing):
    params = {"name": "notes.txt", "content": "hello"}
    del params[missing]
    decision = evaluate_policy("drive.create_file", params)
    assert decision.status == "denied"
    assert decision.error_code == "invalid_params"


def test_drive_create_file_name_too_long_denied():
    decision = evaluate_policy("drive.create_file", {"name": "x" * 201, "content": "hi"})
    assert decision.status == "denied"


def test_drive_create_file_content_too_long_denied():
    decision = evaluate_policy("drive.create_file", {"name": "x", "content": "y" * 20001})
    assert decision.status == "denied"


def test_drive_create_file_empty_content_is_allowed():
    """Empty content is a legitimate empty file, not a missing field --
    only a missing/non-string 'content' key is denied."""
    decision = evaluate_policy("drive.create_file", {"name": "empty.txt", "content": ""})
    assert decision.status == "allowed"


# ── write verbs are implemented, not just recognized ────────────────────


@pytest.mark.parametrize(
    "verb",
    [
        "gmail.create_draft",
        "calendar.create_event",
        "calendar.update_event",
        "calendar.delete_event",
        "drive.create_file",
    ],
)
def test_write_verbs_are_recognized_as_implemented(verb):
    """These must NOT fall into NOT_IMPLEMENTED_VERBS -- a regression
    there would silently turn a write verb into a no-op 'not_implemented'
    reply instead of denying or executing it."""
    from app.policy import IMPLEMENTED_VERBS, Verb

    assert Verb(verb) in IMPLEMENTED_VERBS
