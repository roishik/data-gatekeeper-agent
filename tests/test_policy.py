"""Layer 3 tests: deny-by-default, param bounds, and the sensitive-query
refusal list."""
from __future__ import annotations

import dataclasses

import pytest

from app.policy import CalendarListEventsParams, GmailSearchParams, Verb, evaluate_policy


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
