"""
policy.py — Layer 3: plain Python, deny-by-default authorization.

This is where "the request passed Layer 0/1/2" becomes "and it's still
only allowed to do this narrow thing" (research/03 section 4). Two rules
hold everywhere in this file:

  1. Deny-by-default. Every code path that doesn't explicitly reach
     status="allowed" denies. There is no catch-all "otherwise allow".
  2. Never coerce. A param that's the wrong type, out of range, or
     simply extra is a DENIAL, never silently dropped, clamped, or
     truncated into something that would pass. The only exception is the
     documented default for `max_results`, which is a real default (used
     when the field is absent), not a repair of a bad value.

The verb enum is the Action-Selector pattern from research/03 section
2.3 made concrete: a small, closed, versioned set of operations, each
with its own strictly-typed param dataclass. `params` arriving from
Layer 2 is a plain dict that may contain anything (including an injected
"to"/"recipients" key, per the brief's own example threat) -- this layer
only ever reads the handful of keys a given verb defines and constructs
a fresh, narrow dataclass from them. Anything else in the dict is never
looked at again, which is what actually stops "add a recipient" from
working: there is no field to put it in.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

from app.config import SENSITIVE_QUERY_TERMS


class Verb(str, Enum):
    GMAIL_SEARCH = "gmail.search"
    CALENDAR_LIST_EVENTS = "calendar.list_events"
    DRIVE_SEARCH = "drive.search"
    CONTACTS_SEARCH = "contacts.search"
    UNSUPPORTED = "unsupported"


# The verbs with a real executor in this MVP (research/00 brief,
# "Suggested next phases" step 3 started the walking skeleton with ONE
# read-only verb; calendar.list_events is the second).
IMPLEMENTED_VERBS = frozenset({Verb.GMAIL_SEARCH, Verb.CALENDAR_LIST_EVENTS})
NOT_IMPLEMENTED_VERBS = frozenset({Verb.DRIVE_SEARCH, Verb.CONTACTS_SEARCH})

QUERY_MAX_CHARS = 200
MAX_RESULTS_DEFAULT = 5
MAX_RESULTS_MIN = 1
MAX_RESULTS_MAX = 10
NEWER_THAN_DAYS_MIN = 1
NEWER_THAN_DAYS_MAX = 365

# calendar.list_events bounds. Deliberately three small bounded integers
# and NOTHING date-shaped -- see app/calendar_window.py's docstring for
# why: the reader LLM (Layer 2) never has to parse, produce, or reason
# about an actual date or timezone, only pick a small integer, which is
# the "low-capacity output type" principle (research/03 section 2.4)
# applied to a brand-new verb rather than just gmail.search's.
CAL_DAY_OFFSET_DEFAULT = 0  # 0 = today
CAL_DAY_OFFSET_MIN = 0
CAL_DAY_OFFSET_MAX = 13
CAL_DAYS_DEFAULT = 1
CAL_DAYS_MIN = 1
CAL_DAYS_MAX = 7
CAL_MAX_RESULTS_DEFAULT = 10
CAL_MAX_RESULTS_MIN = 1
CAL_MAX_RESULTS_MAX = 25


@dataclass(frozen=True)
class GmailSearchParams:
    query: str
    max_results: int = MAX_RESULTS_DEFAULT
    newer_than_days: int | None = None


@dataclass(frozen=True)
class CalendarListEventsParams:
    day_offset: int = CAL_DAY_OFFSET_DEFAULT
    days: int = CAL_DAYS_DEFAULT
    max_results: int = CAL_MAX_RESULTS_DEFAULT


@dataclass(frozen=True)
class PolicyDecision:
    status: str  # "allowed" | "denied" | "not_implemented" | "unsupported"
    verb: Verb
    error_code: str | None = None
    reason: str | None = None
    # set only when status == "allowed"; exactly one shape per verb, per
    # the same allowlisted-field-extraction principle as GmailSearchParams
    # (see module docstring point 2) -- CalendarListEventsParams has no
    # field a "to"/"recipients"/date-string injection could land in either.
    params: GmailSearchParams | CalendarListEventsParams | None = None


def _contains_sensitive_term(query: str) -> str | None:
    lowered = query.lower()
    for term in SENSITIVE_QUERY_TERMS:
        if term.lower() in lowered:
            return term
    return None


def evaluate_policy(verb_raw: str, params: dict[str, Any]) -> PolicyDecision:
    """Entry point for Layer 3. Re-validates everything from scratch --
    it does not matter whether `verb_raw`/`params` came from the
    deterministic block parser or the quarantined LLM fallback (Layer
    2); both are equally untrusted from this layer's point of view."""
    try:
        verb = Verb(verb_raw)
    except ValueError:
        return PolicyDecision(
            status="unsupported",
            verb=Verb.UNSUPPORTED,
            error_code="unknown_verb",
            reason=f"'{verb_raw}' is not a recognized verb",
        )

    if verb == Verb.UNSUPPORTED:
        return PolicyDecision(
            status="unsupported",
            verb=verb,
            error_code="unsupported",
            reason="request did not resolve to a supported verb",
        )

    if verb in NOT_IMPLEMENTED_VERBS:
        return PolicyDecision(
            status="not_implemented",
            verb=verb,
            error_code="not_implemented",
            reason=f"'{verb.value}' is a recognized verb but has no executor yet",
        )

    if verb == Verb.GMAIL_SEARCH:
        return _evaluate_gmail_search(params)

    if verb == Verb.CALENDAR_LIST_EVENTS:
        return _evaluate_calendar_list_events(params)

    # Unreachable given the enum is exhaustively handled above, but
    # deny-by-default means even an unreachable branch denies rather
    # than falling through to "allowed" by omission.
    return PolicyDecision(status="denied", verb=verb, error_code="policy_denied", reason="no matching policy rule")


def _evaluate_gmail_search(params: dict[str, Any]) -> PolicyDecision:
    verb = Verb.GMAIL_SEARCH

    query = params.get("query")
    if not isinstance(query, str) or not query.strip():
        return PolicyDecision(
            status="denied", verb=verb, error_code="invalid_params",
            reason="'query' is required and must be a non-empty string",
        )
    if len(query) > QUERY_MAX_CHARS:
        return PolicyDecision(
            status="denied", verb=verb, error_code="invalid_params",
            reason=f"'query' exceeds {QUERY_MAX_CHARS} characters",
        )

    sensitive_hit = _contains_sensitive_term(query)
    if sensitive_hit:
        return PolicyDecision(
            status="denied", verb=verb, error_code="sensitive_query_refused",
            reason=f"query matches a refused sensitive category ('{sensitive_hit}')",
        )

    max_results = params.get("max_results", MAX_RESULTS_DEFAULT)
    # bool is a subclass of int in Python -- explicitly excluded so
    # `max_results: true` doesn't silently pass as 1.
    if not isinstance(max_results, int) or isinstance(max_results, bool):
        return PolicyDecision(status="denied", verb=verb, error_code="invalid_params", reason="'max_results' must be an integer")
    if not (MAX_RESULTS_MIN <= max_results <= MAX_RESULTS_MAX):
        return PolicyDecision(
            status="denied", verb=verb, error_code="invalid_params",
            reason=f"'max_results' must be between {MAX_RESULTS_MIN} and {MAX_RESULTS_MAX}",
        )

    newer_than_days_raw = params.get("newer_than_days")
    newer_than_days: int | None = None
    if newer_than_days_raw is not None:
        if not isinstance(newer_than_days_raw, int) or isinstance(newer_than_days_raw, bool):
            return PolicyDecision(status="denied", verb=verb, error_code="invalid_params", reason="'newer_than_days' must be an integer")
        if not (NEWER_THAN_DAYS_MIN <= newer_than_days_raw <= NEWER_THAN_DAYS_MAX):
            return PolicyDecision(
                status="denied", verb=verb, error_code="invalid_params",
                reason=f"'newer_than_days' must be between {NEWER_THAN_DAYS_MIN} and {NEWER_THAN_DAYS_MAX}",
            )
        newer_than_days = newer_than_days_raw

    return PolicyDecision(
        status="allowed",
        verb=verb,
        params=GmailSearchParams(query=query, max_results=max_results, newer_than_days=newer_than_days),
    )


def _evaluate_calendar_list_events(params: dict[str, Any]) -> PolicyDecision:
    verb = Verb.CALENDAR_LIST_EVENTS

    day_offset = params.get("day_offset", CAL_DAY_OFFSET_DEFAULT)
    if not isinstance(day_offset, int) or isinstance(day_offset, bool):
        return PolicyDecision(status="denied", verb=verb, error_code="invalid_params", reason="'day_offset' must be an integer")
    if not (CAL_DAY_OFFSET_MIN <= day_offset <= CAL_DAY_OFFSET_MAX):
        return PolicyDecision(
            status="denied", verb=verb, error_code="invalid_params",
            reason=f"'day_offset' must be between {CAL_DAY_OFFSET_MIN} and {CAL_DAY_OFFSET_MAX}",
        )

    days = params.get("days", CAL_DAYS_DEFAULT)
    if not isinstance(days, int) or isinstance(days, bool):
        return PolicyDecision(status="denied", verb=verb, error_code="invalid_params", reason="'days' must be an integer")
    if not (CAL_DAYS_MIN <= days <= CAL_DAYS_MAX):
        return PolicyDecision(
            status="denied", verb=verb, error_code="invalid_params",
            reason=f"'days' must be between {CAL_DAYS_MIN} and {CAL_DAYS_MAX}",
        )

    max_results = params.get("max_results", CAL_MAX_RESULTS_DEFAULT)
    if not isinstance(max_results, int) or isinstance(max_results, bool):
        return PolicyDecision(status="denied", verb=verb, error_code="invalid_params", reason="'max_results' must be an integer")
    if not (CAL_MAX_RESULTS_MIN <= max_results <= CAL_MAX_RESULTS_MAX):
        return PolicyDecision(
            status="denied", verb=verb, error_code="invalid_params",
            reason=f"'max_results' must be between {CAL_MAX_RESULTS_MIN} and {CAL_MAX_RESULTS_MAX}",
        )

    return PolicyDecision(
        status="allowed",
        verb=verb,
        params=CalendarListEventsParams(day_offset=day_offset, days=days, max_results=max_results),
    )
