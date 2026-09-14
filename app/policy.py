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


# The only verb with a real executor in this MVP (research/00 brief,
# "Suggested next phases" step 3: walking skeleton == ONE read-only verb).
IMPLEMENTED_VERBS = frozenset({Verb.GMAIL_SEARCH})
NOT_IMPLEMENTED_VERBS = frozenset(
    {Verb.CALENDAR_LIST_EVENTS, Verb.DRIVE_SEARCH, Verb.CONTACTS_SEARCH}
)

QUERY_MAX_CHARS = 200
MAX_RESULTS_DEFAULT = 5
MAX_RESULTS_MIN = 1
MAX_RESULTS_MAX = 10
NEWER_THAN_DAYS_MIN = 1
NEWER_THAN_DAYS_MAX = 365


@dataclass(frozen=True)
class GmailSearchParams:
    query: str
    max_results: int = MAX_RESULTS_DEFAULT
    newer_than_days: int | None = None


@dataclass(frozen=True)
class PolicyDecision:
    status: str  # "allowed" | "denied" | "not_implemented" | "unsupported"
    verb: Verb
    error_code: str | None = None
    reason: str | None = None
    params: GmailSearchParams | None = None  # set only when status == "allowed"


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
