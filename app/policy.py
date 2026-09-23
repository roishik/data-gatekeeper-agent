"""
policy.py — Layer 3: plain Python, deny-by-default authorization.

This is where "the request passed Layer 0/1/2" becomes "and it's still
only allowed to do this narrow thing" (research/03 section 4). Three rules
hold everywhere in this file:

  1. Deny-by-default. Every code path that doesn't explicitly reach
     status="allowed" denies. There is no catch-all "otherwise allow".
  2. Never coerce. A param that's the wrong type or out of range is a
     DENIAL, never silently clamped or truncated into something that
     would pass. The only exception is the documented default for
     `max_results`, which is a real default (used when the field is
     absent), not a repair of a bad value. A parameter a verb doesn't
     define at all is never read or passed on; whether the request still
     runs is the owner's rule (2026-09-22): yes, with the extras listed
     back in the reply as ignored, if the request passed the injection
     screen (apply_extra_params_gate) -- so a requester never believes a
     field it sent (a timezone, a cc) took effect -- and denied otherwise.
     A few extras whose meaning changed are refused outright
     (_REFUSED_EXTRA_PARAMS).
  3. Single-line fields (addresses, subjects, titles, names, queries)
     never contain a line break or other control character, and
     multi-line fields (a draft body, a file's content) never contain a
     control character other than tab/newline. A newline in a draft
     subject used to crash Python's email library mid-request.

The verb enum is the Action-Selector pattern from research/03 section
2.3 made concrete: a small, closed, versioned set of operations, each
with its own strictly-typed param dataclass. `params` arriving from
Layer 2 is a plain dict that may contain anything (including an injected
"to"/"recipients" key, per the brief's own example threat) -- this layer
reads only the keys a verb defines and constructs a fresh, narrow
dataclass from them. There is no field to put "add a recipient" into:
an extra key never reaches an executor, whatever rule 2 decides about
the rest of the request.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, replace
from enum import Enum
from typing import Any

from app.config import SENSITIVE_QUERY_TERMS


class Verb(str, Enum):
    GMAIL_SEARCH = "gmail.search"
    GMAIL_CREATE_DRAFT = "gmail.create_draft"
    CALENDAR_LIST_EVENTS = "calendar.list_events"
    CALENDAR_CREATE_EVENT = "calendar.create_event"
    CALENDAR_UPDATE_EVENT = "calendar.update_event"
    CALENDAR_DELETE_EVENT = "calendar.delete_event"
    DRIVE_SEARCH = "drive.search"
    DRIVE_CREATE_FILE = "drive.create_file"
    CONTACTS_SEARCH = "contacts.search"
    CAPABILITIES = "capabilities"
    UNSUPPORTED = "unsupported"


NOT_IMPLEMENTED_VERBS = frozenset({Verb.DRIVE_SEARCH, Verb.CONTACTS_SEARCH})

# Batched sub-requests (app/pipeline.py's batch handling), capped so one
# email's worth of work can't push a single request past the Cloud Run
# timeout -- each item can itself trigger a Google API call plus Jev
# screening. Read here by the capabilities verb; enforced in pipeline.py.
BATCH_MAX_ITEMS = 25

QUERY_MAX_CHARS = 200
MAX_RESULTS_DEFAULT = 5
MAX_RESULTS_MIN = 1
MAX_RESULTS_MAX = 30
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

# gmail.create_draft bounds. Deliberately no allowlist on `to` -- the
# owner's explicit choice (CLAUDE.md) is that this verb only ever creates
# a Gmail DRAFT (never sends), so the owner reviewing and manually
# sending it in Gmail is the approval step for an arbitrary recipient.
# Still validated as *shaped like* an email address -- deny-by-default
# never means "accept anything".
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
DRAFT_TO_MAX_CHARS = 254  # RFC 5321 max mailbox length
DRAFT_SUBJECT_MAX_CHARS = 200
# Raised from 5,000 on 2026-09-22 with the payload rail (app/request_parser.py),
# which carries long bodies verbatim without any LLM re-emitting them.
DRAFT_BODY_MAX_CHARS = 20000
# Optional thread_id: a value the requester copied from a prior
# gmail.search reply so a draft can be filed into that conversation. It's
# passed to Gmail's API in a JSON body (never a mail header), but we still
# constrain it to an opaque-token shape -- deny-by-default never means
# "accept anything", and this keeps anything odd out of the API call.
_THREAD_ID_RE = re.compile(r"^[A-Za-z0-9_-]+$")
DRAFT_THREAD_ID_MAX_CHARS = 512

# calendar.create_event / update_event bounds. day_offset/start_time are
# the same "small bounded token, never a real date/timestamp" trick as
# CAL_DAY_OFFSET_* above (app/calendar_window.py does the arithmetic) --
# widened to a year out since a created event can reasonably be far in
# the future, unlike a "what's on my calendar" read window. Also no
# attendee allowlist, by the same explicit owner choice as gmail
# drafts -- but calendar writes run WITHOUT the manual-review step a
# draft gets, since Calendar sends real invites immediately (see
# CLAUDE.md). attendees are still validated as email-shaped and bounded
# in count.
_TIME_RE = re.compile(r"^([01]\d|2[0-3]):([0-5]\d)$")
EVENT_TITLE_MAX_CHARS = 200
# A location is often a full address, room name, or video-call link --
# longer than a title, but still one line (added 2026-09-22, owner's
# request: Instinct couldn't send a meeting location at all before this).
EVENT_LOCATION_MAX_CHARS = 500
EVENT_DAY_OFFSET_MIN = 0
EVENT_DAY_OFFSET_MAX = 365
EVENT_DURATION_MIN_MINUTES = 5
EVENT_DURATION_MAX_MINUTES = 480  # 8 hours
EVENT_ATTENDEES_MAX = 10
EVENT_ID_MAX_CHARS = 1024  # Google's documented maximum
# Google event ids are base32hex (a-v, 0-9); a recurring event's instance
# id appends `_<timestamp>` (e.g. `abc123_20260922T100000Z`). Nothing else
# is ever a valid id, so nothing else is ever passed to the API.
_EVENT_ID_RE = re.compile(r"^[A-Za-z0-9_]+$")

# drive.create_file bounds. Always written into one fixed, app-owned
# folder (GOOGLE_DRIVE_FOLDER_ID, resolved in app/drive_executor.py) --
# there is no `folder` field here for a request to redirect into.
DRIVE_NAME_MAX_CHARS = 200
DRIVE_CONTENT_MAX_CHARS = 100000  # raised from 20,000 with the payload rail (2026-09-22)


@dataclass(frozen=True)
class GmailSearchParams:
    query: str
    max_results: int = MAX_RESULTS_DEFAULT
    newer_than_days: int | None = None


@dataclass(frozen=True)
class GmailCreateDraftParams:
    to: str
    subject: str
    body: str
    thread_id: str | None = None


@dataclass(frozen=True)
class CalendarListEventsParams:
    day_offset: int = CAL_DAY_OFFSET_DEFAULT
    days: int = CAL_DAYS_DEFAULT
    max_results: int = CAL_MAX_RESULTS_DEFAULT


@dataclass(frozen=True)
class CalendarCreateEventParams:
    title: str
    day_offset: int
    start_time: str  # "HH:MM", owner's local time
    duration_minutes: int
    attendees: tuple[str, ...] = ()
    location: str = ""


@dataclass(frozen=True)
class CalendarUpdateEventParams:
    event_id: str
    title: str | None = None
    day_offset: int | None = None
    start_time: str | None = None
    duration_minutes: int | None = None
    # None = leave the location alone; "" = clear it; anything else = set it.
    location: str | None = None
    # Merged into the event's existing guests (app/calendar_executor.py) --
    # there is deliberately no "replace the whole list" field any more.
    add_attendees: tuple[str, ...] = ()
    remove_attendees: tuple[str, ...] = ()


@dataclass(frozen=True)
class CalendarDeleteEventParams:
    event_id: str


@dataclass(frozen=True)
class DriveCreateFileParams:
    name: str
    content: str


@dataclass(frozen=True)
class CapabilitiesParams:
    """No fields: capabilities takes no input, it only reports on this
    service itself. A dataclass anyway, for the same reason every other
    verb gets one -- PolicyDecision.params stays a closed union, and
    app/pipeline.py's executor dispatch stays isinstance()-based."""


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
    params: (
        GmailSearchParams
        | GmailCreateDraftParams
        | CalendarListEventsParams
        | CalendarCreateEventParams
        | CalendarUpdateEventParams
        | CalendarDeleteEventParams
        | DriveCreateFileParams
        | CapabilitiesParams
        | None
    ) = None
    # Extra parameters this verb doesn't define, which were NOT read or
    # passed on. Only ever set on an allowed decision; the reply lists them
    # so the requester knows they had no effect. See apply_extra_params_gate.
    ignored_params: tuple[str, ...] = ()


# ── Shared validators ─────────────────────────────────────────────────────

_SINGLE_LINE_FORBIDDEN_RE = re.compile(r"[\x00-\x1f\x7f\u0085\u2028\u2029]")
_MULTI_LINE_FORBIDDEN_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _is_single_line(value: str) -> bool:
    return not _SINGLE_LINE_FORBIDDEN_RE.search(value)


def _is_clean_multi_line(value: str) -> bool:
    return not _MULTI_LINE_FORBIDDEN_RE.search(value)


def _is_email(value: str) -> bool:
    return bool(_EMAIL_RE.match(value)) and _is_single_line(value)


@dataclass(frozen=True)
class VerbSpec:
    """One place to register a verb's param names, whether it's a write,
    and its bounds -- instead of three hand-maintained tables that could
    silently drift apart (a prior review flagged WRITE_VERBS as exactly
    this risk: a future verb added to VERB_PARAMS but forgotten here
    would fail OPEN on the injection-screen write gate, apply_screen_gate
    below). IMPLEMENTED_VERBS/VERB_PARAMS/WRITE_VERBS are now all derived
    from this registry; nothing else builds them by hand. `param_bounds`
    is a short, human-readable description per param (referencing the
    real constants above, not re-stating their values), used only by the
    `capabilities` verb (app/capabilities.py) to describe this service to
    Instinct -- it has no effect on validation, which still happens in
    each verb's own _evaluate_* function below."""

    verb: Verb
    param_names: frozenset[str]
    is_write: bool
    param_bounds: tuple[str, ...] = ()


VERB_SPECS: dict[Verb, VerbSpec] = {
    Verb.GMAIL_SEARCH: VerbSpec(
        verb=Verb.GMAIL_SEARCH,
        param_names=frozenset({"query", "max_results", "newer_than_days"}),
        is_write=False,
        param_bounds=(
            f"query: string, required, max {QUERY_MAX_CHARS} chars",
            f"max_results: int, {MAX_RESULTS_MIN}-{MAX_RESULTS_MAX}, default {MAX_RESULTS_DEFAULT}",
            f"newer_than_days: int, {NEWER_THAN_DAYS_MIN}-{NEWER_THAN_DAYS_MAX}, optional",
        ),
    ),
    Verb.GMAIL_CREATE_DRAFT: VerbSpec(
        verb=Verb.GMAIL_CREATE_DRAFT,
        param_names=frozenset({"to", "subject", "body", "thread_id"}),
        is_write=True,
        param_bounds=(
            f"to: string, required, valid email, max {DRAFT_TO_MAX_CHARS} chars",
            f"subject: string, required, max {DRAFT_SUBJECT_MAX_CHARS} chars",
            f"body: string, required, max {DRAFT_BODY_MAX_CHARS} chars (use the payload rail for long bodies)",
            "thread_id: string, optional, from a prior gmail.search reply's thread_id",
        ),
    ),
    Verb.CALENDAR_LIST_EVENTS: VerbSpec(
        verb=Verb.CALENDAR_LIST_EVENTS,
        param_names=frozenset({"day_offset", "days", "max_results"}),
        is_write=False,
        param_bounds=(
            f"day_offset: int, {CAL_DAY_OFFSET_MIN}-{CAL_DAY_OFFSET_MAX}, default {CAL_DAY_OFFSET_DEFAULT}",
            f"days: int, {CAL_DAYS_MIN}-{CAL_DAYS_MAX}, default {CAL_DAYS_DEFAULT}",
            f"max_results: int, {CAL_MAX_RESULTS_MIN}-{CAL_MAX_RESULTS_MAX}, default {CAL_MAX_RESULTS_DEFAULT}",
        ),
    ),
    Verb.CALENDAR_CREATE_EVENT: VerbSpec(
        verb=Verb.CALENDAR_CREATE_EVENT,
        param_names=frozenset({"title", "day_offset", "start_time", "duration_minutes", "attendees", "location"}),
        is_write=True,
        param_bounds=(
            f"title: string, required, max {EVENT_TITLE_MAX_CHARS} chars",
            f"day_offset: int, {EVENT_DAY_OFFSET_MIN}-{EVENT_DAY_OFFSET_MAX}, required",
            "start_time: string 'HH:MM', required, owner's local time",
            f"duration_minutes: int, {EVENT_DURATION_MIN_MINUTES}-{EVENT_DURATION_MAX_MINUTES}, required",
            f"attendees: list of email strings, up to {EVENT_ATTENDEES_MAX}, optional",
            f"location: string, max {EVENT_LOCATION_MAX_CHARS} chars, optional",
        ),
    ),
    Verb.CALENDAR_UPDATE_EVENT: VerbSpec(
        verb=Verb.CALENDAR_UPDATE_EVENT,
        param_names=frozenset({
            "event_id", "title", "day_offset", "start_time", "duration_minutes",
            "location", "add_attendees", "remove_attendees",
        }),
        is_write=True,
        param_bounds=(
            f"event_id: string, required, max {EVENT_ID_MAX_CHARS} chars",
            f"title: string, optional, max {EVENT_TITLE_MAX_CHARS} chars",
            f"day_offset: int, {EVENT_DAY_OFFSET_MIN}-{EVENT_DAY_OFFSET_MAX}, optional",
            "start_time: string 'HH:MM', optional",
            f"duration_minutes: int, {EVENT_DURATION_MIN_MINUTES}-{EVENT_DURATION_MAX_MINUTES}, optional",
            f"location: string, max {EVENT_LOCATION_MAX_CHARS} chars, optional (\"\" clears it, omitted leaves it alone)",
            f"add_attendees: list of email strings, optional, event total capped at {EVENT_ATTENDEES_MAX}",
            "remove_attendees: list of email strings, optional",
        ),
    ),
    Verb.CALENDAR_DELETE_EVENT: VerbSpec(
        verb=Verb.CALENDAR_DELETE_EVENT,
        param_names=frozenset({"event_id"}),
        is_write=True,
        param_bounds=(f"event_id: string, required, max {EVENT_ID_MAX_CHARS} chars",),
    ),
    Verb.DRIVE_CREATE_FILE: VerbSpec(
        verb=Verb.DRIVE_CREATE_FILE,
        param_names=frozenset({"name", "content"}),
        is_write=True,
        param_bounds=(
            f"name: string, required, max {DRIVE_NAME_MAX_CHARS} chars",
            f"content: string, required, max {DRIVE_CONTENT_MAX_CHARS} chars (use the payload rail for long content)",
        ),
    ),
    Verb.CAPABILITIES: VerbSpec(
        verb=Verb.CAPABILITIES,
        param_names=frozenset(),
        is_write=False,
        param_bounds=(),
    ),
}

# research/00 brief, "Suggested next phases" step 3 started the walking
# skeleton with ONE read-only verb; every write verb was added once the
# owner explicitly decided -- see CLAUDE.md -- to give the gatekeeper
# write access: gmail.create_draft only ever creates a Gmail DRAFT, never
# sends (the owner reviews and sends it themselves in Gmail -- that
# manual step is the approval), and the calendar/drive write verbs run
# fully autonomously by the owner's explicit choice, with no
# recipient/attendee allowlist gating them.
IMPLEMENTED_VERBS = frozenset(VERB_SPECS.keys())
# Every parameter each verb defines. Anything else in a request is an
# "extra" parameter: never read, never passed on, and handled centrally in
# evaluate_policy() -- see rule 2 in the module docstring.
VERB_PARAMS: dict[Verb, frozenset[str]] = {verb: spec.param_names for verb, spec in VERB_SPECS.items()}
# Verbs with a side effect outside this service. The injection-screen gate
# (apply_screen_gate) applies to these only.
WRITE_VERBS = frozenset(verb for verb, spec in VERB_SPECS.items() if spec.is_write)
# Extra parameters that are REFUSED instead of ignored, because ignoring
# them would silently do something different from what was asked: the old
# `attendees` on update_event meant "replace the guest list", so a request
# using it clearly wants a guest change that ignoring it would not make.
_REFUSED_EXTRA_PARAMS: dict[Verb, dict[str, str]] = {
    Verb.CALENDAR_UPDATE_EVENT: {
        "attendees": "'attendees' is not accepted here: guests are changed with add_attendees / "
                     "remove_attendees (there is no field that replaces the whole list)",
    },
}
_IGNORED_PARAMS_MAX = 20
_IGNORED_PARAM_NAME_MAX_CHARS = 64


def _deny(verb: "Verb", reason: str) -> "PolicyDecision":
    return PolicyDecision(status="denied", verb=verb, error_code="invalid_params", reason=reason)


def _contains_sensitive_term(query: str) -> str | None:
    lowered = query.lower()
    for term in SENSITIVE_QUERY_TERMS:
        if term.lower() in lowered:
            return term
    return None


def apply_screen_gate(decision: PolicyDecision, injection_score: float | None, threshold: float | None) -> PolicyDecision:
    """The block-path injection gate (owner's decision, 2026-09-22): an
    ALLOWED write verb is denied when the request's injection score (subject
    + request block -- app/injection_screen.py) is at or above the
    threshold. Reads are never gated here: they stay log-only, and
    everything they return is screened on the way out (app/output_screen.py).

    This only ever adds a denial on top of a decision that was already
    allowed -- it can never allow anything. And "no signal" (a None score:
    screen off, or TypeSafe unreachable) never denies, so TypeSafe's
    availability can't become a denial-of-service against real requests."""
    if decision.status != "allowed" or decision.verb not in WRITE_VERBS:
        return decision
    if injection_score is None or threshold is None or injection_score < threshold:
        return decision
    return PolicyDecision(
        status="denied", verb=decision.verb, error_code="screened",
        reason="request content was flagged as a likely prompt-injection attempt",
    )


def apply_extra_params_gate(decision: PolicyDecision, injection_score: float | None, threshold: float | None) -> PolicyDecision:
    """Extra parameters are tolerated -- ignored, and listed in the reply --
    only when the request PASSED the injection screen: a request score
    below the threshold (owner's decision, 2026-09-22: a new kind of
    request should still get a useful answer). A score at/above the
    threshold, or no score at all (TypeSafe unreachable or not
    configured), denies a request that carries extras. This gate can only
    add a denial; it never allows anything."""
    if decision.status != "allowed" or not decision.ignored_params:
        return decision
    if injection_score is not None and threshold is not None and injection_score < threshold:
        return decision
    return PolicyDecision(
        status="denied", verb=decision.verb, error_code="invalid_params",
        reason=(
            f"unexpected parameter(s): {', '.join(decision.ignored_params)} -- extra parameters are only "
            "accepted when the request passes the injection screen"
        ),
    )


def parse_error_decision(verb_raw: str, error_code: str, reason: str | None) -> PolicyDecision:
    """Layer 2 couldn't turn the email into a verb + params at all (a
    broken or ambiguous block, a bad payload, plain text too long to
    extract -- see app/request_parser.py). That's a denial like any other,
    decided here so every denial still comes out of Layer 3."""
    try:
        verb = Verb(verb_raw)
    except ValueError:
        verb = Verb.UNSUPPORTED
    return PolicyDecision(status="denied", verb=verb, error_code=error_code, reason=reason)


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

    refused = _REFUSED_EXTRA_PARAMS.get(verb, {})
    for key in params:
        if key in refused:
            return PolicyDecision(status="denied", verb=verb, error_code="invalid_params", reason=refused[key])
    allowed_keys = VERB_PARAMS.get(verb, frozenset())
    extras = tuple(sorted(str(key)[:_IGNORED_PARAM_NAME_MAX_CHARS] for key in params if key not in allowed_keys))
    decision = _evaluate_known_params(verb, {k: v for k, v in params.items() if k in allowed_keys})
    if extras and decision.status == "allowed":
        decision = replace(decision, ignored_params=extras[:_IGNORED_PARAMS_MAX])
    return decision


def _evaluate_known_params(verb: Verb, params: dict[str, Any]) -> PolicyDecision:
    if verb == Verb.GMAIL_SEARCH:
        return _evaluate_gmail_search(params)

    if verb == Verb.GMAIL_CREATE_DRAFT:
        return _evaluate_gmail_create_draft(params)

    if verb == Verb.CALENDAR_LIST_EVENTS:
        return _evaluate_calendar_list_events(params)

    if verb == Verb.CALENDAR_CREATE_EVENT:
        return _evaluate_calendar_create_event(params)

    if verb == Verb.CALENDAR_UPDATE_EVENT:
        return _evaluate_calendar_update_event(params)

    if verb == Verb.CALENDAR_DELETE_EVENT:
        return _evaluate_calendar_delete_event(params)

    if verb == Verb.DRIVE_CREATE_FILE:
        return _evaluate_drive_create_file(params)

    if verb == Verb.CAPABILITIES:
        return PolicyDecision(status="allowed", verb=verb, params=CapabilitiesParams())

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
    if not _is_single_line(query):
        return _deny(verb, "'query' must be a single line with no control characters")
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


def _evaluate_gmail_create_draft(params: dict[str, Any]) -> PolicyDecision:
    verb = Verb.GMAIL_CREATE_DRAFT


    to = params.get("to")
    if not isinstance(to, str) or not to.strip():
        return PolicyDecision(status="denied", verb=verb, error_code="invalid_params", reason="'to' is required and must be a non-empty string")
    if not _is_single_line(to):
        return _deny(verb, "'to' must be a single line with no control characters")
    to = to.strip()
    if len(to) > DRAFT_TO_MAX_CHARS or not _is_email(to):
        return PolicyDecision(status="denied", verb=verb, error_code="invalid_params", reason="'to' must be a valid email address")

    subject = params.get("subject")
    if not isinstance(subject, str) or not subject.strip():
        return PolicyDecision(status="denied", verb=verb, error_code="invalid_params", reason="'subject' is required and must be a non-empty string")
    if len(subject) > DRAFT_SUBJECT_MAX_CHARS:
        return PolicyDecision(
            status="denied", verb=verb, error_code="invalid_params",
            reason=f"'subject' exceeds {DRAFT_SUBJECT_MAX_CHARS} characters",
        )
    if not _is_single_line(subject):
        return _deny(verb, "'subject' must be a single line with no control characters")

    body = params.get("body")
    if not isinstance(body, str) or not body.strip():
        return PolicyDecision(status="denied", verb=verb, error_code="invalid_params", reason="'body' is required and must be a non-empty string")
    if len(body) > DRAFT_BODY_MAX_CHARS:
        return PolicyDecision(
            status="denied", verb=verb, error_code="invalid_params",
            reason=f"'body' exceeds {DRAFT_BODY_MAX_CHARS} characters",
        )
    if not _is_clean_multi_line(body):
        return _deny(verb, "'body' may not contain control characters other than tab and newline")

    # Optional: file the draft into an existing thread (reply-in-thread).
    # Absent -> a new-email draft, exactly as before.
    thread_id_raw = params.get("thread_id")
    thread_id: str | None = None
    if thread_id_raw is not None:
        if not isinstance(thread_id_raw, str) or not thread_id_raw.strip():
            return PolicyDecision(status="denied", verb=verb, error_code="invalid_params", reason="'thread_id' must be a non-empty string when given")
        thread_id = thread_id_raw.strip()
        if len(thread_id) > DRAFT_THREAD_ID_MAX_CHARS or not _THREAD_ID_RE.match(thread_id):
            return PolicyDecision(status="denied", verb=verb, error_code="invalid_params", reason="'thread_id' is not a valid thread id")

    return PolicyDecision(
        status="allowed", verb=verb, params=GmailCreateDraftParams(to=to, subject=subject, body=body, thread_id=thread_id)
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


# ── Shared field validators for calendar.create_event/update_event ─────────
# Each returns (value, error_reason); error_reason is None iff value is
# usable. Factored out because create_event (all fields required) and
# update_event (all fields optional, but validated the same way when
# present) would otherwise duplicate every bound check twice.


def _validate_title(value: Any) -> tuple[str | None, str | None]:
    if not isinstance(value, str) or not value.strip():
        return None, "'title' is required and must be a non-empty string"
    if len(value) > EVENT_TITLE_MAX_CHARS:
        return None, f"'title' exceeds {EVENT_TITLE_MAX_CHARS} characters"
    if not _is_single_line(value):
        return None, "'title' must be a single line with no control characters"
    return value.strip(), None


def _validate_day_offset(value: Any) -> tuple[int | None, str | None]:
    if not isinstance(value, int) or isinstance(value, bool):
        return None, "'day_offset' must be an integer"
    if not (EVENT_DAY_OFFSET_MIN <= value <= EVENT_DAY_OFFSET_MAX):
        return None, f"'day_offset' must be between {EVENT_DAY_OFFSET_MIN} and {EVENT_DAY_OFFSET_MAX}"
    return value, None


def _validate_start_time(value: Any) -> tuple[str | None, str | None]:
    if not isinstance(value, str) or not _TIME_RE.match(value):
        return None, "'start_time' must be an 'HH:MM' string"
    return value, None


def _validate_duration(value: Any) -> tuple[int | None, str | None]:
    if not isinstance(value, int) or isinstance(value, bool):
        return None, "'duration_minutes' must be an integer"
    if not (EVENT_DURATION_MIN_MINUTES <= value <= EVENT_DURATION_MAX_MINUTES):
        return None, f"'duration_minutes' must be between {EVENT_DURATION_MIN_MINUTES} and {EVENT_DURATION_MAX_MINUTES}"
    return value, None


def _validate_attendees(value: Any) -> tuple[tuple[str, ...] | None, str | None]:
    if not isinstance(value, list):
        return None, "'attendees' must be a list of email addresses"
    if len(value) > EVENT_ATTENDEES_MAX:
        return None, f"'attendees' exceeds {EVENT_ATTENDEES_MAX} entries"
    cleaned: list[str] = []
    for entry in value:
        # Control characters are checked on the RAW value, before strip():
        # rule 3 is about what was sent, not what's left after cleanup.
        if not isinstance(entry, str) or not _is_single_line(entry) or not _is_email(entry.strip()):
            return None, f"'attendees' contains a value that is not a valid email address: {entry!r}"
        cleaned.append(entry.strip())
    return tuple(cleaned), None


def _validate_location(value: Any) -> tuple[str | None, str | None]:
    """Unlike title, an empty string is valid here: it means "no location"
    on create, and "clear the location" on update. Reaches real attendees
    verbatim via the Calendar invite once written (not through
    app/reply_guard.py's redaction, which only applies to what THIS
    service tells Instinct) -- app/pipeline.py's invite guard screens it
    the same way it screens the title before any invite goes out."""
    if not isinstance(value, str):
        return None, "'location' must be a string"
    if len(value) > EVENT_LOCATION_MAX_CHARS:
        return None, f"'location' exceeds {EVENT_LOCATION_MAX_CHARS} characters"
    if not _is_single_line(value):
        return None, "'location' must be a single line with no control characters"
    return value.strip(), None


def _validate_event_id(value: Any) -> tuple[str | None, str | None]:
    if not isinstance(value, str) or not value.strip():
        return None, "'event_id' is required and must be a non-empty string"
    if len(value) > EVENT_ID_MAX_CHARS:
        return None, f"'event_id' exceeds {EVENT_ID_MAX_CHARS} characters"
    if not _EVENT_ID_RE.match(value.strip()):
        return None, "'event_id' is not a valid event id"
    return value.strip(), None


def _evaluate_calendar_create_event(params: dict[str, Any]) -> PolicyDecision:
    verb = Verb.CALENDAR_CREATE_EVENT


    title, err = _validate_title(params.get("title"))
    if err:
        return PolicyDecision(status="denied", verb=verb, error_code="invalid_params", reason=err)

    day_offset, err = _validate_day_offset(params.get("day_offset"))
    if err:
        return PolicyDecision(status="denied", verb=verb, error_code="invalid_params", reason=err)

    start_time, err = _validate_start_time(params.get("start_time"))
    if err:
        return PolicyDecision(status="denied", verb=verb, error_code="invalid_params", reason=err)

    duration_minutes, err = _validate_duration(params.get("duration_minutes"))
    if err:
        return PolicyDecision(status="denied", verb=verb, error_code="invalid_params", reason=err)

    attendees_raw = params.get("attendees", [])
    attendees, err = _validate_attendees(attendees_raw)
    if err:
        return PolicyDecision(status="denied", verb=verb, error_code="invalid_params", reason=err)

    location, err = _validate_location(params.get("location", ""))
    if err:
        return PolicyDecision(status="denied", verb=verb, error_code="invalid_params", reason=err)

    # Each validator's (value, err) contract guarantees value is not None
    # here; checked explicitly rather than with `assert`, which `python -O`
    # strips -- deny-by-default must not depend on interpreter flags.
    if title is None or day_offset is None or start_time is None or duration_minutes is None or location is None:
        return _deny(verb, "validated value missing")

    return PolicyDecision(
        status="allowed",
        verb=verb,
        params=CalendarCreateEventParams(
            title=title, day_offset=day_offset, start_time=start_time,
            duration_minutes=duration_minutes, attendees=attendees or (), location=location,
        ),
    )


def _evaluate_calendar_update_event(params: dict[str, Any]) -> PolicyDecision:
    verb = Verb.CALENDAR_UPDATE_EVENT


    event_id, err = _validate_event_id(params.get("event_id"))
    if err:
        return PolicyDecision(status="denied", verb=verb, error_code="invalid_params", reason=err)

    updates: dict[str, Any] = {}
    for field_name, validator in (
        ("title", _validate_title),
        ("day_offset", _validate_day_offset),
        ("start_time", _validate_start_time),
        ("duration_minutes", _validate_duration),
        ("location", _validate_location),
    ):
        if field_name not in params:
            continue
        value, err = validator(params[field_name])
        if err:
            return PolicyDecision(status="denied", verb=verb, error_code="invalid_params", reason=err)
        updates[field_name] = value

    for field_name in ("add_attendees", "remove_attendees"):
        if field_name not in params:
            continue
        value, err = _validate_attendees(params[field_name])
        if err:
            return _deny(verb, err.replace("'attendees'", f"'{field_name}'"))
        if value:
            updates[field_name] = value

    both = {a.lower() for a in updates.get("add_attendees", ())} & {a.lower() for a in updates.get("remove_attendees", ())}
    if both:
        return _deny(verb, "an address can't be in both add_attendees and remove_attendees")

    if not updates:
        return PolicyDecision(
            status="denied", verb=verb, error_code="invalid_params",
            reason="at least one of title/day_offset/start_time/duration_minutes/location/add_attendees/remove_attendees must be given",
        )

    if event_id is None:
        return _deny(verb, "validated event_id missing")
    return PolicyDecision(status="allowed", verb=verb, params=CalendarUpdateEventParams(event_id=event_id, **updates))


def _evaluate_calendar_delete_event(params: dict[str, Any]) -> PolicyDecision:
    verb = Verb.CALENDAR_DELETE_EVENT


    event_id, err = _validate_event_id(params.get("event_id"))
    if err:
        return PolicyDecision(status="denied", verb=verb, error_code="invalid_params", reason=err)

    if event_id is None:
        return _deny(verb, "validated event_id missing")
    return PolicyDecision(status="allowed", verb=verb, params=CalendarDeleteEventParams(event_id=event_id))


def _evaluate_drive_create_file(params: dict[str, Any]) -> PolicyDecision:
    verb = Verb.DRIVE_CREATE_FILE


    name = params.get("name")
    if not isinstance(name, str) or not name.strip():
        return PolicyDecision(status="denied", verb=verb, error_code="invalid_params", reason="'name' is required and must be a non-empty string")
    if len(name) > DRIVE_NAME_MAX_CHARS:
        return PolicyDecision(status="denied", verb=verb, error_code="invalid_params", reason=f"'name' exceeds {DRIVE_NAME_MAX_CHARS} characters")
    if not _is_single_line(name):
        return _deny(verb, "'name' must be a single line with no control characters")

    content = params.get("content")
    if not isinstance(content, str):
        return PolicyDecision(status="denied", verb=verb, error_code="invalid_params", reason="'content' is required and must be a string")
    if len(content) > DRIVE_CONTENT_MAX_CHARS:
        return PolicyDecision(
            status="denied", verb=verb, error_code="invalid_params",
            reason=f"'content' exceeds {DRIVE_CONTENT_MAX_CHARS} characters",
        )
    if not _is_clean_multi_line(content):
        return _deny(verb, "'content' may not contain control characters other than tab and newline")

    return PolicyDecision(status="allowed", verb=verb, params=DriveCreateFileParams(name=name.strip(), content=content))
