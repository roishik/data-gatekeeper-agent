"""
pipeline.py — wires Layers 0-5 together for a single inbound webhook
event.

app/main.py's FastAPI route does almost nothing itself: it hands the raw
body + headers to `handle_webhook()` below and returns whatever HTTP
status it's told to. Keeping the actual logic here, not in main.py, is
what makes the whole pipeline testable without an HTTP client or any
real credentials -- see tests/test_pipeline_injection.py.

Guarantees, in order of where processing can stop:

  1. An UNSIGNED/forged webhook (bad signature, stale timestamp) is
     rejected, never answered, and logged to Cloud Logging only -- NOT to
     the Sheets audit log. The public endpoint is reachable by anyone, and
     writing a Sheets row per unauthenticated POST made it free to burn the
     Sheets write quota and bloat the tamper-evident log (found 2026-09-19).
  2. A signed event that's rejected at Layer 0 (wrong inbox, sender not on
     the allowlist, own-inbox loop, unrecognized payload) is never answered
     but IS audited: it's real mail, and seeing it is the point.
  3. Anything that fails BEFORE a message is marked seen propagates as a
     5xx, so AgentMail retries it -- nothing has happened yet.
  4. From the moment a message is marked seen, every path -- success, a
     denial, a duplicate, or any exception anywhere in Layers 1-4 -- ends
     in exactly one reply attempt to the verified sender and exactly one
     audit record. An exception becomes `status: error` with a code from
     app/failures.py; a failed reply send is recorded on that same audit
     record (`reply_error`) rather than lost.
  5. A write verb's request status is set to `effect_done` as soon as the
     side effect has happened, BEFORE the reply is attempted, so a resend of
     the same request_id after a failed reply can never repeat the write
     (see app/state_store.py).
  6. Everything Layer 4 returns is screened by app/output_screen.py before
     it's rendered: flagged items go out with their text withheld (ids
     kept), and a calendar write that would send a flagged title to
     attendees is refused before it happens.

`batch` (added 2026-09-23) generalizes guarantee 4 rather than special-
casing around it: app/request_parser.py resolves a `verb: batch` block
entirely at Layer 2 into N ordinary ParsedRequests (never a real Verb the
policy engine knows about), and each one runs independently through
_run_batch/_run_batch_item -- its own dedupe, policy decision,
execution, quota slot, and eventual audit record (tagged with the outer
request's id as `batch_id`). The Sheets bookkeeping for those is done
once per batch, not once per item (see _run_batch: Sheets' write quota). Still exactly ONE reply per webhook: render_batch_reply
(app/reply_guard.py) combines every item's own rendering into one email.
Two things are deliberately NOT per-item, for cost and latency reasons:
inbound injection screening (the whole batch block is screened ONCE,
like any single request's block -- one high score anywhere in it gates
every WRITE item via apply_screen_gate, the safe direction to be
imprecise in) and outbound content screening (every item's output is
screened in ONE combined Jev call, app/output_screen.py's scoped_output
splitting the verdicts back out per item) -- BATCH_MAX_ITEMS (25)
separate Jev calls in one request would risk the Cloud Run timeout.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any, Callable

from app.agentmail_client import AgentMailClient
from app.audit_log import AuditLog, AuditRecord
from app.calendar_executor import CalendarClient, CalendarEvent, CalendarInfo
from app.calendar_window import format_window_range, resolve_window, window_spans_other_years
from app.capabilities import CapabilitiesInfo, build_capabilities_info
from app.config import AGENTMAIL_INBOX_ID, INJECTION_DENY_THRESHOLD, MAX_REQUESTS_PER_DAY, OUTPUT_SCREEN_FAIL_MODE, OWNER_TIMEZONE
from app.drive_executor import DriveClient, DriveFileResult
from app.failures import GatekeeperDenied, classify_failure
from app.gmail_executor import DraftResult, GmailClient, GmailResult
from app.ingress import check_event, parsed_sender_address, verify_signature
from app.injection_screen import InjectionScreen
from app.output_screen import (
    CREATED_EVENT_KEY,
    DRAFT_KEY,
    DRIVE_FILE_KEY,
    INVITE_KEY,
    UPDATED_EVENT_KEY,
    NoOpOutputScreen,
    OutputScreen,
    OutputScreenResult,
    all_withheld,
    calendar_key,
    event_key,
    gmail_key,
    scoped_output,
)
from app.policy import (
    CalendarCreateEventParams,
    CalendarDeleteEventParams,
    CalendarListCalendarsParams,
    CalendarListEventsParams,
    CalendarUpdateEventParams,
    CapabilitiesParams,
    DriveCreateFileParams,
    GmailCreateDraftParams,
    GmailSearchParams,
    PolicyDecision,
    apply_extra_params_gate,
    apply_screen_gate,
    evaluate_policy,
    is_write_verb,
    parse_error_decision,
)
from app.reader_llm import ReaderLLM
from app.reply_guard import BatchItemInput, render_batch_reply, render_minimal_reply, render_reply, send_reply
from app.request_parser import EmailParts, ParsedRequest, fallback_request_id_for, parse_request, split_email
from app.state_store import (
    REQUEST_COMPLETED,
    REQUEST_EFFECT_DONE,
    REQUEST_FAILED,
    REQUEST_PROCESSING,
    is_duplicate_request_status,
)

logger = logging.getLogger("gatekeeper.pipeline")


@dataclass(frozen=True)
class WebhookOutcome:
    http_status: int
    reason: str  # internal only -- app/main.py never echoes it to the caller


@dataclass
class ExecutionResults:
    """What Layer 4 produced. At most one field is populated per request
    (exactly one verb runs), but each is kept separate so one verb's
    result can never be handed to another verb's formatter."""

    gmail_results: list[GmailResult] | None = None
    calendar_results: list[CalendarEvent] | None = None
    calendar_window_label: str | None = None  # calendar.list_events' resolved date range, for the reply prose
    calendar_show_year: bool = False  # the window reaches outside this year: the reply spells years out
    calendars: list[CalendarInfo] | None = None  # calendar.list_calendars
    draft_result: DraftResult | None = None
    created_event: CalendarEvent | None = None
    updated_event: CalendarEvent | None = None
    deleted_event_id: str | None = None
    drive_file_result: DriveFileResult | None = None
    capabilities: CapabilitiesInfo | None = None

    @property
    def wrote(self) -> bool:
        return any((self.draft_result, self.created_event, self.updated_event, self.deleted_event_id, self.drive_file_result))

    def render_kwargs(self) -> dict[str, Any]:
        return {
            "gmail_results": self.gmail_results,
            "calendar_results": self.calendar_results,
            "calendar_window_label": self.calendar_window_label,
            "calendar_show_year": self.calendar_show_year,
            "calendars": self.calendars,
            "draft_result": self.draft_result,
            "created_event": self.created_event,
            "updated_event": self.updated_event,
            "deleted_event_id": self.deleted_event_id,
            "drive_file_result": self.drive_file_result,
            "capabilities": self.capabilities,
        }


@dataclass
class _RequestState:
    """Everything one request accumulates on its way through Layers 1-5,
    so the single reply and the single audit record at the end can be
    built from one place however far processing got."""

    message_id: str
    sender: str
    parsed: ParsedRequest
    layer1: str = "ok"
    injection_score: float | None = None  # the REQUEST score: subject + request block (or body)
    payload_injection_score: float | None = None
    injection_screen_status: str | None = None
    llm_usage: dict[str, int] | None = None
    decision: PolicyDecision | None = None
    results: ExecutionResults = field(default_factory=ExecutionResults)
    reply_status: str = "error"
    error_code: str | None = "internal_error"
    retryable: bool = False
    request_started: bool = False  # set once request status 'processing' was written
    failure_code: str | None = None
    failure_stage: str | None = None
    failure_type: str | None = None
    # Our own reason for an execution-time refusal (a GatekeeperDenied), so a
    # denial the requester can fix -- e.g. an unusable calendar_id -- says what
    # to fix. Only ever shown for the codes reply_guard._EXPLAINED_DENIALS
    # lists; security refusals stay generic there.
    denial_detail: str | None = None
    reply_message_id: str | None = None
    reply_error: str | None = None
    outcome_reason: str = "processed"
    output: OutputScreenResult | None = None
    output_reply_sensitive: float | None = None
    output_reply_injection: float | None = None
    # The sender's daily count as read for the rate-cap check, plus how
    # many slots this webhook then recorded -- enough to report
    # requests_remaining_today without re-reading the daily_counts tab
    # (exact, since app/main.py runs one request at a time on one instance).
    quota_used_before: int | None = None
    quota_consumed: int = 0
    # Populated only for a `batch` request (state.parsed.verb == "batch"):
    # one finished _RequestState per item, run independently through
    # Layers 1(request)-4. `output` above holds the COMBINED (unscoped)
    # output-screen result across every item, for the outer status
    # block's aggregate withheld_count/screen; each item's own `output`
    # is a view scoped to just its keys (app/output_screen.py's
    # scoped_output). See _run_batch/render_batch_reply.
    batch_items: list[_RequestState] | None = None


def extract_message_fields(payload: dict[str, Any]) -> dict[str, Any] | None:
    """Pulls the fields this pipeline needs out of an AgentMail webhook
    JSON body (`event_type` at the top level, fields nested under
    `"message"` -- the shape every live delivery since 2026-09-15 has had).
    A couple of plausible key-name variants (`type` alongside
    `event_type`, `id` alongside `message_id`) are accepted defensively;
    returns None if the payload doesn't look like a message event at all,
    which the caller treats as an ignored (never a trusted) event."""
    if not isinstance(payload, dict):
        return None

    event_type = payload.get("event_type") or payload.get("type")
    message = payload.get("message")
    if not isinstance(message, dict):
        return None

    message_id = message.get("message_id") or message.get("id")
    inbox_id = message.get("inbox_id")
    sender = message.get("from") or message.get("from_")
    subject = message.get("subject") or ""
    text = message.get("text") or message.get("html") or ""

    if not (event_type and message_id and inbox_id and sender):
        return None

    return {
        "event_type": event_type,
        "message_id": message_id,
        "inbox_id": inbox_id,
        "sender": sender,
        "subject": subject,
        "text": text,
    }


def handle_webhook(
    body: bytes,
    svix_id: str,
    svix_timestamp: str,
    svix_signature: str,
    *,
    state_store,
    reader_llm: ReaderLLM,
    injection_screen: InjectionScreen,
    gmail_client_factory: Callable[[], GmailClient],
    calendar_client_factory: Callable[[], CalendarClient],
    drive_client_factory: Callable[[], DriveClient],
    agentmail_client: AgentMailClient,
    audit_log: AuditLog,
    payload: dict[str, Any] | None = None,
    output_screen: OutputScreen | None = None,
) -> WebhookOutcome:
    """The single entry point every caller (app/main.py and every test)
    uses. `payload` lets tests pass a pre-parsed dict instead of
    re-encoding JSON, since `body` is still required (and still checked)
    for signature verification -- the two must be consistent in real
    use, which app/main.py guarantees by parsing `body` itself.

    The client factories are zero-arg callables rather than client
    instances so a (possibly credentialed) client is constructed only on
    the one request path that actually reaches Layer 4 for that verb."""
    # ── Layer 0: authenticity ────────────────────────────────────────────
    sig_verdict = verify_signature(body, svix_id, svix_timestamp, svix_signature)
    if not sig_verdict.accepted:
        # Unauthenticated -- Cloud Logging only, never the Sheets audit log
        # (module docstring, guarantee 1).
        logger.warning("unsigned webhook rejected at layer 0 (not audited): %s", sig_verdict.reason)
        return WebhookOutcome(202, sig_verdict.reason)

    try:
        data = payload if payload is not None else json.loads(body)
    except Exception:
        data = None
    fields = extract_message_fields(data) if isinstance(data, dict) else None
    if fields is None:
        logger.info("webhook rejected at layer 0: unrecognized_payload_shape")
        _append_audit(audit_log, AuditRecord(
            agentmail_message_id="unknown", sender="unknown",
            layer0_verdict="unrecognized_payload_shape", layer1_verdict="not_reached",
        ))
        return WebhookOutcome(202, "unrecognized_payload_shape")

    message_id = fields["message_id"]
    sender_address = parsed_sender_address(fields["sender"])

    event_verdict = check_event(event_type=fields["event_type"], inbox_id=fields["inbox_id"], sender_header=fields["sender"])
    if not event_verdict.accepted:
        logger.info("webhook rejected at layer 0: %s", event_verdict.reason)
        _append_audit(audit_log, AuditRecord(
            agentmail_message_id=message_id, sender=sender_address,
            layer0_verdict=event_verdict.reason, layer1_verdict="not_reached",
        ))
        return WebhookOutcome(202, event_verdict.reason)  # rejected, never answered

    # ── Layer 1: message dedupe ──────────────────────────────────────────
    # Deliberately unguarded: a failure here propagates as a 5xx and
    # AgentMail retries, because nothing has happened yet (guarantee 3).
    if state_store.is_duplicate_message(message_id):
        _append_audit(audit_log, AuditRecord(
            agentmail_message_id=message_id, sender=sender_address,
            layer0_verdict="ok", layer1_verdict="duplicate_message",
        ))
        return WebhookOutcome(200, "duplicate_message")  # that message already got its reply
    state_store.mark_message_seen(message_id)

    # ── From here on: exactly one reply + one audit record (guarantee 4) ─
    output_screen = output_screen or NoOpOutputScreen()
    state = _RequestState(message_id=message_id, sender=sender_address, parsed=_unresolved_request(message_id))
    stage = "layer1"
    try:
        stage = _run_request(
            state, fields,
            state_store=state_store, reader_llm=reader_llm, injection_screen=injection_screen,
            output_screen=output_screen,
            gmail_client_factory=gmail_client_factory, calendar_client_factory=calendar_client_factory,
            drive_client_factory=drive_client_factory,
        )
    except GatekeeperDenied as denied:
        state.reply_status, state.error_code, state.retryable = "denied", denied.error_code, False
        state.denial_detail = denied.reason or None
    except Exception as exc:
        failure = classify_failure(exc)
        stage = getattr(exc, "_gatekeeper_stage", stage)
        logger.exception("request %s failed at %s (%s)", state.parsed.request_id, stage, failure.code)
        state.failure_code, state.failure_stage, state.failure_type = failure.code, stage, failure.type_name
        state.outcome_reason = "failed"
        if state.results.wrote and state.decision is not None:
            # The side effect already happened (the failure came after it,
            # e.g. recording `effect_done`). Report what was done -- an
            # "error, retryable" reply would invite a resend of a write that
            # succeeded. The failure itself is still on the audit record.
            state.reply_status, state.error_code = _status_for_decision(state.decision)
            state.retryable = False
            if state.output is None:
                state.output = _screen_output(output_screen, state.results)
        else:
            state.reply_status, state.error_code, state.retryable = "error", failure.code, failure.retryable

    # ── Layer 5: reply ───────────────────────────────────────────────────
    _send(state, agentmail_client, state_store)
    if state.batch_items is None:
        _append_audit(audit_log, _audit_record(state))
        _finalize_request_statuses([state], state_store)
    else:
        # Each item gets its own final status and its own audit record
        # (batch_id = the outer request_id, for correlation) -- deferred
        # until here, rather than inside _run_batch, so each one reflects
        # whether the ONE combined reply actually reached the requester
        # (reply_error/reply_message_id), exactly like a standalone
        # request's own audit record does. Written as ONE audit append and
        # ONE status append for the whole batch, not one each per item
        # (Sheets' write quota -- see _run_batch).
        for item_state in state.batch_items:
            item_state.reply_error = state.reply_error
            item_state.reply_message_id = state.reply_message_id
        _append_audits(audit_log, [
            _audit_record(state),
            *(_audit_record(item_state, batch_id=state.parsed.request_id) for item_state in state.batch_items),
        ])
        _finalize_request_statuses([state, *state.batch_items], state_store)
    return WebhookOutcome(200, state.outcome_reason)


def _early_return(state: _RequestState, reason: str, error_code: str, *, reply_status: str = "error") -> None:
    """`state.layer1` (the audit record) and `state.outcome_reason` (the
    returned WebhookOutcome) want the same short reason for an early
    return out of _run_request/_run_batch_item -- previously set by hand,
    three near-identical lines, at each call site."""
    state.layer1 = reason
    state.reply_status, state.error_code = reply_status, error_code
    state.outcome_reason = reason


def _run_request(
    state: _RequestState,
    fields: dict[str, Any],
    *,
    state_store,
    reader_llm: ReaderLLM,
    injection_screen: InjectionScreen,
    output_screen: OutputScreen,
    gmail_client_factory: Callable[[], GmailClient],
    calendar_client_factory: Callable[[], CalendarClient],
    drive_client_factory: Callable[[], DriveClient],
) -> str:
    """Layers 1 (cap, request dedupe) through 4, then the output screen. Returns normally for every
    handled outcome -- including denials, duplicates and the rate limit --
    and records the reply to send on `state`. Raises for anything broken;
    handle_webhook turns that into an error reply. Tags any exception with
    the stage it escaped from, for the audit record."""
    stage = "layer1"
    try:
        state.quota_used_before = state_store.count_today(state.sender)
        if state.quota_used_before >= MAX_REQUESTS_PER_DAY:
            _early_return(state, "rate_limited", "rate_limited")
            return stage

        # ── Deterministic split, then the injection screen, part by part
        # (app/injection_screen.py). The subject counts toward the request
        # score: it's just as attacker-influenced as the body (research/03's
        # OpenClaw lesson).
        stage = "layer2"
        parts = split_email(fields["text"])
        stage = "screen"
        screen_parts, request_part_names = _inbound_screen_parts(fields["subject"], parts)
        inbound = injection_screen.screen_parts(screen_parts)
        state.injection_score = inbound.max_of(request_part_names)
        state.payload_injection_score = inbound.max_of([name for name in screen_parts if name.startswith("payload:")])
        state.injection_screen_status = inbound.status

        # ── Layer 2: parse ───────────────────────────────────────────────
        stage = "layer2"
        state.parsed = parse_request(
            fields["text"], state.message_id, reader_llm,
            injection_score=state.injection_score, injection_deny_threshold=INJECTION_DENY_THRESHOLD, parts=parts,
        )
        if state.parsed.source == "llm":
            state.llm_usage = getattr(reader_llm, "last_usage", None)

        # ── Layer 1 (cont.): request dedupe, now that we know the id ─────
        stage = "layer1"
        prior = state_store.get_request_status_detail(state.parsed.request_id)
        prior_status, prior_updated_at = prior if prior is not None else (None, None)
        if is_duplicate_request_status(prior_status, prior_updated_at, write_verb=is_write_verb(state.parsed.verb)):
            _early_return(state, "duplicate_request", "duplicate_request", reply_status="duplicate")
            return stage
        state_store.set_request_status(state.parsed.request_id, REQUEST_PROCESSING, state.sender)
        state.request_started = True

        # `batch` is resolved entirely in app/request_parser.py into N
        # ordinary ParsedRequests (state.parsed.batch_items); each one runs
        # independently through the same Layers 1(request)-4 below, with
        # its own dedupe/policy/execute/audit record and its own quota
        # slot -- the OUTER batch request_id above is deduped and given a
        # final status like any request, but never itself consumes a
        # quota slot (nothing was actually executed under it directly).
        # A problem with the batch ENVELOPE itself (too many items, an
        # empty/missing 'requests' list) sets parse_error with batch_items
        # left empty -- that must fall through to the parse_error_decision
        # branch below like any other malformed request, not be read as
        # "an empty batch that ran successfully".
        if state.parsed.verb == "batch" and not state.parsed.parse_error:
            stage = "layer4"
            state.batch_items, state.output = _run_batch(
                state, state_store=state_store, gmail_client_factory=gmail_client_factory,
                calendar_client_factory=calendar_client_factory, drive_client_factory=drive_client_factory,
                output_screen=output_screen,
            )
            state.reply_status, state.error_code, state.retryable = "completed", None, False
            return stage

        state_store.record_request(state.sender, state.parsed.request_id)
        state.quota_consumed = 1

        # ── Layer 3: policy ──────────────────────────────────────────────
        stage = "layer3"
        if state.parsed.parse_error:
            state.decision = parse_error_decision(state.parsed.verb, state.parsed.parse_error, state.parsed.parse_error_detail)
        else:
            state.decision = evaluate_policy(state.parsed.verb, state.parsed.params)
            state.decision = apply_screen_gate(state.decision, state.injection_score, INJECTION_DENY_THRESHOLD)
            state.decision = apply_extra_params_gate(state.decision, state.injection_score, INJECTION_DENY_THRESHOLD)

        # ── Layer 4: executor ────────────────────────────────────────────
        stage = "layer4"
        state.results = _execute(
            state.decision, state.parsed, gmail_client_factory, calendar_client_factory, drive_client_factory,
            invite_guard=_make_invite_guard(output_screen),
        )
        if state.results.wrote:
            stage = "layer1"
            state_store.set_request_status(state.parsed.request_id, REQUEST_EFFECT_DONE, state.sender)

        # ── Output screen (app/output_screen.py): never raises -- a failure
        # here must not turn a completed write into an error reply.
        stage = "output_screen"
        state.output = _screen_output(output_screen, state.results)

        state.reply_status, state.error_code = _status_for_decision(state.decision)
        state.retryable = False
        return stage
    except Exception as exc:
        exc._gatekeeper_stage = stage  # type: ignore[attr-defined]
        raise


def _inbound_screen_parts(subject: str, parts: EmailParts) -> tuple[dict[str, str], list[str]]:
    """What the injection screen scores, part by part, plus which parts make
    up the request score (the parts that can steer what the gatekeeper
    does). Payload parts are only ever data -- scored and logged, never
    part of the request score."""
    screen: dict[str, str] = {}
    if subject.strip():
        screen["subject"] = subject
    if parts.remainder.strip():
        screen["body"] = parts.remainder
    block_names = ["request_block"] if len(parts.block_texts) == 1 else [f"request_block:{i + 1}" for i in range(len(parts.block_texts))]
    for name, text in zip(block_names, parts.block_texts):
        screen[name] = text
    for name, text in parts.payloads.items():
        screen[f"payload:{name}"] = text
    request_names = ["subject"] + (block_names if parts.block_texts else ["body"])
    return screen, request_names


def _make_invite_guard(output_screen: OutputScreen) -> Callable[[str, str], None]:
    """A calendar event with attendees sends its title AND location to
    third parties the moment it's written, with no human review -- so both
    are screened first, and a flagged (or, failing closed, unscreenable)
    title/location refuses the write. See app/output_screen.py."""

    def guard(title: str, location: str) -> None:
        try:
            result = output_screen.screen_items({INVITE_KEY: {"title": title, "location": location}})
        except Exception:
            logger.exception("invite title/location screen failed")
            result = all_withheld([INVITE_KEY], fail_closed=OUTPUT_SCREEN_FAIL_MODE != "open")
        if result.is_withheld(INVITE_KEY):
            raise GatekeeperDenied(
                "sensitive_content_refused",
                "the event title or location was flagged as sensitive (or could not be screened) and the event has attendees",
            )

    return guard


def _output_items(results: ExecutionResults) -> dict[str, dict[str, str]]:
    items: dict[str, dict[str, str]] = {}
    for i, r in enumerate(results.gmail_results or []):
        items[gmail_key(i)] = {"from": r.sender, "subject": r.subject, "date": r.date, "snippet": r.snippet}
    for i, e in enumerate(results.calendar_results or []):
        items[event_key(i)] = {"title": e.summary, "location": e.location}
    for i, c in enumerate(results.calendars or []):
        items[calendar_key(i)] = {"name": c.name}
    if results.created_event:
        items[CREATED_EVENT_KEY] = {"title": results.created_event.summary, "location": results.created_event.location}
    if results.updated_event:
        items[UPDATED_EVENT_KEY] = {"title": results.updated_event.summary, "location": results.updated_event.location}
    if results.draft_result:
        items[DRAFT_KEY] = {"to": results.draft_result.to, "subject": results.draft_result.subject}
    if results.drive_file_result:
        items[DRIVE_FILE_KEY] = {"name": results.drive_file_result.name}
    return items


def _screen_output(output_screen: OutputScreen, results: ExecutionResults) -> OutputScreenResult | None:
    items = _output_items(results)
    if not items:
        return None
    try:
        return output_screen.screen_items(items)
    except Exception:
        logger.exception("output screen failed; applying fail mode %s", OUTPUT_SCREEN_FAIL_MODE)
        return all_withheld(list(items), fail_closed=OUTPUT_SCREEN_FAIL_MODE != "open")


def _execute(
    decision: PolicyDecision,
    parsed: ParsedRequest,
    gmail_client_factory: Callable[[], GmailClient],
    calendar_client_factory: Callable[[], CalendarClient],
    drive_client_factory: Callable[[], DriveClient],
    *,
    invite_guard: Callable[[str, str], None],
) -> ExecutionResults:
    """Layer 4: only for an allowed verb -- exactly one verb, read or
    write, runs per request."""
    results = ExecutionResults()
    if decision.status != "allowed":
        return results
    params = decision.params
    if isinstance(params, GmailSearchParams):
        results.gmail_results = gmail_client_factory().search(
            query=params.query, max_results=params.max_results, newer_than_days=params.newer_than_days,
        )
    elif isinstance(params, GmailCreateDraftParams):
        results.draft_result = gmail_client_factory().create_draft(
            to=params.to, subject=params.subject, body=params.body, thread_id=params.thread_id,
        )
    elif isinstance(params, CalendarListCalendarsParams):
        results.calendars = calendar_client_factory().list_calendars()
    elif isinstance(params, CalendarListEventsParams):
        window = resolve_window(params.day_offset, params.days, OWNER_TIMEZONE)
        results.calendar_results = calendar_client_factory().list_events(
            time_min=window.time_min, time_max=window.time_max, max_results=params.max_results,
            calendar_id=params.calendar_id, query=params.query,
        )
        # A window in the past, or a wide one, can reach another year: the
        # reply then says which (see calendar_window.window_spans_other_years).
        results.calendar_show_year = window_spans_other_years(window.time_min, window.time_max, OWNER_TIMEZONE)
        results.calendar_window_label = format_window_range(
            window.time_min, window.time_max, OWNER_TIMEZONE, with_year=results.calendar_show_year,
        )
    elif isinstance(params, CalendarCreateEventParams):
        if params.attendees:
            invite_guard(params.title, params.location)
        results.created_event = calendar_client_factory().create_event(
            title=params.title, day_offset=params.day_offset, start_time=params.start_time,
            duration_minutes=params.duration_minutes, attendees=params.attendees, request_id=parsed.request_id,
            location=params.location, calendar_id=params.calendar_id, end_day_offset=params.end_day_offset,
            end_time=params.end_time, all_day=params.all_day,
        )
    elif isinstance(params, CalendarUpdateEventParams):
        results.updated_event = calendar_client_factory().update_event(
            event_id=params.event_id, title=params.title, day_offset=params.day_offset,
            start_time=params.start_time, duration_minutes=params.duration_minutes,
            add_attendees=params.add_attendees, remove_attendees=params.remove_attendees,
            invite_guard=invite_guard, location=params.location, calendar_id=params.calendar_id,
            end_day_offset=params.end_day_offset, end_time=params.end_time, all_day=params.all_day,
        )
    elif isinstance(params, CalendarDeleteEventParams):
        calendar_client_factory().delete_event(event_id=params.event_id, calendar_id=params.calendar_id)
        results.deleted_event_id = params.event_id
    elif isinstance(params, DriveCreateFileParams):
        results.drive_file_result = drive_client_factory().create_file(name=params.name, content=params.content)
    elif isinstance(params, CapabilitiesParams):
        # No Google API call, no credentials, nothing owner-derived --
        # see app/capabilities.py's module docstring.
        results.capabilities = build_capabilities_info()
    return results


def _status_for_decision(decision: PolicyDecision) -> tuple[str, str | None]:
    if decision.status == "allowed":
        return "completed", None
    return decision.status, decision.error_code


def _run_batch_item(
    item_state: _RequestState,
    *,
    state_store,
    injection_score: float | None,
    gmail_client_factory: Callable[[], GmailClient],
    calendar_client_factory: Callable[[], CalendarClient],
    drive_client_factory: Callable[[], DriveClient],
    output_screen: OutputScreen,
) -> None:
    """One batch item's Layers 3-4, mirroring _run_request's single-request
    flow exactly (policy, execute, EFFECT_DONE) -- Layer 1 (cap, dedupe,
    PROCESSING) was already done for every item at once by _run_batch.
    `injection_score` is the shared score the whole email was screened with
    once (see _run_batch's docstring), never a fresh per-item Jev call, and
    output screening is NOT done here (deferred to one combined call across
    every item, in _run_batch, for the same reason: BATCH_MAX_ITEMS separate
    Jev calls in one request risks the Cloud Run timeout). An exception here
    is caught and turned into that item's own error status -- one item's
    failure must not abort the rest of the batch."""
    parsed = item_state.parsed
    stage = "layer3"
    try:
        if parsed.parse_error:
            item_state.decision = parse_error_decision(parsed.verb, parsed.parse_error, parsed.parse_error_detail)
        else:
            item_state.decision = evaluate_policy(parsed.verb, parsed.params)
            item_state.decision = apply_screen_gate(item_state.decision, injection_score, INJECTION_DENY_THRESHOLD)
            item_state.decision = apply_extra_params_gate(item_state.decision, injection_score, INJECTION_DENY_THRESHOLD)

        stage = "layer4"
        item_state.results = _execute(
            item_state.decision, parsed, gmail_client_factory, calendar_client_factory, drive_client_factory,
            invite_guard=_make_invite_guard(output_screen),
        )
        if item_state.results.wrote:
            # Per item, straight after its own side effect -- not batched
            # with the others: a crash later in the batch must not lose the
            # record that this write happened (app/state_store.py).
            stage = "layer1"
            state_store.set_request_status(parsed.request_id, REQUEST_EFFECT_DONE, item_state.sender)

        item_state.reply_status, item_state.error_code = _status_for_decision(item_state.decision)
        item_state.retryable = False
    except GatekeeperDenied as denied:
        item_state.reply_status, item_state.error_code, item_state.retryable = "denied", denied.error_code, False
        item_state.denial_detail = denied.reason or None
    except Exception as exc:
        failure = classify_failure(exc)
        logger.exception("batch item %s failed at %s (%s)", parsed.request_id, stage, failure.code)
        item_state.failure_code, item_state.failure_stage, item_state.failure_type = failure.code, stage, failure.type_name
        if item_state.results.wrote and item_state.decision is not None:
            # Same rule as the top-level handler: the write already
            # happened, so report it as done rather than inviting a
            # resend that would only hit "duplicate" (effect_done).
            item_state.reply_status, item_state.error_code = _status_for_decision(item_state.decision)
            item_state.retryable = False
        else:
            item_state.reply_status, item_state.error_code, item_state.retryable = "error", failure.code, failure.retryable


def _screen_batch_output(
    output_screen: OutputScreen, item_states: list[_RequestState]
) -> OutputScreenResult | None:
    """One combined screen_items() call across every item's output,
    namespaced `f"item{i}:{key}"` -- BATCH_MAX_ITEMS items cost one Jev
    call instead of up to BATCH_MAX_ITEMS, the same fail-mode contract as
    _screen_output."""
    combined: dict[str, dict[str, str]] = {}
    for i, item_state in enumerate(item_states):
        for key, fields in _output_items(item_state.results).items():
            combined[f"item{i}:{key}"] = fields
    if not combined:
        return None
    try:
        return output_screen.screen_items(combined)
    except Exception:
        logger.exception("batch output screen failed; applying fail mode %s", OUTPUT_SCREEN_FAIL_MODE)
        return all_withheld(list(combined), fail_closed=OUTPUT_SCREEN_FAIL_MODE != "open")


def _run_batch(
    state: _RequestState,
    *,
    state_store,
    gmail_client_factory: Callable[[], GmailClient],
    calendar_client_factory: Callable[[], CalendarClient],
    drive_client_factory: Callable[[], DriveClient],
    output_screen: OutputScreen,
) -> tuple[list[_RequestState], OutputScreenResult | None]:
    """Runs every item in state.parsed.batch_items independently, each
    through the same per-request pipeline a standalone request uses -- own
    dedupe, own policy decision, own execution, own quota slot, own
    eventual audit record (appended by the caller, app/handle_webhook,
    once the combined reply's send outcome is known). Returns the finished
    per-item states plus the ONE combined output-screen result (used for
    the outer reply's aggregate withheld_count/screen, and scoped per item
    on each item_state.output for render_batch_reply).

    Layer 1 is done for all items at once, not per item: one read of the
    request_status tab, the daily cap decided in memory from the count
    _run_request already read, then one append each for the quota rows and
    the PROCESSING rows. Done per item, a batch cost ~7 sequential Sheets
    calls per item -- a 25-item batch overran Sheets' 60-writes-per-minute
    per-user quota mid-request (429s, and audit records lost to Cloud
    Logging) and ate most of the Cloud Run timeout. Every PROCESSING row
    still lands before any item executes, so a write is never performed
    without its request_id already claimed."""
    item_states = [
        _RequestState(
            message_id=state.message_id, sender=state.sender, parsed=item_parsed,
            injection_score=state.injection_score, payload_injection_score=state.payload_injection_score,
            injection_screen_status=state.injection_screen_status,
        )
        for item_parsed in state.parsed.batch_items
    ]

    used = state.quota_used_before if state.quota_used_before is not None else state_store.count_today(state.sender)
    prior = state_store.get_request_status_details([item_state.parsed.request_id for item_state in item_states])
    claimed: set[str] = set()
    runnable: list[_RequestState] = []
    for item_state in item_states:
        request_id = item_state.parsed.request_id
        if used + len(runnable) >= MAX_REQUESTS_PER_DAY:
            _early_return(item_state, "rate_limited", "rate_limited")
            continue
        prior_status, prior_updated_at = prior.get(request_id, (None, None))
        # `claimed`: a request_id repeated within this same batch is a
        # duplicate of its first occurrence, as if that one had already
        # recorded PROCESSING (the rows aren't written until below).
        if request_id in claimed or is_duplicate_request_status(
            prior_status, prior_updated_at, write_verb=is_write_verb(item_state.parsed.verb)
        ):
            _early_return(item_state, "duplicate_request", "duplicate_request", reply_status="duplicate")
            continue
        claimed.add(request_id)
        runnable.append(item_state)

    runnable_ids = [item_state.parsed.request_id for item_state in runnable]
    # Quota rows first: if the PROCESSING append then fails, the worst
    # case is spent quota slots, never a claimed request_id that didn't run.
    state_store.record_requests(state.sender, runnable_ids)
    state.quota_consumed = len(runnable_ids)
    state_store.set_request_statuses([(request_id, REQUEST_PROCESSING) for request_id in runnable_ids], state.sender)
    for item_state in runnable:
        item_state.request_started = True
        _run_batch_item(
            item_state, state_store=state_store, injection_score=state.injection_score,
            gmail_client_factory=gmail_client_factory, calendar_client_factory=calendar_client_factory,
            drive_client_factory=drive_client_factory, output_screen=output_screen,
        )

    combined_output = _screen_batch_output(output_screen, item_states)
    if combined_output is not None:
        for i, item_state in enumerate(item_states):
            scoped = scoped_output(combined_output, f"item{i}")
            # An item with nothing to screen gets no output result at all,
            # the same as a standalone request with no result content.
            item_state.output = scoped if scoped.verdicts else None

    return item_states, combined_output


def _reply_detail(state: _RequestState) -> str | None:
    """Why a request was denied, in our own words: the policy decision's
    reason, or else the executor's."""
    return (state.decision.reason if state.decision else None) or state.denial_detail


def _batch_item_input(item_state: _RequestState) -> BatchItemInput:
    return BatchItemInput(
        parsed_request=item_state.parsed,
        status=item_state.reply_status,
        error_code=item_state.error_code,
        retryable=item_state.retryable,
        detail=_reply_detail(item_state),
        ignored_params=(
            item_state.decision.ignored_params
            if item_state.decision and item_state.reply_status == "completed" else ()
        ),
        output=item_state.output,
        render_kwargs=item_state.results.render_kwargs(),
    )


def _unresolved_request(message_id: str) -> ParsedRequest:
    """Stand-in until (or if) Layer 2 resolves a real request -- the
    request_id is still stable per message, so a reply is always
    correlatable."""
    return ParsedRequest(request_id=fallback_request_id_for(message_id), verb="unsupported", params={}, source="block")


def _send(state: _RequestState, agentmail_client: AgentMailClient, state_store) -> None:
    """Render and send the one reply. Never raises: a rendering failure
    falls back to a minimal status-only reply, and a send failure is
    recorded on the audit record instead of being lost."""
    requests_remaining_today: int | None = None
    if state.quota_used_before is not None:
        requests_remaining_today = max(0, MAX_REQUESTS_PER_DAY - state.quota_used_before - state.quota_consumed)
    else:
        # The rate-cap read itself never happened or failed -- try once more.
        try:
            requests_remaining_today = max(0, MAX_REQUESTS_PER_DAY - state_store.count_today(state.sender))
        except Exception:
            logger.exception("could not compute requests_remaining_today for %s", state.sender)
    try:
        if state.batch_items is not None:
            body = render_batch_reply(
                state.parsed.request_id,
                [_batch_item_input(item_state) for item_state in state.batch_items],
                combined_output=state.output,
                requests_remaining_today=requests_remaining_today,
            )
        else:
            body = render_reply(
                state.parsed, state.reply_status, state.error_code,
                retryable=state.retryable, detail=_reply_detail(state),
                output=state.output,
                ignored_params=state.decision.ignored_params if state.decision and state.reply_status == "completed" else (),
                requests_remaining_today=requests_remaining_today,
                **state.results.render_kwargs(),
            )
    except Exception:
        logger.exception("rendering the reply for %s failed; sending a minimal reply", state.parsed.request_id)
        body = render_minimal_reply(
            state.parsed.request_id, state.reply_status, state.error_code, state.retryable,
            requests_remaining_today=requests_remaining_today,
        )
    if state.output is not None:
        # Audit-only calibration signal for the per-item thresholds
        # (OUTPUT_SENSITIVE_THRESHOLD/OUTPUT_INJECTION_THRESHOLD): the
        # max verdict already computed per item, not a second Jev call
        # over the whole rendered prose -- every item was already
        # screened individually a few lines up (_screen_output/
        # _screen_batch_output), and re-screening the same text again
        # here would cost one more network round trip per reply for a
        # number this derives for free from verdicts already in hand.
        state.output_reply_sensitive = state.output.max_sensitive
        state.output_reply_injection = state.output.max_targets_reader
    try:
        result = send_reply(
            agentmail_client,
            inbox_id=AGENTMAIL_INBOX_ID or "",
            agentmail_message_id=state.message_id,
            sender_address=state.sender,
            body=body,
        )
        state.reply_message_id = result.message_id if result else None
    except Exception as exc:
        logger.exception("sending the reply for %s failed", state.parsed.request_id)
        state.reply_error = type(exc).__name__


def _final_request_status(state: _RequestState) -> str | None:
    """The request's last status row (app/state_store.py), or None if it
    never got as far as recording one. A resend may run again only from
    FAILED: a read whose reply never arrived, or anything that errored
    before a side effect. A write that happened stays at EFFECT_DONE unless
    its reply was delivered."""
    if not state.request_started:
        return None
    wrote = state.results.wrote
    replied = state.reply_error is None
    if wrote:
        return REQUEST_COMPLETED if replied else REQUEST_EFFECT_DONE
    if state.reply_status == "error" or not replied:
        return REQUEST_FAILED
    return REQUEST_COMPLETED


def _finalize_request_statuses(states: list[_RequestState], state_store) -> None:
    """Every final status row in ONE append (a batch's outer request plus
    all its items -- see _run_batch). Never raises."""
    statuses = [(s.parsed.request_id, status) for s in states if (status := _final_request_status(s)) is not None]
    if not statuses:
        return
    try:
        state_store.set_request_statuses(statuses, states[0].sender)
    except Exception:
        logger.exception("could not record final statuses %s", statuses)


def _audit_record(state: _RequestState, *, batch_id: str | None = None) -> AuditRecord:
    results = state.results
    # A TOP-LEVEL request rate-limited before Layer 2 ever ran still has
    # `state.parsed` set to the _unresolved_request() placeholder, not a
    # real parse -- nulled out here so a rate-limited record never claims
    # a request_id/verb it never actually resolved. A BATCH ITEM's
    # `parsed` is always the real, already-parsed item (parsing happens
    # once, for the whole batch, before any item's rate-cap check runs),
    # so that exception doesn't apply to it.
    parsed = state.parsed if (batch_id is not None or state.layer1 != "rate_limited") else None
    return AuditRecord(
        agentmail_message_id=state.message_id,
        sender=state.sender,
        batch_id=batch_id,
        layer0_verdict="ok",
        layer1_verdict=state.layer1,
        parsed_request_id=parsed.request_id if parsed else None,
        parsed_verb=parsed.verb if parsed else None,
        parsed_source=parsed.source if parsed else None,
        payload_count=parsed.payload_count if parsed else 0,
        payload_chars=parsed.payload_chars if parsed else 0,
        injection_score=state.injection_score,
        payload_injection_score=state.payload_injection_score,
        injection_screen_status=state.injection_screen_status,
        policy_status=state.decision.status if state.decision else None,
        ignored_params=state.decision.ignored_params if state.decision else (),
        policy_error_code=state.decision.error_code if state.decision else None,
        reply_status=state.reply_status,
        reply_error_code=state.error_code,
        result_count=(
            len(results.gmail_results or [])
            + len(results.calendar_results or [])
            + len(results.calendars or [])
            + sum(1 for r in (results.draft_result, results.created_event, results.updated_event,
                              results.deleted_event_id, results.drive_file_result) if r)
        ),
        gmail_message_ids=tuple(r.message_id for r in results.gmail_results or ()),
        calendar_event_ids=tuple(e.event_id for e in results.calendar_results or ()),
        # The calendar a calendar verb was aimed at (an opaque id, like the
        # event ids): an event id alone doesn't say which calendar it's on.
        # None for every other verb, and for a list_events that named none.
        calendar_id=getattr(state.decision.params, "calendar_id", None) if state.decision else None,
        reply_message_id=state.reply_message_id,
        reply_error=state.reply_error,
        output_screen_status=state.output.status if state.output else None,
        output_withheld_count=state.output.withheld_count if state.output else 0,
        output_withheld_categories=tuple(state.output.categories) if state.output else (),
        output_max_sensitive=state.output.max_sensitive if state.output else None,
        output_max_injection=state.output.max_targets_reader if state.output else None,
        output_reply_sensitive=state.output_reply_sensitive,
        output_reply_injection=state.output_reply_injection,
        failure_code=state.failure_code,
        failure_stage=state.failure_stage,
        failure_type=state.failure_type,
        llm_input_tokens=(state.llm_usage or {}).get("input_tokens"),
        llm_output_tokens=(state.llm_usage or {}).get("output_tokens"),
        draft_id=results.draft_result.draft_id if results.draft_result else None,
        draft_to=results.draft_result.to if results.draft_result else None,
        created_event_id=results.created_event.event_id if results.created_event else None,
        updated_event_id=results.updated_event.event_id if results.updated_event else None,
        deleted_event_id=results.deleted_event_id,
        drive_file_id=results.drive_file_result.file_id if results.drive_file_result else None,
    )


def _append_audit(audit_log: AuditLog, record: AuditRecord) -> None:
    """The audit append never takes the request down with it. If Sheets is
    unreachable, the full record -- ids and verdicts only, per the audit
    log's own minimization rule -- goes to Cloud Logging at ERROR instead,
    so it's still recoverable."""
    try:
        audit_log.append(record)
    except Exception:
        logger.exception("audit append failed; record follows: %s", json.dumps(_record_for_log(record), sort_keys=True))


def _append_audits(audit_log: AuditLog, records: list[AuditRecord]) -> None:
    """_append_audit for several records in ONE write (a batch -- see
    _run_batch), with the same never-raise, log-it-instead fallback."""
    try:
        audit_log.append_many(records)
    except Exception:
        logger.exception("audit append of %d records failed; records follow", len(records))
        for record in records:
            logger.error("unwritten audit record: %s", json.dumps(_record_for_log(record), sort_keys=True))


def _record_for_log(record: AuditRecord) -> dict[str, Any]:
    from dataclasses import asdict

    return {k: (list(v) if isinstance(v, tuple) else v) for k, v in asdict(record).items()}
