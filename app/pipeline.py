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
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any, Callable

from app.agentmail_client import AgentMailClient
from app.audit_log import AuditLog, AuditRecord
from app.calendar_executor import CalendarClient, CalendarEvent
from app.calendar_window import resolve_window
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
    event_key,
    gmail_key,
)
from app.policy import (
    CalendarCreateEventParams,
    CalendarDeleteEventParams,
    CalendarListEventsParams,
    CalendarUpdateEventParams,
    DriveCreateFileParams,
    GmailCreateDraftParams,
    GmailSearchParams,
    PolicyDecision,
    apply_screen_gate,
    evaluate_policy,
    parse_error_decision,
)
from app.reader_llm import ReaderLLM
from app.reply_guard import render_minimal_reply, render_reply, send_reply
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
    draft_result: DraftResult | None = None
    created_event: CalendarEvent | None = None
    updated_event: CalendarEvent | None = None
    deleted_event_id: str | None = None
    drive_file_result: DriveFileResult | None = None

    @property
    def wrote(self) -> bool:
        return any((self.draft_result, self.created_event, self.updated_event, self.deleted_event_id, self.drive_file_result))

    def render_kwargs(self) -> dict[str, Any]:
        return {
            "gmail_results": self.gmail_results,
            "calendar_results": self.calendar_results,
            "draft_result": self.draft_result,
            "created_event": self.created_event,
            "updated_event": self.updated_event,
            "deleted_event_id": self.deleted_event_id,
            "drive_file_result": self.drive_file_result,
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
    reply_message_id: str | None = None
    reply_error: str | None = None
    outcome_reason: str = "processed"
    output: OutputScreenResult | None = None
    output_reply_sensitive: float | None = None
    output_reply_injection: float | None = None


def extract_message_fields(payload: dict[str, Any]) -> dict[str, Any] | None:
    """Pulls the fields this pipeline needs out of an AgentMail webhook
    JSON body (`event_type` at the top level, fields nested under
    `"message"`). A couple of plausible key-name variants (`type` alongside
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
    except Exception as exc:
        failure = classify_failure(exc)
        stage = getattr(exc, "_gatekeeper_stage", stage)
        logger.exception("request %s failed at %s (%s)", state.parsed.request_id, stage, failure.code)
        state.reply_status, state.error_code, state.retryable = "error", failure.code, failure.retryable
        state.failure_code, state.failure_stage, state.failure_type = failure.code, stage, failure.type_name
        state.outcome_reason = "failed"

    # ── Layer 5: reply ───────────────────────────────────────────────────
    _send(state, agentmail_client, output_screen)
    _append_audit(audit_log, _audit_record(state))
    _finalize_request_status(state, state_store)
    return WebhookOutcome(200, state.outcome_reason)


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
        if state_store.count_today(state.sender) >= MAX_REQUESTS_PER_DAY:
            state.layer1 = "rate_limited"
            state.reply_status, state.error_code = "error", "rate_limited"
            state.outcome_reason = "rate_limited"
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
        prior_status = state_store.get_request_status(state.parsed.request_id)
        if is_duplicate_request_status(prior_status):
            state.layer1 = "duplicate_request"
            state.reply_status, state.error_code = "duplicate", "duplicate_request"
            state.outcome_reason = "duplicate_request"
            return stage
        state_store.set_request_status(state.parsed.request_id, REQUEST_PROCESSING, state.sender)
        state.request_started = True
        state_store.record_request(state.sender, state.parsed.request_id)

        # ── Layer 3: policy ──────────────────────────────────────────────
        stage = "layer3"
        if state.parsed.parse_error:
            state.decision = parse_error_decision(state.parsed.verb, state.parsed.parse_error, state.parsed.parse_error_detail)
        else:
            state.decision = evaluate_policy(state.parsed.verb, state.parsed.params)
            state.decision = apply_screen_gate(state.decision, state.injection_score, INJECTION_DENY_THRESHOLD)

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


def _make_invite_guard(output_screen: OutputScreen) -> Callable[[str], None]:
    """A calendar event with attendees sends its title to third parties the
    moment it's written, with no human review -- so the title is screened
    first, and a flagged (or, failing closed, unscreenable) title refuses
    the write. See app/output_screen.py."""

    def guard(title: str) -> None:
        try:
            result = output_screen.screen_items({INVITE_KEY: {"title": title}})
        except Exception:
            logger.exception("invite title screen failed")
            result = all_withheld([INVITE_KEY], fail_closed=OUTPUT_SCREEN_FAIL_MODE != "open")
        if result.is_withheld(INVITE_KEY):
            raise GatekeeperDenied(
                "sensitive_content_refused",
                "the event title was flagged as sensitive (or could not be screened) and the event has attendees",
            )

    return guard


def _output_items(results: ExecutionResults) -> dict[str, dict[str, str]]:
    items: dict[str, dict[str, str]] = {}
    for i, r in enumerate(results.gmail_results or []):
        items[gmail_key(i)] = {"from": r.sender, "subject": r.subject, "date": r.date, "snippet": r.snippet}
    for i, e in enumerate(results.calendar_results or []):
        items[event_key(i)] = {"title": e.summary, "location": e.location}
    if results.created_event:
        items[CREATED_EVENT_KEY] = {"title": results.created_event.summary}
    if results.updated_event:
        items[UPDATED_EVENT_KEY] = {"title": results.updated_event.summary}
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
    invite_guard: Callable[[str], None],
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
    elif isinstance(params, CalendarListEventsParams):
        window = resolve_window(params.day_offset, params.days, OWNER_TIMEZONE)
        results.calendar_results = calendar_client_factory().list_events(
            time_min=window.time_min, time_max=window.time_max, max_results=params.max_results,
        )
    elif isinstance(params, CalendarCreateEventParams):
        if params.attendees:
            invite_guard(params.title)
        results.created_event = calendar_client_factory().create_event(
            title=params.title, day_offset=params.day_offset, start_time=params.start_time,
            duration_minutes=params.duration_minutes, attendees=params.attendees, request_id=parsed.request_id,
        )
    elif isinstance(params, CalendarUpdateEventParams):
        results.updated_event = calendar_client_factory().update_event(
            event_id=params.event_id, title=params.title, day_offset=params.day_offset,
            start_time=params.start_time, duration_minutes=params.duration_minutes,
            add_attendees=params.add_attendees, remove_attendees=params.remove_attendees,
            invite_guard=invite_guard,
        )
    elif isinstance(params, CalendarDeleteEventParams):
        calendar_client_factory().delete_event(event_id=params.event_id)
        results.deleted_event_id = params.event_id
    elif isinstance(params, DriveCreateFileParams):
        results.drive_file_result = drive_client_factory().create_file(name=params.name, content=params.content)
    return results


def _status_for_decision(decision: PolicyDecision) -> tuple[str, str | None]:
    if decision.status == "allowed":
        return "completed", None
    return decision.status, decision.error_code


def _unresolved_request(message_id: str) -> ParsedRequest:
    """Stand-in until (or if) Layer 2 resolves a real request -- the
    request_id is still stable per message, so a reply is always
    correlatable."""
    return ParsedRequest(request_id=fallback_request_id_for(message_id), verb="unsupported", params={}, source="block")


def _send(state: _RequestState, agentmail_client: AgentMailClient, output_screen: OutputScreen) -> None:
    """Render and send the one reply. Never raises: a rendering failure
    falls back to a minimal status-only reply, and a send failure is
    recorded on the audit record instead of being lost."""
    try:
        body = render_reply(
            state.parsed, state.reply_status, state.error_code,
            retryable=state.retryable, detail=state.decision.reason if state.decision else None,
            output=state.output,
            **state.results.render_kwargs(),
        )
    except Exception:
        logger.exception("rendering the reply for %s failed; sending a minimal reply", state.parsed.request_id)
        body = render_minimal_reply(state.parsed.request_id, state.reply_status, state.error_code, state.retryable)
    if state.output is not None:
        # Whole-reply backstop: the rendered prose (not the status block) is
        # screened once more. Audit-only -- a calibration signal for the
        # per-item thresholds, never a second withholding pass.
        try:
            prose = body.split("\n\n---GATEKEEPER-RESPONSE---", 1)[0]
            state.output_reply_sensitive, state.output_reply_injection = output_screen.screen_text(prose)
        except Exception:
            logger.exception("whole-reply screen failed")
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


def _finalize_request_status(state: _RequestState, state_store) -> None:
    """The request's last status row (app/state_store.py). A resend may run
    again only from FAILED: a read whose reply never arrived, or anything
    that errored before a side effect. A write that happened stays at
    EFFECT_DONE unless its reply was delivered."""
    if not state.request_started:
        return
    wrote = state.results.wrote
    replied = state.reply_error is None
    if wrote:
        status = REQUEST_COMPLETED if replied else REQUEST_EFFECT_DONE
    elif state.reply_status == "error" or not replied:
        status = REQUEST_FAILED
    else:
        status = REQUEST_COMPLETED
    try:
        state_store.set_request_status(state.parsed.request_id, status, state.sender)
    except Exception:
        logger.exception("could not record final status %s for request %s", status, state.parsed.request_id)


def _audit_record(state: _RequestState) -> AuditRecord:
    results = state.results
    parsed = state.parsed if state.layer1 != "rate_limited" else None
    return AuditRecord(
        agentmail_message_id=state.message_id,
        sender=state.sender,
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
        policy_error_code=state.decision.error_code if state.decision else None,
        reply_status=state.reply_status,
        reply_error_code=state.error_code,
        result_count=(
            len(results.gmail_results or [])
            + len(results.calendar_results or [])
            + sum(1 for r in (results.draft_result, results.created_event, results.updated_event,
                              results.deleted_event_id, results.drive_file_result) if r)
        ),
        gmail_message_ids=tuple(r.message_id for r in results.gmail_results or ()),
        calendar_event_ids=tuple(e.event_id for e in results.calendar_results or ()),
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


def _record_for_log(record: AuditRecord) -> dict[str, Any]:
    from dataclasses import asdict

    return {k: (list(v) if isinstance(v, tuple) else v) for k, v in asdict(record).items()}
