"""
pipeline.py — wires Layers 0-5 together for a single inbound webhook
event, and writes exactly one AuditRecord no matter where processing
stops.

app/main.py's FastAPI route does almost nothing itself: it hands the raw
body + headers to `handle_webhook()` below and returns whatever HTTP
status it's told to. Keeping the actual logic here, not in main.py, is
what makes the whole pipeline testable without an HTTP client or any
real credentials -- see tests/test_pipeline_injection.py.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any, Callable

from app.agentmail_client import AgentMailClient
from app.audit_log import AuditLog, AuditRecord
from app.calendar_executor import CalendarClient, CalendarEvent
from app.calendar_window import resolve_window
from app.config import AGENTMAIL_INBOX_ID, MAX_REQUESTS_PER_DAY, OWNER_EMAIL, OWNER_TIMEZONE
from app.drive_executor import DriveClient, DriveFileResult
from app.gmail_executor import DraftResult, GmailClient, GmailResult
from app.ingress import check_event, parsed_sender_address, verify_signature
from app.policy import (
    CalendarCreateEventParams,
    CalendarDeleteEventParams,
    CalendarListEventsParams,
    CalendarUpdateEventParams,
    DriveCreateFileParams,
    GmailCreateDraftParams,
    GmailSearchParams,
    PolicyDecision,
    evaluate_policy,
)
from app.reader_llm import ReaderLLM
from app.reply_guard import render_reply, send_reply
from app.request_parser import ParsedRequest, parse_request

logger = logging.getLogger("gatekeeper.pipeline")


@dataclass(frozen=True)
class WebhookOutcome:
    http_status: int
    reason: str


def extract_message_fields(payload: dict[str, Any]) -> dict[str, Any] | None:
    """Pulls the fields this pipeline needs out of an AgentMail webhook
    JSON body. The envelope shape (`event_type` at the top level,
    dot-notation values like "message.received", fields nested under
    `"message"`, `message.message_id`, `message.from`) was confirmed
    against AgentMail's current published API reference (raw markdown
    fetched during this build) -- see the final build report. Still NOT
    exercised against a live webhook delivery, so a couple of plausible
    key-name variants (`type` alongside `event_type`, `id` alongside
    `message_id`) are accepted defensively in case a real delivery
    differs from the reference doc in some small way; returns None if
    the payload doesn't look like a message event at all, which the
    caller treats as an ignored (never a trusted) event."""
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
    gmail_client_factory: Callable[[], GmailClient],
    calendar_client_factory: Callable[[], CalendarClient],
    drive_client_factory: Callable[[], DriveClient],
    agentmail_client: AgentMailClient,
    audit_log: AuditLog,
    payload: dict[str, Any] | None = None,
) -> WebhookOutcome:
    """The single entry point every caller (app/main.py and every test)
    uses. `payload` lets tests pass a pre-parsed dict instead of
    re-encoding JSON, since `body` is still required (and still checked)
    for signature verification -- the two must be consistent in real
    use, which app/main.py guarantees by parsing `body` itself.

    `gmail_client_factory`/`calendar_client_factory`/`drive_client_factory`
    are zero-arg callables rather than client instances so a (possibly
    credentialed) client is constructed only on the one request path that
    actually reaches Layer 4 for that verb -- a gmail.search request
    never touches Calendar or Drive credentials, and vice versa."""
    sig_verdict = verify_signature(body, svix_id, svix_timestamp, svix_signature)

    # Best-effort extraction of a message id / sender for the audit log
    # EVEN when the signature is invalid -- an unauthenticated or
    # forged webhook attempt is itself worth a tamper-evident record
    # (research/03 section 4.6, anomaly detection), clearly distinct
    # from a genuine, verified request. These values are UNVERIFIED and
    # must never be used for anything but logging.
    claimed_message_id = "unknown"
    claimed_sender = "unknown"
    data: dict[str, Any] | None = None
    try:
        data = payload if payload is not None else json.loads(body)
        probe = extract_message_fields(data) if isinstance(data, dict) else None
        if probe:
            claimed_message_id = probe["message_id"]
            claimed_sender = parsed_sender_address(probe["sender"])
    except Exception:
        data = None

    if not sig_verdict.accepted:
        logger.info("webhook rejected at layer 0: %s", sig_verdict.reason)
        _log_audit(audit_log, claimed_message_id, claimed_sender, layer0=sig_verdict.reason, layer1="not_reached")
        return WebhookOutcome(202, sig_verdict.reason)

    fields = extract_message_fields(data) if isinstance(data, dict) else None
    if fields is None:
        logger.info("webhook rejected at layer 0: unrecognized_payload_shape")
        _log_audit(audit_log, claimed_message_id, claimed_sender, layer0="unrecognized_payload_shape", layer1="not_reached")
        return WebhookOutcome(202, "unrecognized_payload_shape")

    message_id = fields["message_id"]
    sender_address = parsed_sender_address(fields["sender"])

    event_verdict = check_event(event_type=fields["event_type"], inbox_id=fields["inbox_id"], sender_header=fields["sender"])
    if not event_verdict.accepted:
        logger.info("webhook rejected at layer 0: %s", event_verdict.reason)
        _log_audit(audit_log, message_id, sender_address, layer0=event_verdict.reason, layer1="not_reached")
        return WebhookOutcome(202, event_verdict.reason)  # rejected, never answered

    # ── Layer 1: idempotency + daily cap ────────────────────────────────
    if state_store.is_duplicate_message(message_id):
        _log_audit(audit_log, message_id, sender_address, layer0="ok", layer1="duplicate_message")
        return WebhookOutcome(200, "duplicate_message")
    state_store.mark_message_seen(message_id)

    if state_store.count_today(sender_address) >= MAX_REQUESTS_PER_DAY:
        _log_audit(audit_log, message_id, sender_address, layer0="ok", layer1="rate_limited")
        _reply(agentmail_client, message_id, sender_address, _unresolved_request(message_id), "error", "rate_limited")
        return WebhookOutcome(200, "rate_limited")

    # ── Layer 2: parse ───────────────────────────────────────────────────
    parsed = parse_request(fields["text"], message_id, reader_llm)
    llm_usage = getattr(reader_llm, "last_usage", None) if parsed.source == "llm" else None

    if state_store.is_duplicate_request(parsed.request_id):
        _log_audit(audit_log, message_id, sender_address, layer0="ok", layer1="duplicate_request", parsed=parsed)
        return WebhookOutcome(200, "duplicate_request")
    state_store.mark_request_seen(parsed.request_id)
    state_store.record_request(sender_address)

    # ── Layer 3: policy ──────────────────────────────────────────────────
    decision = evaluate_policy(parsed.verb, parsed.params)

    # ── Layer 4: executor (only for an allowed verb -- exactly one
    # verb, read or write, runs per request) ────────────────────────────
    gmail_results: list[GmailResult] | None = None
    calendar_results: list[CalendarEvent] | None = None
    draft_result: DraftResult | None = None
    created_event: CalendarEvent | None = None
    updated_event: CalendarEvent | None = None
    deleted_event_id: str | None = None
    drive_file_result: DriveFileResult | None = None
    if decision.status == "allowed" and isinstance(decision.params, GmailSearchParams):
        gmail_client = gmail_client_factory()
        gmail_results = gmail_client.search(
            query=decision.params.query,
            max_results=decision.params.max_results,
            newer_than_days=decision.params.newer_than_days,
        )
    elif decision.status == "allowed" and isinstance(decision.params, GmailCreateDraftParams):
        gmail_client = gmail_client_factory()
        draft_result = gmail_client.create_draft(
            to=decision.params.to, subject=decision.params.subject, body=decision.params.body
        )
    elif decision.status == "allowed" and isinstance(decision.params, CalendarListEventsParams):
        window = resolve_window(decision.params.day_offset, decision.params.days, OWNER_TIMEZONE)
        calendar_client = calendar_client_factory()
        calendar_results = calendar_client.list_events(
            time_min=window.time_min, time_max=window.time_max, max_results=decision.params.max_results
        )
    elif decision.status == "allowed" and isinstance(decision.params, CalendarCreateEventParams):
        calendar_client = calendar_client_factory()
        created_event = calendar_client.create_event(
            title=decision.params.title,
            day_offset=decision.params.day_offset,
            start_time=decision.params.start_time,
            duration_minutes=decision.params.duration_minutes,
            attendees=decision.params.attendees,
        )
    elif decision.status == "allowed" and isinstance(decision.params, CalendarUpdateEventParams):
        calendar_client = calendar_client_factory()
        updated_event = calendar_client.update_event(
            event_id=decision.params.event_id,
            title=decision.params.title,
            day_offset=decision.params.day_offset,
            start_time=decision.params.start_time,
            duration_minutes=decision.params.duration_minutes,
            attendees=decision.params.attendees,
        )
    elif decision.status == "allowed" and isinstance(decision.params, CalendarDeleteEventParams):
        calendar_client = calendar_client_factory()
        calendar_client.delete_event(event_id=decision.params.event_id)
        deleted_event_id = decision.params.event_id
    elif decision.status == "allowed" and isinstance(decision.params, DriveCreateFileParams):
        drive_client = drive_client_factory()
        drive_file_result = drive_client.create_file(name=decision.params.name, content=decision.params.content)

    reply_status, error_code = _status_for_decision(decision)

    # ── Layer 5: reply ───────────────────────────────────────────────────
    reply_result = _reply(
        agentmail_client, message_id, sender_address, parsed, reply_status, error_code, gmail_results, calendar_results,
        draft_result=draft_result, created_event=created_event, updated_event=updated_event,
        deleted_event_id=deleted_event_id, drive_file_result=drive_file_result,
    )

    _log_audit(
        audit_log,
        message_id,
        sender_address,
        layer0="ok",
        layer1="ok",
        parsed=parsed,
        decision=decision,
        gmail_results=gmail_results,
        draft_result=draft_result,
        created_event=created_event,
        updated_event=updated_event,
        deleted_event_id=deleted_event_id,
        drive_file_result=drive_file_result,
        calendar_results=calendar_results,
        reply_message_id=reply_result.message_id if reply_result else None,
        llm_usage=llm_usage,
    )
    return WebhookOutcome(200, "processed")


def _status_for_decision(decision: PolicyDecision) -> tuple[str, str | None]:
    if decision.status == "allowed":
        return "completed", None
    return decision.status, decision.error_code


def _unresolved_request(message_id: str) -> ParsedRequest:
    return ParsedRequest(request_id=f"unresolved-{message_id}", verb="unsupported", params={}, source="block")


def _reply(
    agentmail_client: AgentMailClient,
    message_id: str,
    sender_address: str,
    parsed: ParsedRequest,
    status: str,
    error_code: str | None,
    gmail_results: list[GmailResult] | None = None,
    calendar_results: list[CalendarEvent] | None = None,
    *,
    draft_result: DraftResult | None = None,
    created_event: CalendarEvent | None = None,
    updated_event: CalendarEvent | None = None,
    deleted_event_id: str | None = None,
    drive_file_result: DriveFileResult | None = None,
):
    body = render_reply(
        parsed, status, error_code, gmail_results, calendar_results,
        draft_result=draft_result, created_event=created_event, updated_event=updated_event,
        deleted_event_id=deleted_event_id, drive_file_result=drive_file_result,
    )
    return send_reply(
        agentmail_client,
        inbox_id=AGENTMAIL_INBOX_ID or "",
        agentmail_message_id=message_id,
        sender_address=sender_address,
        bcc_address=OWNER_EMAIL or "",
        body=body,
    )


def _log_audit(
    audit_log: AuditLog,
    message_id: str,
    sender: str,
    *,
    layer0: str,
    layer1: str,
    parsed: ParsedRequest | None = None,
    decision: PolicyDecision | None = None,
    gmail_results: list[GmailResult] | None = None,
    calendar_results: list[CalendarEvent] | None = None,
    reply_message_id: str | None = None,
    llm_usage: dict[str, int] | None = None,
    draft_result: DraftResult | None = None,
    created_event: CalendarEvent | None = None,
    updated_event: CalendarEvent | None = None,
    deleted_event_id: str | None = None,
    drive_file_result: DriveFileResult | None = None,
) -> None:
    write_result_count = sum(
        1 for r in (draft_result, created_event, updated_event, deleted_event_id, drive_file_result) if r
    )
    audit_log.append(
        AuditRecord(
            agentmail_message_id=message_id,
            sender=sender,
            layer0_verdict=layer0,
            layer1_verdict=layer1,
            parsed_request_id=parsed.request_id if parsed else None,
            parsed_verb=parsed.verb if parsed else None,
            parsed_source=parsed.source if parsed else None,
            policy_status=decision.status if decision else None,
            policy_error_code=decision.error_code if decision else None,
            result_count=(
                (len(gmail_results) if gmail_results else 0)
                + (len(calendar_results) if calendar_results else 0)
                + write_result_count
            ),
            gmail_message_ids=tuple(r.message_id for r in gmail_results) if gmail_results else (),
            calendar_event_ids=tuple(e.event_id for e in calendar_results) if calendar_results else (),
            reply_message_id=reply_message_id,
            llm_input_tokens=(llm_usage or {}).get("input_tokens"),
            llm_output_tokens=(llm_usage or {}).get("output_tokens"),
            draft_id=draft_result.draft_id if draft_result else None,
            draft_to=draft_result.to if draft_result else None,
            created_event_id=created_event.event_id if created_event else None,
            updated_event_id=updated_event.event_id if updated_event else None,
            deleted_event_id=deleted_event_id,
            drive_file_id=drive_file_result.file_id if drive_file_result else None,
        )
    )
