"""
reply_guard.py — Layer 5: the only module that decides what text leaves
this service, and to whom.

Three guarantees, all enforced HERE rather than trusted from an upstream
layer:

  1. The reply goes to the cryptographically-verified sender address
     ONLY. `render_reply`/`send_reply` don't even have a "recipient"
     parameter -- only `sender_address`, which app/pipeline.py fills in
     exactly once, from app/ingress.py's `parsed_sender_address()`,
     never from a Reply-To header or from anything inside the email body
     or a Gmail result. An injected instruction anywhere upstream has no
     field to write a different recipient into. No cc, no bcc: until
     2026-09-22 every reply was BCC'd to the owner; the owner dropped that
     in favor of AgentMail's own thread history.
  2. Gmail result text (subject, snippet, sender) and Calendar result
     text (event summary, location) are redacted -- deterministically,
     and deliberately narrowly -- for written-out passwords, full payment
     card numbers (Luhn-checked), one-time codes (digits in code/login/
     verification context), and URLs BEFORE they can appear in a
     reply -- the last line of defense against a poisoned Gmail snippet
     OR a poisoned calendar event title/location trying to phish or
     exfiltrate via the reply itself, even though Layer 3 already
     refused any gmail.search *query* that would knowingly search for
     such content (there is no equivalent query to refuse for
     calendar.list_events -- an attacker who can create an event on the
     owner's calendar controls its title and location directly, which is
     exactly why this redaction pass matters there too).
  3. Plain text only, size-capped, no attachments, no rendered links --
     closing the exact auto-fetch exfiltration channel research/03
     section 1.5 (EchoLeak) used.

Every reply is: human-readable prose first, then a fenced
---GATEKEEPER-RESPONSE--- YAML block with request_id/status/error_code/
retryable/result_count/withheld_count (+ screen) -- research/05 section 2's
"Design C" hybrid protocol. docs/PROTOCOL.md documents every field.

Point 2's regex redaction and the structural escaping below run on every
item; on top of them, app/output_screen.py's Jev verdicts decide which
items' text is withheld outright (ids kept) -- see render_reply's `output`.
"""
from __future__ import annotations

import re

import yaml

from app.agentmail_client import AgentMailClient, ReplyResult
from app.calendar_executor import CalendarEvent
from app.calendar_window import format_event_range
from app.config import OWNER_TIMEZONE, REPLY_MAX_CHARS
from app.drive_executor import DriveFileResult
from app.gmail_executor import DraftResult, GmailResult
from app.output_screen import (
    CREATED_EVENT_KEY,
    DRAFT_KEY,
    DRIVE_FILE_KEY,
    UPDATED_EVENT_KEY,
    WITHHELD_TEXT,
    OutputScreenResult,
    event_key,
    gmail_key,
)
from app.request_parser import ParsedRequest

_REDACTED = "[redacted]"

# Secrecy redaction is NARROW on purpose (owner's rule, 2026-09-22): the
# owner shares personal, financial and business information with Instinct
# deliberately. Exactly three things must never leak -- written-out
# passwords, full payment card numbers, one-time codes -- the same three
# app/output_screen.py asks Jev about. (Until then every 4-8 digit number
# was redacted: years in dates, amounts, order numbers.) URLs are the one
# other thing removed, for a different reason: see module docstring point 3.
#
# Order matters: URLs first (so a digit run inside a URL isn't half-
# redacted), then passwords, then card numbers, then one-time codes (so a
# card number isn't chopped into "codes" first).
_URL_RE = re.compile(r"https?://\S+", re.I)
# A value written right after a password label: "password: hunter2",
# "password is hunter2", "סיסמה: ...". Only redacted when the value looks
# like a secret (see _looks_like_secret), so "password is required" stays.
_PASSWORD_RE = re.compile(
    r"(?P<label>\b(?:password|passwd|pwd|passcode|passphrase)\b|סיסמה|סיסמא)"
    r"(?P<sep>\s*[:=]\s*|\s+is\s+|\s+היא\s+)(?P<value>[^\s,;]+)",
    re.I,
)
# 13-19 digits, optionally grouped by spaces or dashes; redacted only if
# the digits pass the Luhn checksum every real card number passes.
_CARD_CANDIDATE_RE = re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)")
# One-time codes: a 4-8 digit number, but only in text that also talks
# about a code, login or verification -- a bare "2026" or "4999" is not one.
_OTP_CONTEXT_RE = re.compile(
    r"\b(?:code|otp|one[- ]?time|passcode|pin|verif\w*|2fa|mfa|two[- ]factor|sign[- ]?in|"
    r"log[- ]?in|authenticat\w*)\b|קוד|אימות",
    re.I,
)
_OTP_RE = re.compile(r"(?<![\d.,/:])\b\d{4,8}\b(?![.,/:]\d)")


def _luhn_ok(digits: str) -> bool:
    total = 0
    for index, char in enumerate(reversed(digits)):
        value = int(char)
        if index % 2 == 1:
            value = value * 2 - 9 if value > 4 else value * 2
        total += value
    return total % 10 == 0


def _redact_card(match: re.Match) -> str:
    digits = re.sub(r"\D", "", match.group(0))
    return _REDACTED if 13 <= len(digits) <= 19 and _luhn_ok(digits) else match.group(0)


def _looks_like_secret(value: str) -> bool:
    value = value.strip(".!?)\"'")
    if len(value) < 4:
        return False
    has_digit = any(c.isdigit() for c in value)
    has_symbol = any(not c.isalnum() for c in value)
    mixed_case = any(c.isupper() for c in value) and any(c.islower() for c in value)
    return has_digit or has_symbol or mixed_case or not value.isascii()


def _redact_password(match: re.Match) -> str:
    if not _looks_like_secret(match.group("value")):
        return match.group(0)
    return f"{match.group('label')}{match.group('sep')}{_REDACTED}"


# Structural escaping (ported 2026-09-22 from the fix/durable-agentmail-webhook
# branch): separate from the secrecy redaction above. Every Google- or
# attacker-derived display value is flattened to ONE printable line that
# cannot forge protocol framing or a chat-role boundary. Before this, an
# email subject or calendar title containing a newline plus
# `---GATEKEEPER-RESPONSE---` could plant a fake status block in a reply --
# a real concern, since Instinct (an LLM) parses these replies.
_ANSI_RE = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))")
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_LINE_SEPARATORS_RE = re.compile(r"[\r\n\u0085\u2028\u2029]+")
# Every marker the protocol uses, including the payload rail's (docs/PROTOCOL.md).
_RESERVED_MARKER_RE = re.compile(
    r"---(?:GATEKEEPER-[A-Z0-9_-]+|END(?:-PAYLOAD-[A-Za-z0-9_-]+)?|PAYLOAD-[A-Za-z0-9_-]+)---", re.I
)
_ROLE_TAG_RE = re.compile(r"</?\s*(?:system|assistant|developer|tool|user)(?:\s+[^>]*)?>", re.I)
_ROLE_LABEL_RE = re.compile(r"^\s*(?:system|assistant|developer|tool|user)\s*:", re.I)


def sanitize_output(text: str) -> str:
    """Make provider-controlled text safe inside the line protocol: one
    printable line, no ANSI/control characters, no protocol markers, no
    chat-role tags or leading role labels. Used alone for opaque ids (so
    their digit runs survive), and via safe_display() for everything else."""
    value = str(text)
    value = _ANSI_RE.sub("", value)
    value = _LINE_SEPARATORS_RE.sub(" ", value)
    value = _CONTROL_RE.sub("", value)
    value = _RESERVED_MARKER_RE.sub("[reserved marker removed]", value)
    value = _ROLE_TAG_RE.sub("[role tag removed]", value)
    value = _ROLE_LABEL_RE.sub("[role label removed] ", value)
    return " ".join(value.split())


def safe_display(text: str) -> str:
    """Secrecy redaction, then structural escaping -- for every display
    value that isn't an opaque id."""
    return sanitize_output(redact(str(text)))


def redact(text: str) -> str:
    """Pure function, unit-tested in isolation. See the comment above
    _URL_RE for exactly what is -- and deliberately isn't -- removed."""
    text = _URL_RE.sub(_REDACTED, text)
    text = _PASSWORD_RE.sub(_redact_password, text)
    text = _CARD_CANDIDATE_RE.sub(_redact_card, text)
    if _OTP_CONTEXT_RE.search(text):
        text = _OTP_RE.sub(_REDACTED, text)
    return text


def render_reply(
    parsed_request: ParsedRequest,
    status: str,
    error_code: str | None,
    gmail_results: list[GmailResult] | None = None,
    calendar_results: list[CalendarEvent] | None = None,
    clarification_question: str | None = None,
    draft_result: DraftResult | None = None,
    created_event: CalendarEvent | None = None,
    updated_event: CalendarEvent | None = None,
    deleted_event_id: str | None = None,
    drive_file_result: DriveFileResult | None = None,
    retryable: bool = False,
    detail: str | None = None,
    output: OutputScreenResult | None = None,
    ignored_params: tuple[str, ...] = (),
) -> str:
    """Builds the full reply body. Deliberately takes no recipient
    argument at all -- see module docstring point 1. Exactly one of the
    result arguments is populated per call in practice (app/pipeline.py
    only ever executes one verb per request), but each is accepted
    independently rather than a single ambiguous "results" blob, so a
    caller can't accidentally hand one verb's result to another verb's
    formatter."""
    result_count = (
        len(gmail_results or [])
        + len(calendar_results or [])
        + (1 if draft_result else 0)
        + (1 if created_event else 0)
        + (1 if updated_event else 0)
        + (1 if deleted_event_id else 0)
        + (1 if drive_file_result else 0)
    )
    prose_lines: list[str] = []

    def withheld(key: str) -> bool:
        return output is not None and output.is_withheld(key)

    if error_code == "rate_limited":
        prose_lines.append("You've hit today's request limit for this inbox. Please try again tomorrow.")
    elif status == "duplicate":
        prose_lines.append(
            "This request_id was already received, so it was not run again. "
            "The earlier reply for it carries the result."
        )
    elif status == "error":
        prose_lines.append(_error_prose(error_code, retryable))
    elif status == "completed" and parsed_request.verb == "calendar.list_events":
        if calendar_results:
            prose_lines.append(f"Found {len(calendar_results)} event(s):")
            for i, e in enumerate(calendar_results):
                # The time comes from Google's structured start/end, never free
                # text, so it's kept even when the item's text is withheld.
                when = format_event_range(e.start, e.end, e.all_day, OWNER_TIMEZONE)
                event_id = f"(event_id: {sanitize_output(e.event_id)})"
                if withheld(event_key(i)):
                    prose_lines.append(f"- {WITHHELD_TEXT} — {when} {event_id}")
                    continue
                title = safe_display(e.summary) or "(no title)"
                location = f", at {safe_display(e.location)}" if e.location else ""
                attendees = f", {e.attendee_count} attendee(s)" if e.attendee_count else ""
                prose_lines.append(f"- {title} — {when}{location}{attendees} {event_id}")
        else:
            prose_lines.append("No events found.")
    elif status == "completed" and parsed_request.verb == "calendar.create_event" and created_event:
        title = WITHHELD_TEXT if withheld(CREATED_EVENT_KEY) else f"'{safe_display(created_event.summary) or '(no title)'}'"
        when = format_event_range(created_event.start, created_event.end, created_event.all_day, OWNER_TIMEZONE)
        attendees = f", invited {created_event.attendee_count} attendee(s)" if created_event.attendee_count else ""
        prose_lines.append(f"Created event {title} — {when}{attendees} (event_id: {sanitize_output(created_event.event_id)}).")
    elif status == "completed" and parsed_request.verb == "calendar.update_event" and updated_event:
        title = WITHHELD_TEXT if withheld(UPDATED_EVENT_KEY) else f"'{safe_display(updated_event.summary) or '(no title)'}'"
        when = format_event_range(updated_event.start, updated_event.end, updated_event.all_day, OWNER_TIMEZONE)
        attendees = f", {updated_event.attendee_count} attendee(s)" if updated_event.attendee_count else ""
        prose_lines.append(f"Updated event {title} — {when}{attendees} (event_id: {sanitize_output(updated_event.event_id)}).")
    elif status == "completed" and parsed_request.verb == "calendar.delete_event" and deleted_event_id:
        prose_lines.append(f"Deleted event {sanitize_output(deleted_event_id)}.")
    elif status == "completed" and parsed_request.verb == "gmail.create_draft" and draft_result:
        where = (
            f" (as a reply in thread {sanitize_output(draft_result.thread_id)})"
            if draft_result.thread_id
            else ""
        )
        what = (
            f"a draft {WITHHELD_TEXT}"
            if withheld(DRAFT_KEY)
            else f"a draft to {sanitize_output(draft_result.to)}, subject: '{safe_display(draft_result.subject)}'"
        )
        prose_lines.append(
            f"Created {what}{where}. "
            "Review and send it yourself in Gmail -- this gatekeeper never sends email on your behalf."
        )
    elif status == "completed" and parsed_request.verb == "drive.create_file" and drive_file_result:
        name = WITHHELD_TEXT if withheld(DRIVE_FILE_KEY) else f"'{safe_display(drive_file_result.name)}'"
        prose_lines.append(f"Created Drive file {name}.")
    elif status == "completed":
        results = gmail_results or []
        if results:
            prose_lines.append(f"Found {len(results)} matching email(s):")
            for i, r in enumerate(results):
                # thread_id is an opaque Google token (like a calendar
                # event_id): structurally escaped only -- never through
                # redact(), which would mangle its digit runs and break the
                # ability to reply into the thread. It's what a follow-up
                # gmail.create_draft copies to file a reply into this thread,
                # so it's kept even when the item's text is withheld.
                thread = f" (thread_id: {sanitize_output(r.thread_id)})" if r.thread_id else ""
                if withheld(gmail_key(i)):
                    prose_lines.append(f"- {WITHHELD_TEXT}{thread}")
                    continue
                subject = safe_display(r.subject) or "(no subject)"
                snippet = safe_display(r.snippet)
                # The sender header is attacker-controlled too (display names can carry
                # URLs or instructions), so it goes through the same redaction.
                prose_lines.append(f"- {subject} — {safe_display(r.sender)} ({safe_display(r.date)}){thread}\n  {snippet}")
            if output is not None and output.status == "degraded":
                prose_lines.append("(Content screening was unavailable for some items, so their text was withheld.)")
        else:
            prose_lines.append("No matching emails found.")
    elif status == "needs_clarification":
        prose_lines.append(safe_display(clarification_question) if clarification_question else "Could you clarify this request?")
    elif status == "not_implemented":
        prose_lines.append(f"'{sanitize_output(parsed_request.verb)}' is a recognized request type but isn't implemented yet.")
    elif status == "denied" and error_code in _EXPLAINED_DENIALS:
        # Denials the requester can fix get the policy's own reason (our
        # words, sanitized -- a reason may quote a requester-supplied value).
        # Security denials below deliberately stay generic.
        prose = _EXPLAINED_DENIALS[error_code]
        if detail:
            prose += f" Detail: {sanitize_output(detail)}."
        prose_lines.append(prose)
    elif status == "denied":
        if error_code == "sensitive_query_refused":
            prose_lines.append(
                "This request was refused: it looks like it's asking about a verification code, "
                "password reset, or similarly sensitive content, which this gatekeeper never forwards."
            )
        elif error_code == "sensitive_content_refused":
            prose_lines.append(
                "This request was refused: the event has attendees, and its title was flagged as "
                "sensitive (or could not be checked), so no invite was sent."
            )
        elif error_code == "not_gatekeeper_event":
            prose_lines.append(
                "This request was not authorized: the gatekeeper only changes or deletes calendar "
                "events that it created itself."
            )
        else:
            prose_lines.append("This request was not authorized.")
    else:  # "unsupported" or any other/unknown status
        prose_lines.append("This request could not be understood or completed.")

    ignored = [sanitize_output(name) for name in ignored_params]
    if status == "completed" and ignored:
        # Extra parameters are tolerated only after passing the injection
        # screen (app/policy.py) -- and never silently: the requester must
        # not believe a field it sent took effect.
        prose_lines.append(
            f"Note: ignored parameter(s) that {sanitize_output(parsed_request.verb)} doesn't use: {', '.join(ignored)}."
        )

    prose = "\n".join(prose_lines)

    yaml_block = _status_block(
        parsed_request.request_id, status, error_code, result_count, retryable, output,
        ignored if status == "completed" else [],
    )
    body = f"{prose}\n\n---GATEKEEPER-RESPONSE---\n{yaml_block}\n---END---\n"

    if len(body) > REPLY_MAX_CHARS:
        # Truncate the prose, never the machine-readable block -- a
        # parser (or a human skimming) must always be able to find an
        # intact status block even in a capped reply.
        suffix = "\n\n[truncated]"
        keep = max(0, REPLY_MAX_CHARS - len(body) + len(prose) - len(suffix))
        body = f"{prose[:keep]}{suffix}\n\n---GATEKEEPER-RESPONSE---\n{yaml_block}\n---END---\n"

    return body


_EXPLAINED_DENIALS = {
    "invalid_params": "This request's parameters were not valid.",
    "invalid_request_block": "The GATEKEEPER-REQUEST block could not be parsed.",
    "ambiguous_request": "This email contains more than one GATEKEEPER-REQUEST block; send exactly one request per email.",
    "invalid_payload": "This request's GATEKEEPER-PAYLOAD section(s) were not valid.",
    "too_long_for_freeform": (
        "This request is too long to handle as plain text. Resend it as a GATEKEEPER-REQUEST block, "
        "with the long text in a GATEKEEPER-PAYLOAD section."
    ),
}

_ERROR_PROSE = {
    "not_found": "The item this request refers to was not found.",
    "conflict": "This request conflicts with the current state of the item it refers to.",
    "upstream_rejected": "Google rejected this request.",
    "upstream_unavailable": "A service this request depends on was unavailable.",
    "internal_error": "Something went wrong inside the gatekeeper while handling this request.",
}


def _error_prose(error_code: str | None, retryable: bool) -> str:
    base = _ERROR_PROSE.get(error_code or "", "This request could not be completed.")
    hint = (
        " It is safe to resend it with the same request_id."
        if retryable
        else " Resending it unchanged is unlikely to help."
    )
    return base + hint


def _status_block(
    request_id: str, status: str, error_code: str | None, result_count: int, retryable: bool,
    output: OutputScreenResult | None = None, ignored_params: list[str] | None = None,
) -> str:
    block: dict = {
        "request_id": sanitize_output(request_id),
        "status": sanitize_output(status),
        "error_code": sanitize_output(error_code) if error_code is not None else None,
        "retryable": retryable,
        "result_count": result_count,
        "withheld_count": output.withheld_count if output is not None else 0,
    }
    if output is not None:
        # Only present when there was result content to screen:
        # ok | degraded (some items unscreenable, withheld) | disabled (no screen configured).
        # ("off" would be a YAML boolean -- a naive parser would read False.)
        block["screen"] = output.status
    if ignored_params:
        block["ignored_params"] = list(ignored_params)
    return yaml.safe_dump(block, sort_keys=False, default_flow_style=False).strip()


def render_minimal_reply(request_id: str, status: str, error_code: str | None, retryable: bool) -> str:
    """Fallback used only if render_reply itself raises: no result content
    at all, just the machine-readable status block, so the requester still
    learns what happened to its request."""
    yaml_block = _status_block(request_id, status, error_code, 0, retryable)
    return f"This request was processed, but its results could not be formatted.\n\n---GATEKEEPER-RESPONSE---\n{yaml_block}\n---END---\n"


def send_reply(
    agentmail_client: AgentMailClient,
    inbox_id: str,
    agentmail_message_id: str,
    sender_address: str,
    body: str,
) -> ReplyResult:
    """Sends to `sender_address` ONLY -- no cc, no bcc (see module docstring
    point 1; the owner BCC was removed 2026-09-22)."""
    return agentmail_client.reply(inbox_id=inbox_id, message_id=agentmail_message_id, to=sender_address, text=body)
