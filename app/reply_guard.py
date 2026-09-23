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
     card numbers (Luhn-checked), and one-time codes (digits in code/
     login/verification context) BEFORE they can appear in a reply -- the
     last line of defense against a poisoned Gmail snippet OR a poisoned
     calendar event title/location trying to phish or exfiltrate via the
     reply itself, even though Layer 3 already refused any gmail.search
     *query* that would knowingly search for such content (there is no
     equivalent query to refuse for calendar.list_events -- an attacker
     who can create an event on the owner's calendar controls its title
     and location directly, which is exactly why this redaction pass
     matters there too). URLs are NOT stripped (owner's decision,
     2026-09-23: the owner wants Instinct able to see and review links,
     e.g. a Drive link shared by someone else) -- app/output_screen.py's
     Jev screen, which asks whether an item's text targets the reader,
     remains the defense against a link crafted to phish or exfiltrate.
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
from app.capabilities import CapabilitiesInfo
from app.config import GIT_SHA, OWNER_TIMEZONE, REPLY_MAX_CHARS
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
# was redacted: years in dates, amounts, order numbers.) URLs used to be
# stripped too; the owner removed that 2026-09-23 (see module docstring
# point 2) -- Jev's outbound screen is now the only defense against a
# link-based phishing/exfiltration attempt, not this regex layer.
#
# Order matters: passwords first, then card numbers, then one-time codes
# (so a card number isn't chopped into "codes" first).
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


def safe_display(text: str, *, otp_context: str | None = None) -> str:
    """Secrecy redaction, then structural escaping -- for every display
    value that isn't an opaque id. `otp_context`: see redact()."""
    return sanitize_output(redact(str(text), otp_context=otp_context))


def redact(text: str, *, otp_context: str | None = None) -> str:
    """Pure function, unit-tested in isolation. See the module-level
    comment above for exactly what is -- and deliberately isn't -- removed.

    `otp_context`: a caller that redacts a PAIR of related fields
    separately (a Gmail subject and its snippet, an event title and its
    location) should pass the combined text of both here, so a one-time
    code split across the two fields (the context word "code" in the
    subject, the bare digits in the snippet) is still caught -- checking
    each field for the context word in isolation would miss it. Defaults
    to `text` itself when the caller has no wider context to offer."""
    text = _PASSWORD_RE.sub(_redact_password, text)
    text = _CARD_CANDIDATE_RE.sub(_redact_card, text)
    if _OTP_CONTEXT_RE.search(otp_context if otp_context is not None else text):
        text = _OTP_RE.sub(_REDACTED, text)
    return text


def _format_event_title_location(summary: str, location: str, *, is_withheld: bool) -> tuple[str, str]:
    """Shared by the create_event/update_event reply branches, which used
    to repeat this exact withheld-check / quote / redact sequence with
    only the event variable's name differing. Title and location are
    redacted together (`otp_context`) so a one-time code split across the
    two fields -- e.g. a context word in the title, bare digits in the
    location -- isn't missed the way redacting each field in isolation
    would miss it."""
    if is_withheld:
        return WITHHELD_TEXT, ""
    combined = f"{summary} {location}"
    title = f"'{safe_display(summary, otp_context=combined) or '(no title)'}'"
    location_suffix = f", at {safe_display(location, otp_context=combined)}" if location else ""
    return title, location_suffix


def render_reply(
    parsed_request: ParsedRequest,
    status: str,
    error_code: str | None,
    gmail_results: list[GmailResult] | None = None,
    calendar_results: list[CalendarEvent] | None = None,
    calendar_window_label: str | None = None,
    clarification_question: str | None = None,
    draft_result: DraftResult | None = None,
    created_event: CalendarEvent | None = None,
    updated_event: CalendarEvent | None = None,
    deleted_event_id: str | None = None,
    drive_file_result: DriveFileResult | None = None,
    capabilities: CapabilitiesInfo | None = None,
    retryable: bool = False,
    detail: str | None = None,
    output: OutputScreenResult | None = None,
    ignored_params: tuple[str, ...] = (),
    requests_remaining_today: int | None = None,
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
        + (1 if capabilities else 0)
    )
    prose_lines: list[str] = []
    # Set only by the two branches below that render one line per result
    # item -- lets the size-cap truncation at the end report "showing N
    # of M" instead of a blind character cut (see _status_block's sibling
    # truncation logic further down).
    item_lines_start: int | None = None
    item_lines_total: int | None = None

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
        when_label = f" for {calendar_window_label}" if calendar_window_label else ""
        if calendar_results:
            prose_lines.append(f"Found {len(calendar_results)} event(s){when_label}:")
            item_lines_start = len(prose_lines)
            item_lines_total = len(calendar_results)
            for i, e in enumerate(calendar_results):
                # The time comes from Google's structured start/end, never free
                # text, so it's kept even when the item's text is withheld.
                when = format_event_range(e.start, e.end, e.all_day, OWNER_TIMEZONE)
                event_id = f"(event_id: {sanitize_output(e.event_id)})"
                if withheld(event_key(i)):
                    prose_lines.append(f"- {WITHHELD_TEXT} — {when} {event_id}")
                    continue
                combined = f"{e.summary} {e.location}"
                title = safe_display(e.summary, otp_context=combined) or "(no title)"
                location = f", at {safe_display(e.location, otp_context=combined)}" if e.location else ""
                attendees = f", {e.attendee_count} attendee(s)" if e.attendee_count else ""
                prose_lines.append(f"- {title} — {when}{location}{attendees} {event_id}")
        else:
            prose_lines.append(f"No events found{when_label}.")
    elif status == "completed" and parsed_request.verb == "calendar.create_event" and created_event:
        # Title and location are screened as ONE item (app/pipeline.py's
        # _output_items), so a flagged event hides both together rather
        # than exposing whichever field wasn't the sensitive one.
        title, location = _format_event_title_location(
            created_event.summary, created_event.location, is_withheld=withheld(CREATED_EVENT_KEY)
        )
        when = format_event_range(created_event.start, created_event.end, created_event.all_day, OWNER_TIMEZONE)
        attendees = f", invited {created_event.attendee_count} attendee(s)" if created_event.attendee_count else ""
        prose_lines.append(f"Created event {title} — {when}{location}{attendees} (event_id: {sanitize_output(created_event.event_id)}).")
    elif status == "completed" and parsed_request.verb == "calendar.update_event" and updated_event:
        title, location = _format_event_title_location(
            updated_event.summary, updated_event.location, is_withheld=withheld(UPDATED_EVENT_KEY)
        )
        when = format_event_range(updated_event.start, updated_event.end, updated_event.all_day, OWNER_TIMEZONE)
        attendees = f", {updated_event.attendee_count} attendee(s)" if updated_event.attendee_count else ""
        prose_lines.append(f"Updated event {title} — {when}{location}{attendees} (event_id: {sanitize_output(updated_event.event_id)}).")
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
    elif status == "completed" and parsed_request.verb == "capabilities" and capabilities is not None:
        # Nothing here originates from Google or the requester, so none of
        # it needs safe_display/redaction -- see app/capabilities.py.
        prose_lines.append(f"Capabilities (protocol_version {sanitize_output(capabilities.protocol_version)}):")
        for v in capabilities.verbs:
            kind = "write" if v.is_write else "read"
            prose_lines.append(f"- {sanitize_output(v.verb)} ({kind})")
            for bound in v.param_bounds:
                prose_lines.append(f"    {sanitize_output(bound)}")
        prose_lines.append(
            f"Daily quota: {capabilities.max_requests_per_day} requests. "
            f"batch accepts up to {capabilities.batch_max_items} items."
        )
    elif status == "completed":
        results = gmail_results or []
        if results:
            prose_lines.append(f"Found {len(results)} matching email(s):")
            item_lines_start = len(prose_lines)
            item_lines_total = len(results)
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
                # Subject and snippet are redacted separately but share one
                # OTP context check, so a code split across the two (the
                # word "code" in the subject, the bare digits in the
                # snippet) isn't missed the way checking each in isolation
                # would miss it.
                combined = f"{r.subject} {r.snippet}"
                subject = safe_display(r.subject, otp_context=combined) or "(no subject)"
                snippet = safe_display(r.snippet, otp_context=combined)
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
        requests_remaining_today=requests_remaining_today,
    )
    body = f"{prose}\n\n---GATEKEEPER-RESPONSE---\n{yaml_block}\n---END---\n"

    if len(body) > REPLY_MAX_CHARS:
        # Truncate the prose, never the machine-readable block -- a
        # parser (or a human skimming) must always be able to find an
        # intact status block even in a capped reply. `available` is the
        # character budget for the prose itself (the block/markers never
        # shrink, so whatever they cost is subtracted out first).
        available = REPLY_MAX_CHARS - (len(body) - len(prose))
        if item_lines_start is not None and item_lines_total is not None:
            # A per-item list (gmail.search / calendar.list_events):
            # truncate at the last COMPLETE item boundary rather than
            # mid-item, and report how many of the total actually made it
            # in -- a blind character cut left result_count claiming the
            # full count while the visible list silently fell short of it.
            item_lines_end = item_lines_start + item_lines_total
            head_lines = prose_lines[:item_lines_start]
            item_lines = prose_lines[item_lines_start:item_lines_end]
            tail_lines = prose_lines[item_lines_end:]
            head = "\n".join(head_lines)
            tail = ("\n" + "\n".join(tail_lines)) if tail_lines else ""
            # Reserve room for the largest this suffix could ever be
            # (shown can't have more digits than total).
            suffix_budget = available - len(f"\n\n[showing {item_lines_total} of {item_lines_total}]") - len(tail)
            used = len(head)
            kept_items: list[str] = []
            for line in item_lines:
                cost = len(line) + 1  # the newline joining it to what came before
                if used + cost > suffix_budget:
                    break
                used += cost
                kept_items.append(line)
            shown = len(kept_items)
            new_prose = "\n".join([*head_lines, *kept_items])
            suffix = f"\n\n[showing {shown} of {item_lines_total}]{tail}"
            body = f"{new_prose}{suffix}\n\n---GATEKEEPER-RESPONSE---\n{yaml_block}\n---END---\n"
        else:
            suffix = "\n\n[truncated]"
            keep = max(0, available - len(suffix))
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
    requests_remaining_today: int | None = None,
) -> str:
    block: dict = {
        # First key, deliberately: a protocol-level fact about which
        # revision answered, not a per-request one (Instinct's review,
        # M1) -- lets Instinct tell old vs. new protocol apart during a
        # deploy transition instead of guessing from which fields appear.
        "protocol_version": GIT_SHA,
        "request_id": sanitize_output(request_id),
        "status": sanitize_output(status),
        "error_code": sanitize_output(error_code) if error_code is not None else None,
        "retryable": retryable,
        "result_count": result_count,
        "withheld_count": output.withheld_count if output is not None else 0,
    }
    if requests_remaining_today is not None:
        # Omitted (rather than a placeholder) when the count itself
        # couldn't be read (state_store.count_today failed) -- the
        # requester should never be told a specific number that might be
        # wrong (Instinct's review, M6: nearly free since count_today is
        # already computed for the rate-cap check).
        block["requests_remaining_today"] = requests_remaining_today
    if output is not None:
        # Only present when there was result content to screen:
        # ok | degraded (some items unscreenable, withheld) | disabled (no screen configured).
        # ("off" would be a YAML boolean -- a naive parser would read False.)
        block["screen"] = output.status
    if ignored_params:
        block["ignored_params"] = list(ignored_params)
    return yaml.safe_dump(block, sort_keys=False, default_flow_style=False).strip()


def render_minimal_reply(
    request_id: str, status: str, error_code: str | None, retryable: bool,
    requests_remaining_today: int | None = None,
) -> str:
    """Fallback used only if render_reply itself raises: no result content
    at all, just the machine-readable status block, so the requester still
    learns what happened to its request."""
    yaml_block = _status_block(
        request_id, status, error_code, 0, retryable, requests_remaining_today=requests_remaining_today
    )
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
