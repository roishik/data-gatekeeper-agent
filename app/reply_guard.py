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
     field to write a different recipient into.
  2. Gmail result text (subject, snippet, sender) and Calendar result
     text (event summary, location) are redacted for OTP-like codes,
     URLs, and email-verification phrasing BEFORE they can appear in a
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
result_count -- research/05 section 2's "Design C" hybrid protocol.
"""
from __future__ import annotations

import re

import yaml

from app.agentmail_client import AgentMailClient, ReplyResult
from app.calendar_executor import CalendarEvent
from app.calendar_window import format_event_range
from app.config import OWNER_TIMEZONE, REPLY_MAX_CHARS
from app.gmail_executor import GmailResult
from app.request_parser import ParsedRequest

_REDACTED = "[redacted]"

# Deliberately aggressive: over-redacting a price or a year in a subject
# line costs nothing; under-redacting an OTP costs a lot (see module
# docstring point 2). Order matters -- URLs first, so a URL containing a
# digit run isn't partially mangled by _OTP_RE before _URL_RE gets to it.
_URL_RE = re.compile(r"https?://\S+", re.I)
_OTP_RE = re.compile(r"\b\d{4,8}\b")
_VERIFICATION_PHRASE_RE = re.compile(
    r"(verification code|verify your (email|account|identity)|confirm your (email|account)"
    r"|one[- ]?time (code|password)|security code|login code|sign-?in code|password reset)",
    re.I,
)


def redact(text: str) -> str:
    """Pure function, unit-tested in isolation."""
    text = _URL_RE.sub(_REDACTED, text)
    text = _OTP_RE.sub(_REDACTED, text)
    text = _VERIFICATION_PHRASE_RE.sub(_REDACTED, text)
    return text


def render_reply(
    parsed_request: ParsedRequest,
    status: str,
    error_code: str | None,
    gmail_results: list[GmailResult] | None = None,
    calendar_results: list[CalendarEvent] | None = None,
    clarification_question: str | None = None,
) -> str:
    """Builds the full reply body. Deliberately takes no recipient
    argument at all -- see module docstring point 1. Exactly one of
    `gmail_results`/`calendar_results` is populated per call in
    practice (app/pipeline.py only ever executes one verb per request),
    but both are accepted independently rather than a single ambiguous
    "results" blob, so a caller can't accidentally hand a Gmail result
    to the calendar formatter or vice versa."""
    result_count = len(gmail_results or []) + len(calendar_results or [])
    prose_lines: list[str] = []

    if error_code == "rate_limited":
        prose_lines.append("You've hit today's request limit for this inbox. Please try again tomorrow.")
    elif status == "completed" and parsed_request.verb == "calendar.list_events":
        if calendar_results:
            prose_lines.append(f"Found {len(calendar_results)} event(s):")
            for e in calendar_results:
                title = redact(e.summary) or "(no title)"
                when = format_event_range(e.start, e.end, e.all_day, OWNER_TIMEZONE)
                location = f", at {redact(e.location)}" if e.location else ""
                attendees = f", {e.attendee_count} attendee(s)" if e.attendee_count else ""
                prose_lines.append(f"- {title} — {when}{location}{attendees}")
        else:
            prose_lines.append("No events found.")
    elif status == "completed":
        results = gmail_results or []
        if results:
            prose_lines.append(f"Found {len(results)} matching email(s):")
            for r in results:
                subject = redact(r.subject) or "(no subject)"
                snippet = redact(r.snippet)
                # The sender header is attacker-controlled too (display names can carry
                # URLs or instructions), so it goes through the same redaction.
                prose_lines.append(f"- {subject} — {redact(r.sender)} ({r.date})\n  {snippet}")
        else:
            prose_lines.append("No matching emails found.")
    elif status == "needs_clarification":
        prose_lines.append(clarification_question or "Could you clarify this request?")
    elif status == "not_implemented":
        prose_lines.append(f"'{parsed_request.verb}' is a recognized request type but isn't implemented yet.")
    elif status == "denied":
        if error_code == "sensitive_query_refused":
            prose_lines.append(
                "This request was refused: it looks like it's asking about a verification code, "
                "password reset, or similarly sensitive content, which this gatekeeper never forwards."
            )
        else:
            prose_lines.append("This request was not authorized.")
    else:  # "unsupported" or any other/unknown status
        prose_lines.append("This request could not be understood or completed.")

    prose = "\n".join(prose_lines)

    block = {
        "request_id": parsed_request.request_id,
        "status": status,
        "error_code": error_code,
        "result_count": result_count,
    }
    yaml_block = yaml.safe_dump(block, sort_keys=False, default_flow_style=False).strip()
    body = f"{prose}\n\n---GATEKEEPER-RESPONSE---\n{yaml_block}\n---END---\n"

    if len(body) > REPLY_MAX_CHARS:
        # Truncate the prose, never the machine-readable block -- a
        # parser (or a human skimming) must always be able to find an
        # intact status block even in a capped reply.
        suffix = "\n\n[truncated]"
        keep = max(0, REPLY_MAX_CHARS - len(body) + len(prose) - len(suffix))
        body = f"{prose[:keep]}{suffix}\n\n---GATEKEEPER-RESPONSE---\n{yaml_block}\n---END---\n"

    return body


def send_reply(
    agentmail_client: AgentMailClient,
    inbox_id: str,
    agentmail_message_id: str,
    sender_address: str,
    bcc_address: str,
    body: str,
) -> ReplyResult:
    return agentmail_client.reply(
        inbox_id=inbox_id, message_id=agentmail_message_id, to=sender_address, bcc=bcc_address, text=body
    )
