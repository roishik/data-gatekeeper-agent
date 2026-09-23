"""
ingress.py — Layer 0: the mail gate.

Everything here runs BEFORE any parsed request, any LLM call, or any
Google/AgentMail API call exists. Its only job is deciding, as cheaply
and deterministically as possible, whether an inbound webhook POST is
even worth looking at further:

  1. Verify the AgentMail/Svix webhook signature over the RAW body, and
     reject a stale timestamp (verify_signature). A manual HMAC check
     per the Standard Webhooks spec -- which is what AgentMail's docs
     say they implement (svix-id / svix-timestamp / svix-signature
     headers) -- rather than a dependency on the `svix` package: one
     fewer moving part, and it's fully testable offline (a test computes
     a matching signature with the same HMAC construction).
  2. Only accept a "message.received" event for OUR configured inbox
     (check_event).
  3. Sender allowlist: an EXACT match on the parsed address, display
     name stripped and ignored -- `"Instinct" <attacker@evil.com>` does
     NOT match just because the display name says "Instinct".
  4. Loop prevention: reject anything claiming to be FROM our own inbox
     address, so a misconfigured auto-reply chain can't feed the
     pipeline its own output forever.

A rejected event is logged by the caller (app/pipeline.py) but NEVER
answered -- replying to an unauthenticated sender would confirm the
gatekeeper's address is live and watching, which is the opposite of what
a rejection is for.
"""
from __future__ import annotations

import binascii
import email.utils
import hashlib
import hmac
import time
from base64 import b64decode, b64encode
from dataclasses import dataclass

from app.config import (
    AGENTMAIL_INBOX_ID,
    AGENTMAIL_WEBHOOK_SECRET,
    ALLOWED_SENDERS,
    GATEKEEPER_INBOX_ADDRESS,
    WEBHOOK_TOLERANCE_SECONDS,
)

# AgentMail's docs (fetched during the original build, raw markdown, not
# just an AI-summarized pass) confirm `event_type`
# is dot-notation and that "message.received" has three siblings this
# service must NOT treat as a normal inbound request:
# "message.received.spam", "message.received.blocked",
# "message.received.unauthenticated". Only the exact base value is
# accepted; the siblings fall through to "ignored_event_type:..." below
# like any other unrecognized type, which is the correct behavior for
# mail AgentMail itself already flagged as spam/blocked/unauthenticated.
_ACCEPTED_EVENT_TYPES = frozenset({"message.received"})


@dataclass(frozen=True)
class Verdict:
    accepted: bool
    reason: str  # short, machine-readable, always set; "ok" when accepted


def verify_signature(
    body: bytes,
    svix_id: str,
    svix_timestamp: str,
    svix_signature: str,
    secret: str | None = None,
    now: float | None = None,
    tolerance_seconds: int | None = None,
) -> Verdict:
    """Standard Webhooks signature check: HMAC-SHA256 over
    `"{id}.{timestamp}.".encode() + body`, using the base64-decoded
    secret (after stripping the "whsec_" prefix AgentMail's secrets are
    issued with), compared against every `v1,<base64>` entry in
    svix-signature (space-delimited -- AgentMail can present more than
    one valid signature during a secret-rotation window; matching ANY of
    them is correct, not just the first).

    Also rejects a timestamp outside +/- tolerance_seconds: a signature
    alone never expires on its own, so this is the replay-window half of
    the check, done unconditionally even when the signature is valid.

    A misconfigured AGENTMAIL_WEBHOOK_SECRET that isn't valid base64
    returns a clean denial rather than letting binascii.Error escape --
    every webhook used to become a 500 (and an AgentMail retry storm)
    instead of a rejection until this was caught."""
    secret = secret if secret is not None else (AGENTMAIL_WEBHOOK_SECRET or "")
    tolerance = tolerance_seconds if tolerance_seconds is not None else WEBHOOK_TOLERANCE_SECONDS

    if not secret:
        return Verdict(False, "no_webhook_secret_configured")
    if not (svix_id and svix_timestamp and svix_signature):
        return Verdict(False, "missing_signature_headers")

    try:
        ts = int(svix_timestamp)
    except ValueError:
        return Verdict(False, "invalid_timestamp")

    current = now if now is not None else time.time()
    if abs(current - ts) > tolerance:
        return Verdict(False, "stale_timestamp")

    try:
        secret_bytes = b64decode(secret[len("whsec_"):] if secret.startswith("whsec_") else secret, validate=True)
    except (binascii.Error, ValueError):
        return Verdict(False, "invalid_webhook_secret")
    signed_content = f"{svix_id}.{svix_timestamp}.".encode() + body
    expected = b64encode(hmac.new(secret_bytes, signed_content, hashlib.sha256).digest()).decode()

    for candidate in svix_signature.split():
        _, _, sig_b64 = candidate.partition(",")
        if sig_b64 and hmac.compare_digest(sig_b64, expected):
            return Verdict(True, "ok")
    return Verdict(False, "signature_mismatch")


def check_event(
    event_type: str,
    inbox_id: str,
    sender_header: str,
    configured_inbox_id: str | None = None,
    allowed_senders: tuple[str, ...] | None = None,
    gatekeeper_address: str | None = None,
) -> Verdict:
    """Everything after signature verification: event type, inbox id,
    loop prevention, sender allowlist. Split from verify_signature() so
    each check has one job and one obvious, loggable failure reason."""
    configured_inbox_id = configured_inbox_id if configured_inbox_id is not None else (AGENTMAIL_INBOX_ID or "")
    allowed_senders = allowed_senders if allowed_senders is not None else tuple(ALLOWED_SENDERS)
    gatekeeper_address = gatekeeper_address if gatekeeper_address is not None else (GATEKEEPER_INBOX_ADDRESS or "")

    if event_type not in _ACCEPTED_EVENT_TYPES:
        return Verdict(False, f"ignored_event_type:{event_type}")
    if inbox_id != configured_inbox_id:
        return Verdict(False, "wrong_inbox")

    sender_address = parsed_sender_address(sender_header)
    if not sender_address:
        return Verdict(False, "unparseable_sender")

    # Loop prevention BEFORE the allowlist check: our own address should
    # never be on the allowlist, but checking loop first makes that
    # invariant explicit rather than incidental.
    if gatekeeper_address and sender_address == gatekeeper_address.lower().strip():
        return Verdict(False, "loop_own_inbox")

    allowed = {a.lower().strip() for a in allowed_senders}
    if sender_address not in allowed:
        return Verdict(False, "sender_not_allowlisted")

    return Verdict(True, "ok")


def parsed_sender_address(sender_header: str) -> str:
    """Exact address only, display name discarded -- the single source
    of truth for "who sent this", used by every later layer (rate
    limiting, and the reply guard's "reply only to the verified
    sender"). Built on email.utils.parseaddr (stdlib, RFC 2822 aware)
    rather than a hand-rolled regex, specifically so a crafted display
    name like `"a@allowed.com" <attacker@evil.com>` is parsed the way a
    real mail client would parse it, not the way a naive `"<" in header`
    check might be fooled into reading it."""
    _, address = email.utils.parseaddr(sender_header)
    return address.lower().strip()
