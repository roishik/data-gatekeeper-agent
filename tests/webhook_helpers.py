"""
webhook_helpers.py — build correctly (and incorrectly) signed webhook
requests for tests, using the SAME HMAC construction as
app/ingress.py's verify_signature, so a test failure means the code
under test is wrong, not that the fixture disagrees with it.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import time
from base64 import b64decode, b64encode
from typing import Any

TEST_WEBHOOK_SECRET = "whsec_" + b64encode(b"0123456789abcdef0123456789abcdef").decode()


def sign(
    body: bytes,
    secret: str = TEST_WEBHOOK_SECRET,
    svix_id: str = "msg_test_1",
    timestamp: float | None = None,
) -> tuple[str, str, str]:
    """Returns (svix_id, svix_timestamp, svix_signature) for `body`,
    correctly signed with `secret` at `timestamp` (default: now)."""
    ts = str(int(timestamp if timestamp is not None else time.time()))
    secret_bytes = b64decode(secret[len("whsec_") :] if secret.startswith("whsec_") else secret)
    signed_content = f"{svix_id}.{ts}.".encode() + body
    sig = b64encode(hmac.new(secret_bytes, signed_content, hashlib.sha256).digest()).decode()
    return svix_id, ts, f"v1,{sig}"


def make_payload(
    sender: str = "instinct@example.com",
    inbox_id: str = "inbox_1",
    message_id: str = "msg_1",
    text: str = "hello",
    subject: str = "Re: gatekeeper",
    event_type: str = "message.received",
) -> dict[str, Any]:
    return {
        "event_type": event_type,
        "message": {
            "message_id": message_id,
            "inbox_id": inbox_id,
            "from": sender,
            "subject": subject,
            "text": text,
        },
    }


def make_body(**kwargs: Any) -> bytes:
    return json.dumps(make_payload(**kwargs)).encode()
