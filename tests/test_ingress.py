"""Layer 0 tests: signature verification, sender allowlist (incl. a
spoofed display name), loop prevention, and event/inbox filtering."""
from __future__ import annotations

import time

from app.ingress import check_event, parsed_sender_address, verify_signature
from tests.webhook_helpers import TEST_WEBHOOK_SECRET, sign


def test_valid_signature_is_accepted():
    body = b'{"hello": "world"}'
    svix_id, ts, sig = sign(body)
    verdict = verify_signature(body, svix_id, ts, sig, secret=TEST_WEBHOOK_SECRET)
    assert verdict.accepted
    assert verdict.reason == "ok"


def test_invalid_signature_is_rejected():
    body = b'{"hello": "world"}'
    svix_id, ts, _ = sign(body)
    verdict = verify_signature(body, svix_id, ts, "v1,not-a-real-signature", secret=TEST_WEBHOOK_SECRET)
    assert not verdict.accepted
    assert verdict.reason == "signature_mismatch"


def test_signature_computed_over_wrong_body_is_rejected():
    """A signature valid for one body must not validate a different
    (e.g. tampered-in-transit) body."""
    original = b'{"hello": "world"}'
    tampered = b'{"hello": "world!!"}'
    svix_id, ts, sig = sign(original)
    verdict = verify_signature(tampered, svix_id, ts, sig, secret=TEST_WEBHOOK_SECRET)
    assert not verdict.accepted
    assert verdict.reason == "signature_mismatch"


def test_stale_timestamp_is_rejected():
    body = b'{"hello": "world"}'
    old_timestamp = time.time() - 3600  # 1 hour ago, well past the default 300s tolerance
    svix_id, ts, sig = sign(body, timestamp=old_timestamp)
    verdict = verify_signature(body, svix_id, ts, sig, secret=TEST_WEBHOOK_SECRET, tolerance_seconds=300)
    assert not verdict.accepted
    assert verdict.reason == "stale_timestamp"


def test_missing_signature_headers_is_rejected():
    body = b'{"hello": "world"}'
    verdict = verify_signature(body, "", "", "", secret=TEST_WEBHOOK_SECRET)
    assert not verdict.accepted
    assert verdict.reason == "missing_signature_headers"


def test_no_secret_configured_is_rejected():
    body = b'{"hello": "world"}'
    svix_id, ts, sig = sign(body)
    verdict = verify_signature(body, svix_id, ts, sig, secret="")
    assert not verdict.accepted
    assert verdict.reason == "no_webhook_secret_configured"


def test_check_event_accepts_valid_event():
    verdict = check_event(
        event_type="message.received",
        inbox_id="inbox_1",
        sender_header="Instinct <instinct@example.com>",
        configured_inbox_id="inbox_1",
        allowed_senders=("instinct@example.com",),
        gatekeeper_address="gatekeeper@example.com",
    )
    assert verdict.accepted


def test_check_event_ignores_non_message_received_event():
    verdict = check_event(
        event_type="message.sent",
        inbox_id="inbox_1",
        sender_header="instinct@example.com",
        configured_inbox_id="inbox_1",
        allowed_senders=("instinct@example.com",),
        gatekeeper_address="gatekeeper@example.com",
    )
    assert not verdict.accepted
    assert verdict.reason.startswith("ignored_event_type")


def test_check_event_rejects_wrong_inbox():
    verdict = check_event(
        event_type="message.received",
        inbox_id="some_other_inbox",
        sender_header="instinct@example.com",
        configured_inbox_id="inbox_1",
        allowed_senders=("instinct@example.com",),
        gatekeeper_address="gatekeeper@example.com",
    )
    assert not verdict.accepted
    assert verdict.reason == "wrong_inbox"


def test_check_event_rejects_non_allowlisted_sender():
    verdict = check_event(
        event_type="message.received",
        inbox_id="inbox_1",
        sender_header="attacker@evil.com",
        configured_inbox_id="inbox_1",
        allowed_senders=("instinct@example.com",),
        gatekeeper_address="gatekeeper@example.com",
    )
    assert not verdict.accepted
    assert verdict.reason == "sender_not_allowlisted"


def test_check_event_rejects_spoofed_display_name():
    """A display name that SAYS the right thing must not fool the
    allowlist -- only the actual address is checked."""
    spoofed = '"instinct@example.com" <attacker@evil.com>'
    assert parsed_sender_address(spoofed) == "attacker@evil.com"

    verdict = check_event(
        event_type="message.received",
        inbox_id="inbox_1",
        sender_header=spoofed,
        configured_inbox_id="inbox_1",
        allowed_senders=("instinct@example.com",),
        gatekeeper_address="gatekeeper@example.com",
    )
    assert not verdict.accepted
    assert verdict.reason == "sender_not_allowlisted"


def test_check_event_rejects_loop_from_own_inbox():
    """Even if the gatekeeper's own address were accidentally also on
    the allowlist (a misconfiguration), loop prevention must still win
    -- defense in depth, tested directly rather than assumed."""
    verdict = check_event(
        event_type="message.received",
        inbox_id="inbox_1",
        sender_header="gatekeeper@example.com",
        configured_inbox_id="inbox_1",
        allowed_senders=("instinct@example.com", "gatekeeper@example.com"),
        gatekeeper_address="gatekeeper@example.com",
    )
    assert not verdict.accepted
    assert verdict.reason == "loop_own_inbox"


def test_parsed_sender_address_strips_display_name():
    assert parsed_sender_address("Instinct <Instinct@Example.com>") == "instinct@example.com"
