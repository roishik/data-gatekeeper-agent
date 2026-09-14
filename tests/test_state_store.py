"""Layer 1 tests: idempotency (message id and request id) and the daily
request cap, against InMemoryStateStore -- the same Protocol prod's
SheetsStateStore implements."""
from __future__ import annotations

from datetime import date

from app.state_store import InMemoryStateStore


def test_message_dedupe():
    store = InMemoryStateStore()
    assert not store.is_duplicate_message("msg_1")
    store.mark_message_seen("msg_1")
    assert store.is_duplicate_message("msg_1")
    assert not store.is_duplicate_message("msg_2")


def test_request_dedupe():
    store = InMemoryStateStore()
    assert not store.is_duplicate_request("req_1")
    store.mark_request_seen("req_1")
    assert store.is_duplicate_request("req_1")
    assert not store.is_duplicate_request("req_2")


def test_daily_cap_counts_per_sender_per_day():
    store = InMemoryStateStore()
    today = date(2026, 9, 14)
    assert store.count_today("a@example.com", today) == 0
    store.record_request("a@example.com", today)
    store.record_request("a@example.com", today)
    assert store.count_today("a@example.com", today) == 2
    # A different sender's count is independent.
    assert store.count_today("b@example.com", today) == 0
    # A different day is independent too.
    assert store.count_today("a@example.com", date(2026, 9, 15)) == 0
