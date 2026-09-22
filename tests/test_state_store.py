"""Layer 1 tests: message dedupe, request status, and the daily cap --
against InMemoryStateStore AND SheetsStateStore (with a recording fake
Sheets service; tests/test_sheets_live.py covers the real API).

The SheetsStateStore tests exist because of the 2026-09-19 production bug
(see app/state_store.py's module docstring): rows starting with a blank
cell made Sheets shift every later append one column right, silently
breaking request dedupe and the daily cap. The recording fake can't
reproduce Sheets' table detection itself, but it can enforce the rule that
prevents it -- every appended row starts with a non-empty key -- across a
full request lifecycle."""
from __future__ import annotations

from datetime import date, datetime, timezone

import pytest

from app.state_store import (
    REQUEST_COMPLETED,
    REQUEST_EFFECT_DONE,
    REQUEST_FAILED,
    REQUEST_PROCESSING,
    InMemoryStateStore,
    SheetsStateStore,
    is_duplicate_request_status,
    owner_today,
)


class _Exec:
    def __init__(self, fn):
        self._fn = fn

    def execute(self):
        return self._fn()


class FakeSheetsService:
    """Just enough of spreadsheets() / spreadsheets().values() for
    SheetsStateStore. Rows are stored A-aligned (the naive reading the
    store relies on); every append is recorded for invariant checks."""

    def __init__(self, tabs: dict[str, list[list[str]]] | None = None):
        self.tabs: dict[str, list[list[str]]] = {k: [list(r) for r in v] for k, v in (tabs or {}).items()}
        self.appended: list[tuple[str, list[str]]] = []
        self.created = False

    # spreadsheets()
    def spreadsheets(self):
        return self

    def values(self):
        return _Values(self)

    def create(self, body, fields=None):
        def _do():
            self.created = True
            for sheet in body["sheets"]:
                self.tabs.setdefault(sheet["properties"]["title"], [])
            return {"spreadsheetId": "sheet_new"}
        return _Exec(_do)

    def get(self, spreadsheetId, fields=None):
        return _Exec(lambda: {"sheets": [{"properties": {"title": t}} for t in self.tabs]})

    def batchUpdate(self, spreadsheetId, body):
        def _do():
            for req in body["requests"]:
                self.tabs.setdefault(req["addSheet"]["properties"]["title"], [])
            return {}
        return _Exec(_do)


class _Values:
    def __init__(self, svc: FakeSheetsService):
        self._svc = svc

    @staticmethod
    def _tab(a1_range: str) -> str:
        return a1_range.split("!", 1)[0]

    def get(self, spreadsheetId, range):
        return _Exec(lambda: {"values": [list(r) for r in self._svc.tabs.get(self._tab(range), [])]})

    def append(self, spreadsheetId, range, valueInputOption, insertDataOption, body):
        def _do():
            assert valueInputOption == "RAW"  # never USER_ENTERED: no formula evaluation of request data
            tab = self._tab(range)
            for row in body["values"]:
                self._svc.tabs.setdefault(tab, []).append(list(row))
                self._svc.appended.append((tab, list(row)))
            return {}
        return _Exec(_do)


# ── InMemoryStateStore ──────────────────────────────────────────────────


def test_message_dedupe():
    store = InMemoryStateStore()
    assert not store.is_duplicate_message("msg_1")
    store.mark_message_seen("msg_1")
    assert store.is_duplicate_message("msg_1")
    assert not store.is_duplicate_message("msg_2")


def test_request_status_lifecycle():
    store = InMemoryStateStore()
    assert store.get_request_status("req_1") is None
    store.set_request_status("req_1", REQUEST_PROCESSING)
    assert store.get_request_status("req_1") == REQUEST_PROCESSING
    store.set_request_status("req_1", REQUEST_COMPLETED)
    assert store.get_request_status("req_1") == REQUEST_COMPLETED
    assert store.get_request_status("req_2") is None


def test_only_failed_requests_may_be_resent():
    assert not is_duplicate_request_status(None)
    assert not is_duplicate_request_status(REQUEST_FAILED)
    for status in (REQUEST_PROCESSING, REQUEST_EFFECT_DONE, REQUEST_COMPLETED):
        assert is_duplicate_request_status(status)


def test_daily_cap_counts_per_sender_per_day():
    store = InMemoryStateStore()
    today = date(2026, 9, 14)
    assert store.count_today("a@example.com", today) == 0
    store.record_request("a@example.com", "req_1", today)
    store.record_request("a@example.com", "req_2", today)
    assert store.count_today("a@example.com", today) == 2
    # A different sender's count is independent.
    assert store.count_today("b@example.com", today) == 0
    # A different day is independent too.
    assert store.count_today("a@example.com", date(2026, 9, 15)) == 0


def test_owner_today_uses_owner_timezone_not_utc():
    # 22:30 UTC on Sep 21 is already 01:30 on Sep 22 in Asia/Jerusalem (UTC+3).
    late_utc = datetime(2026, 9, 21, 22, 30, tzinfo=timezone.utc)
    assert owner_today(late_utc) == date(2026, 9, 22)


# ── SheetsStateStore (recording fake service) ───────────────────────────


def _full_lifecycle(store) -> None:
    store.mark_message_seen("msg_1")
    store.set_request_status("req_1", REQUEST_PROCESSING, "a@example.com")
    store.record_request("a@example.com", "req_1", date(2026, 9, 22))
    store.set_request_status("req_1", REQUEST_EFFECT_DONE, "a@example.com")
    store.set_request_status("req_1", REQUEST_COMPLETED, "a@example.com")
    store.mark_message_seen("msg_2")
    store.set_request_status("req_2", REQUEST_PROCESSING)  # sender optional
    store.record_request("a@example.com", "req_2", date(2026, 9, 22))
    store.set_request_status("req_2", REQUEST_FAILED)


def test_sheets_every_appended_row_starts_with_a_non_empty_key():
    svc = FakeSheetsService()
    store = SheetsStateStore(spreadsheet_id="sheet_1", service=svc)
    _full_lifecycle(store)
    assert svc.appended, "lifecycle should have appended rows"
    for tab, row in svc.appended:
        assert row and str(row[0]).strip(), f"blank first cell appended to {tab}: {row}"


def test_sheets_append_refuses_a_blank_first_cell():
    store = SheetsStateStore(spreadsheet_id="sheet_1", service=FakeSheetsService())
    with pytest.raises(ValueError):
        store._append("daily_counts", "C", ["", "a@example.com", "2026-09-22"])
    with pytest.raises(ValueError):
        store.set_request_status("", REQUEST_PROCESSING)


def test_sheets_round_trip_dedupe_status_and_count():
    store = SheetsStateStore(spreadsheet_id="sheet_1", service=FakeSheetsService())
    _full_lifecycle(store)
    assert store.is_duplicate_message("msg_1") and store.is_duplicate_message("msg_2")
    assert not store.is_duplicate_message("msg_3")
    # Append-only: the LAST status row for an id wins.
    assert store.get_request_status("req_1") == REQUEST_COMPLETED
    assert store.get_request_status("req_2") == REQUEST_FAILED
    assert store.get_request_status("req_3") is None
    assert store.count_today("a@example.com", date(2026, 9, 22)) == 2
    assert store.count_today("a@example.com", date(2026, 9, 23)) == 0
    assert store.count_today("b@example.com", date(2026, 9, 22)) == 0


def test_sheets_upgrades_an_existing_spreadsheet_in_place_and_ignores_legacy_tab():
    # The shape of the real prod state sheet on 2026-09-19: single-column
    # message rows, and a legacy `requests` tab with misaligned rows.
    svc = FakeSheetsService(tabs={
        "messages": [["<old-1@mail.gmail.com>"], ["<old-2@mail.gmail.com>"]],
        "requests": [["", "req-b83cbe400299"], ["", "", "roishikler@mail.instinct.com", "2026-09-15"]],
    })
    store = SheetsStateStore(spreadsheet_id="sheet_prod", service=svc)
    assert {"request_status", "daily_counts"} <= set(svc.tabs), "missing tabs should be added"
    assert not svc.created, "an existing spreadsheet must never be recreated"
    # Old single-column message rows still dedupe.
    assert store.is_duplicate_message("<old-1@mail.gmail.com>")
    # Nothing in the legacy tab is ever read as state.
    assert store.get_request_status("req-b83cbe400299") is None
    assert store.count_today("roishikler@mail.instinct.com", date(2026, 9, 15)) == 0


def test_sheets_creates_a_spreadsheet_with_all_tabs_when_unpinned():
    svc = FakeSheetsService()
    store = SheetsStateStore(spreadsheet_id=None, service=svc)
    assert svc.created and store.spreadsheet_id == "sheet_new"
    assert {"messages", "request_status", "daily_counts"} <= set(svc.tabs)
