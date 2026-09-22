"""
test_sheets_live.py — contract tests for SheetsStateStore and SheetsAuditLog
against the REAL Google Sheets API.

Why these exist: from launch until 2026-09-19 the prod state sheet's rate
cap and request-id dedupe silently never worked, because Sheets'
`values.append` shifted rows that started with a blank cell one column to
the right (see app/state_store.py's module docstring). Every offline test
passed -- the fakes store rows exactly where they're told to, which is
precisely the behavior the real API didn't have. Only a test against the
real API can see that class of bug.

Each test creates its own SCRATCH spreadsheet (drive.file scope: the app
can only touch files it created), exercises it, reads the raw cells back to
check where values actually landed, and moves the file to the Drive trash
(recoverable -- never a permanent delete).

SKIPPED by default. To run:

    RUN_E2E=1 uv run pytest tests/test_sheets_live.py -v

Needs GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET / GOOGLE_REFRESH_TOKEN (the
same owner credentials the service uses; drive.file is among the granted
scopes). Touches no prod spreadsheet.
"""
from __future__ import annotations

import os
from datetime import date

import pytest

from app.audit_log import AuditRecord, SheetsAuditLog, verify_chain
from app.config import have_google_credentials
from app.state_store import REQUEST_COMPLETED, REQUEST_FAILED, REQUEST_PROCESSING, SheetsStateStore

RUN_E2E = os.environ.get("RUN_E2E") == "1"

pytestmark = [
    pytest.mark.e2e,
    pytest.mark.skipif(not RUN_E2E, reason="live Sheets contract test; set RUN_E2E=1 to run"),
]

_DRIVE_FILE_SCOPE = "https://www.googleapis.com/auth/drive.file"


def _trash(spreadsheet_id: str) -> None:
    from app.google_auth_helper import build_google_service

    drive = build_google_service("drive", "v3", scopes=[_DRIVE_FILE_SCOPE])
    drive.files().update(fileId=spreadsheet_id, body={"trashed": True}).execute()


def _raw(store_or_log, a1_range: str) -> list[list[str]]:
    return (
        store_or_log._service.spreadsheets()
        .values()
        .get(spreadsheetId=store_or_log.spreadsheet_id, range=a1_range)
        .execute()
        .get("values", [])
    )


@pytest.fixture
def require_google():
    if not have_google_credentials():
        pytest.skip("missing GOOGLE_CLIENT_ID/GOOGLE_CLIENT_SECRET/GOOGLE_REFRESH_TOKEN")


def test_state_store_rows_land_in_the_columns_the_code_reads(require_google):
    store = SheetsStateStore(spreadsheet_id=None)  # creates a scratch spreadsheet
    try:
        day = date(2026, 1, 1)
        store.mark_message_seen("msg_live_1")
        store.set_request_status("req_live_1", REQUEST_PROCESSING, "a@example.com")
        store.record_request("a@example.com", "req_live_1", day)
        store.set_request_status("req_live_1", REQUEST_COMPLETED, "a@example.com")
        store.mark_message_seen("msg_live_2")
        store.set_request_status("req_live_2", REQUEST_PROCESSING)
        store.record_request("a@example.com", "req_live_2", day)
        store.set_request_status("req_live_2", REQUEST_FAILED)

        # Behavior through the store's own API.
        assert store.is_duplicate_message("msg_live_1") and store.is_duplicate_message("msg_live_2")
        assert store.get_request_status("req_live_1") == REQUEST_COMPLETED
        assert store.get_request_status("req_live_2") == REQUEST_FAILED
        assert store.count_today("a@example.com", day) == 2

        # The contract itself: every key really sits in column A.
        assert [r[0] for r in _raw(store, "messages!A:B")] == ["msg_live_1", "msg_live_2"]
        status_rows = _raw(store, "request_status!A:D")
        assert [r[0] for r in status_rows] == ["req_live_1", "req_live_1", "req_live_2", "req_live_2"]
        assert [r[1] for r in status_rows] == [REQUEST_PROCESSING, REQUEST_COMPLETED, REQUEST_PROCESSING, REQUEST_FAILED]
        count_rows = _raw(store, "daily_counts!A:C")
        assert [r[:2] for r in count_rows] == [["2026-01-01", "a@example.com"]] * 2
    finally:
        _trash(store.spreadsheet_id)


def test_audit_log_chain_verifies_after_real_appends(require_google):
    log = SheetsAuditLog(spreadsheet_id=None)  # creates a scratch spreadsheet
    try:
        for i in range(3):
            log.append(AuditRecord(agentmail_message_id=f"msg_live_{i}", sender="a@example.com", layer0_verdict="ok", layer1_verdict="ok"))
        entries = log.all_entries()
        assert len(entries) == 3
        assert verify_chain(entries)
        # Reloading from the sheet picks the chain up where it left off.
        reopened = SheetsAuditLog(spreadsheet_id=log.spreadsheet_id)
        reopened.append(AuditRecord(agentmail_message_id="msg_live_3", sender="a@example.com", layer0_verdict="ok", layer1_verdict="ok"))
        assert verify_chain(reopened.all_entries())
    finally:
        _trash(log.spreadsheet_id)
