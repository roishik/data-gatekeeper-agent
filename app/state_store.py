"""
state_store.py — Layer 1: idempotency and the daily request cap.

Behind a StateStore Protocol so tests run against InMemoryStateStore
(dict-backed, no I/O) and prod runs against SheetsStateStore (a Google
Sheet as the durable store -- see docs/RUNBOOK.md for why Sheets rather
than a real database: this project already needs a Sheets-writing
credential for the audit log, so reusing it avoids a second storage
dependency for a system this small, at 5-50 requests/day).

Two independent checks live here, per the brief:
  - Idempotency, keyed on the AgentMail message id AND (once parsed) the
    request_id: AgentMail retries webhooks on a non-2xx/timeout
    response, and Instinct itself might resend a logically-identical
    request (same request_id) in a brand-new email after a timeout.
    Either key alone can produce a duplicate; both are checked.
  - Rate limiting: how many requests has this sender made today, capped
    by MAX_REQUESTS_PER_DAY (env).
"""
from __future__ import annotations

import logging
from datetime import date, datetime, timezone
from typing import Protocol

logger = logging.getLogger("gatekeeper.state_store")


class StateStore(Protocol):
    def is_duplicate_message(self, message_id: str) -> bool: ...
    def mark_message_seen(self, message_id: str) -> None: ...
    def is_duplicate_request(self, request_id: str) -> bool: ...
    def mark_request_seen(self, request_id: str) -> None: ...
    def count_today(self, sender: str, today: date | None = None) -> int: ...
    def record_request(self, sender: str, today: date | None = None) -> None: ...


def _today() -> date:
    return datetime.now(timezone.utc).date()


class InMemoryStateStore:
    """Dict-backed, process-local. Used by every test in this repo, and
    as the default for a local `uvicorn` run (STATE_STORE_BACKEND=memory,
    the default). State resets on restart -- correct for tests, and an
    accepted limitation for a quick local run; prod must use
    STATE_STORE_BACKEND=sheets."""

    def __init__(self) -> None:
        self._seen_messages: set[str] = set()
        self._seen_requests: set[str] = set()
        self._daily_counts: dict[tuple[str, date], int] = {}

    def is_duplicate_message(self, message_id: str) -> bool:
        return message_id in self._seen_messages

    def mark_message_seen(self, message_id: str) -> None:
        self._seen_messages.add(message_id)

    def is_duplicate_request(self, request_id: str) -> bool:
        return request_id in self._seen_requests

    def mark_request_seen(self, request_id: str) -> None:
        self._seen_requests.add(request_id)

    def count_today(self, sender: str, today: date | None = None) -> int:
        return self._daily_counts.get((sender, today or _today()), 0)

    def record_request(self, sender: str, today: date | None = None) -> None:
        key = (sender, today or _today())
        self._daily_counts[key] = self._daily_counts.get(key, 0) + 1


class SheetsStateStore:
    """Google-Sheets-backed StateStore for prod. Creates its own
    spreadsheet on first use (scope drive.file, so it never needs
    standing access to a file it didn't create -- research/07 section 4)
    if no spreadsheet_id is given, and logs the new id loudly so the
    operator can pin GOOGLE_SHEETS_STATE_SPREADSHEET_ID for future runs
    (see docs/RUNBOOK.md).

    Reads the whole "messages"/"requests" tab per call and scans in
    Python -- simple and correct at this project's 5-50 requests/day
    scale. A known, accepted limit: this would not scale past a few
    thousand rows without an index.

    NOT exercised against a live Sheets API call -- see the final build
    report's "could not verify" section.
    """

    _MESSAGES_RANGE = "messages!A:A"
    _REQUESTS_RANGE = "requests!A:C"  # request_id, sender, date (iso)

    def __init__(self, spreadsheet_id: str | None = None):
        from googleapiclient.discovery import build  # lazy: keep this module importable without the package

        from app.google_auth_helper import build_google_credentials

        creds = build_google_credentials(scopes=["https://www.googleapis.com/auth/drive.file"])
        self._service = build("sheets", "v4", credentials=creds, cache_discovery=False)
        self.spreadsheet_id = spreadsheet_id or self._get_or_create_spreadsheet()

    def _get_or_create_spreadsheet(self) -> str:
        body = {
            "properties": {"title": "data-gatekeeper-state"},
            "sheets": [{"properties": {"title": "messages"}}, {"properties": {"title": "requests"}}],
        }
        created = self._service.spreadsheets().create(body=body, fields="spreadsheetId").execute()
        spreadsheet_id = created["spreadsheetId"]
        logger.warning(
            "created a new state spreadsheet (id=%s) -- set GOOGLE_SHEETS_STATE_SPREADSHEET_ID "
            "to this value so future runs reuse it instead of creating another one",
            spreadsheet_id,
        )
        return spreadsheet_id

    def _column(self, a1_range: str) -> list[list[str]]:
        result = self._service.spreadsheets().values().get(spreadsheetId=self.spreadsheet_id, range=a1_range).execute()
        return result.get("values", [])

    def _append(self, a1_range: str, values: list[list[str]]) -> None:
        self._service.spreadsheets().values().append(
            spreadsheetId=self.spreadsheet_id,
            range=a1_range,
            valueInputOption="RAW",
            insertDataOption="INSERT_ROWS",
            body={"values": values},
        ).execute()

    def is_duplicate_message(self, message_id: str) -> bool:
        return any(row and row[0] == message_id for row in self._column(self._MESSAGES_RANGE))

    def mark_message_seen(self, message_id: str) -> None:
        self._append("messages!A:A", [[message_id]])

    def is_duplicate_request(self, request_id: str) -> bool:
        return any(row and row[0] == request_id for row in self._column(self._REQUESTS_RANGE))

    def mark_request_seen(self, request_id: str) -> None:
        # Written as its own row (sender/date columns blank) rather than
        # merged into record_request's row: the two calls happen at
        # different points in app/pipeline.py and neither should block
        # on the other. count_today() only matches rows with a non-empty
        # sender column, so this row is invisible to the rate-cap scan.
        self._append("requests!A:C", [[request_id, "", ""]])

    def count_today(self, sender: str, today: date | None = None) -> int:
        target = (today or _today()).isoformat()
        return sum(1 for row in self._column(self._REQUESTS_RANGE) if len(row) >= 3 and row[1] == sender and row[2] == target)

    def record_request(self, sender: str, today: date | None = None) -> None:
        target = (today or _today()).isoformat()
        self._append("requests!A:C", [["", sender, target]])
