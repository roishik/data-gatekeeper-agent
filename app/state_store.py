"""
state_store.py — Layer 1: idempotency and the daily request cap.

Behind a StateStore Protocol so tests run against InMemoryStateStore
(dict-backed, no I/O) and prod runs against SheetsStateStore (a Google
Sheet as the durable store -- see docs/RUNBOOK.md for why Sheets rather
than a real database: this project already needs a Sheets-writing
credential for the audit log, so reusing it avoids a second storage
dependency for a system this small, at 5-50 requests/day).

Three independent pieces of state live here:
  - Message dedupe, keyed on the AgentMail message id: AgentMail retries a
    webhook on a non-2xx/timeout response, and a retry of a message that
    was already handled must never run it twice.
  - Request status, keyed on the request_id: Instinct may resend a
    logically-identical request (same request_id) in a brand-new email. A
    request whose last status is processing/effect_done/completed is a
    duplicate; one that last FAILED may be resent and run again. Recording
    `effect_done` the moment a write verb's side effect has happened (before
    the reply is even attempted) is what stops a resend after a failed
    reply from repeating that write.
  - The daily cap: how many requests a sender made "today", where today is
    the OWNER's calendar day (OWNER_TIMEZONE), not UTC's.

The Sheets bug this layout exists to prevent (found 2026-09-19)
----------------------------------------------------------------
The first version wrote rows that started with a blank cell (`["", sender,
date]`). Sheets' `values.append` "table detection" then shifted every later
append one column right, so request ids landed in column B and sender/date
in C/D -- and the code, reading `row[0]`/`row[1..2]`, never matched
anything. Request-id dedupe and the daily cap silently never worked in
production. The rule now, enforced in `SheetsStateStore._append` itself and
not just by convention: every row this store writes starts with a
non-empty key in column A, and each record kind has its own tab so no row
ever needs a placeholder cell.
"""
from __future__ import annotations

import logging
from datetime import date, datetime, timezone
from typing import Protocol
from zoneinfo import ZoneInfo

from app.config import OWNER_TIMEZONE

logger = logging.getLogger("gatekeeper.state_store")

# Request lifecycle, in order. `failed` is the only status a resend may run
# again from -- see the module docstring.
REQUEST_PROCESSING = "processing"
REQUEST_EFFECT_DONE = "effect_done"
REQUEST_COMPLETED = "completed"
REQUEST_FAILED = "failed"
DUPLICATE_REQUEST_STATUSES = frozenset({REQUEST_PROCESSING, REQUEST_EFFECT_DONE, REQUEST_COMPLETED})


class StateStore(Protocol):
    def is_duplicate_message(self, message_id: str) -> bool: ...
    def mark_message_seen(self, message_id: str) -> None: ...
    def get_request_status(self, request_id: str) -> str | None: ...
    def set_request_status(self, request_id: str, status: str, sender: str = "") -> None: ...
    def count_today(self, sender: str, today: date | None = None) -> int: ...
    def record_request(self, sender: str, request_id: str, today: date | None = None) -> None: ...


def is_duplicate_request_status(status: str | None) -> bool:
    return status in DUPLICATE_REQUEST_STATUSES


def owner_today(now: datetime | None = None) -> date:
    """"Today" for the daily cap is the owner's calendar day -- a cap that
    resets at 03:00 Israel time (UTC midnight) is surprising to reason about.
    `now` is for tests; it defaults to the real current time."""
    tz = ZoneInfo(OWNER_TIMEZONE)
    return (now.astimezone(tz) if now else datetime.now(tz)).date()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class InMemoryStateStore:
    """Dict-backed, process-local. Used by every test in this repo, and
    as the default for a local `uvicorn` run (STATE_STORE_BACKEND=memory,
    the default). State resets on restart -- correct for tests, and an
    accepted limitation for a quick local run; prod must use
    STATE_STORE_BACKEND=sheets."""

    def __init__(self) -> None:
        self._seen_messages: set[str] = set()
        self._request_statuses: dict[str, str] = {}
        self._daily_counts: dict[tuple[str, date], int] = {}

    def is_duplicate_message(self, message_id: str) -> bool:
        return message_id in self._seen_messages

    def mark_message_seen(self, message_id: str) -> None:
        self._seen_messages.add(message_id)

    def get_request_status(self, request_id: str) -> str | None:
        return self._request_statuses.get(request_id)

    def set_request_status(self, request_id: str, status: str, sender: str = "") -> None:
        self._request_statuses[request_id] = status

    def count_today(self, sender: str, today: date | None = None) -> int:
        return self._daily_counts.get((sender, today or owner_today()), 0)

    def record_request(self, sender: str, request_id: str, today: date | None = None) -> None:
        key = (sender, today or owner_today())
        self._daily_counts[key] = self._daily_counts.get(key, 0) + 1


class SheetsStateStore:
    """Google-Sheets-backed StateStore for prod. Creates its own
    spreadsheet on first use (scope drive.file, so it never needs
    standing access to a file it didn't create -- research/07 section 4)
    if no spreadsheet_id is given, and logs the new id loudly so the
    operator can pin GOOGLE_SHEETS_STATE_SPREADSHEET_ID for future runs
    (see docs/RUNBOOK.md).

    One tab per record kind, column A always a non-empty key:

        messages        message_id | first_seen_at
        request_status  request_id | status | updated_at | sender   (append-only, last row wins)
        daily_counts    date       | sender | request_id

    Missing tabs are added on construction, so an existing spreadsheet is
    upgraded in place. The legacy `requests` tab written by the first
    version (whose rows are misaligned -- see the module docstring) is left
    untouched as history and never read.

    Reads a whole tab per call and scans in Python -- simple and correct
    at this project's 5-50 requests/day scale; would need an index past a
    few thousand rows per tab.
    """

    _MESSAGES_TAB = "messages"
    _REQUEST_STATUS_TAB = "request_status"
    _DAILY_COUNTS_TAB = "daily_counts"
    _TABS = (_MESSAGES_TAB, _REQUEST_STATUS_TAB, _DAILY_COUNTS_TAB)

    def __init__(self, spreadsheet_id: str | None = None, service=None):
        if service is None:
            from app.google_auth_helper import build_google_service

            service = build_google_service("sheets", "v4", scopes=["https://www.googleapis.com/auth/drive.file"])
        self._service = service
        self.spreadsheet_id = spreadsheet_id or self._create_spreadsheet()
        self._ensure_tabs()

    def _create_spreadsheet(self) -> str:
        body = {
            "properties": {"title": "data-gatekeeper-state"},
            "sheets": [{"properties": {"title": tab}} for tab in self._TABS],
        }
        created = self._service.spreadsheets().create(body=body, fields="spreadsheetId").execute()
        spreadsheet_id = created["spreadsheetId"]
        logger.warning(
            "created a new state spreadsheet (id=%s) -- set GOOGLE_SHEETS_STATE_SPREADSHEET_ID "
            "to this value so future runs reuse it instead of creating another one",
            spreadsheet_id,
        )
        return spreadsheet_id

    def _ensure_tabs(self) -> None:
        meta = self._service.spreadsheets().get(spreadsheetId=self.spreadsheet_id, fields="sheets.properties.title").execute()
        existing = {s["properties"]["title"] for s in meta.get("sheets", [])}
        missing = [tab for tab in self._TABS if tab not in existing]
        if missing:
            self._service.spreadsheets().batchUpdate(
                spreadsheetId=self.spreadsheet_id,
                body={"requests": [{"addSheet": {"properties": {"title": tab}}} for tab in missing]},
            ).execute()
            logger.info("added state tabs %s to spreadsheet %s", missing, self.spreadsheet_id)

    def _rows(self, tab: str, last_col: str) -> list[list[str]]:
        result = self._service.spreadsheets().values().get(spreadsheetId=self.spreadsheet_id, range=f"{tab}!A:{last_col}").execute()
        return result.get("values", [])

    def _append(self, tab: str, last_col: str, row: list[str]) -> None:
        # The invariant from the module docstring, enforced where rows are
        # written: a blank first cell is exactly what shifted every later
        # append a column right in production.
        if not row or not str(row[0]).strip():
            raise ValueError(f"refusing to append a row with a blank first cell to {tab!r}")
        self._service.spreadsheets().values().append(
            spreadsheetId=self.spreadsheet_id,
            range=f"{tab}!A:{last_col}",
            valueInputOption="RAW",
            insertDataOption="INSERT_ROWS",
            body={"values": [row]},
        ).execute()

    def is_duplicate_message(self, message_id: str) -> bool:
        return any(row and row[0] == message_id for row in self._rows(self._MESSAGES_TAB, "A"))

    def mark_message_seen(self, message_id: str) -> None:
        self._append(self._MESSAGES_TAB, "B", [message_id, _now_iso()])

    def get_request_status(self, request_id: str) -> str | None:
        status: str | None = None
        for row in self._rows(self._REQUEST_STATUS_TAB, "B"):
            if len(row) >= 2 and row[0] == request_id:
                status = row[1]  # append-only: the last matching row wins
        return status

    def set_request_status(self, request_id: str, status: str, sender: str = "") -> None:
        self._append(self._REQUEST_STATUS_TAB, "D", [request_id, status, _now_iso(), sender])

    def count_today(self, sender: str, today: date | None = None) -> int:
        target = (today or owner_today()).isoformat()
        return sum(1 for row in self._rows(self._DAILY_COUNTS_TAB, "B") if len(row) >= 2 and row[0] == target and row[1] == sender)

    def record_request(self, sender: str, request_id: str, today: date | None = None) -> None:
        target = (today or owner_today()).isoformat()
        self._append(self._DAILY_COUNTS_TAB, "C", [target, sender, request_id])
