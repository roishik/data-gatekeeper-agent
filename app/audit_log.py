"""
audit_log.py — the hash-chained, append-only audit trail.

Every layer's decision gets one AuditRecord, appended exactly once per
inbound webhook event that reaches the pipeline (see app/pipeline.py),
including rejections at Layer 0. Each record's hash covers its own
content PLUS the previous record's hash (canonical-JSON, sha256) --
classic hash chaining: tampering with, reordering, or deleting any past
entry breaks every hash after it, and verify_chain() below is the one
function that PROVES that property rather than just documenting it.

Data minimization, per the brief: NEVER log a Gmail snippet or body,
only ids/counts/verdicts. If a field isn't in AuditRecord, it cannot
leak into the log by a future author absent-mindedly widening a dict --
JSONLAuditLog and SheetsAuditLog both serialize through
`_FIELD_ORDER`/`asdict(record)`, never a raw kwargs blob.

Two backends behind the AuditLog Protocol:
  - JSONLAuditLog: an append-only file, one JSON object per line. Used
    in dev and by every test in this repo -- no network, no credentials.
  - SheetsAuditLog: creates its own spreadsheet on first use (scope
    drive.file -- research/07 section 4) and appends one JSON-blob row
    per record. Used in prod. NOT exercised against a live Sheets API
    call -- see the final build report's "could not verify" section.
    Per research/07 section 4's own finding, a Sheets log alone is NOT
    strong tamper-evidence on its own (the same credential that appends
    can also rewrite/delete rows) -- the hash chain here makes tampering
    DETECTABLE. Until 2026-09-22 every reply was also BCC'd to the owner's
    Gmail -- a second copy in a separate account, as research/07
    recommends for real tamper resistance. The owner dropped that BCC
    (AgentMail's own thread history gives full visibility); the trade-off
    is that AgentMail's copy sits in an inbox this service's own API key
    can modify, so this hash chain is now the only tamper-EVIDENT record
    (scripts/verify_audit_chain.py checks it).
"""
from __future__ import annotations

import hashlib
import json
import logging
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol

logger = logging.getLogger("gatekeeper.audit_log")

GENESIS_HASH = "0" * 64

_FIELD_ORDER = [
    "event_id", "timestamp", "agentmail_message_id", "sender",
    "layer0_verdict", "layer1_verdict",
    "parsed_request_id", "parsed_verb", "parsed_source",
    "injection_score",
    "policy_status", "policy_error_code",
    # What the requester was actually told (added 2026-09-22): the policy
    # verdict alone can't show a duplicate, an error, or a rate limit.
    "reply_status", "reply_error_code",
    "result_count", "gmail_message_ids", "calendar_event_ids", "reply_message_id",
    # Failures (added 2026-09-22 -- see app/failures.py): a code, the layer
    # it escaped from, and the exception CLASS name only, never its message,
    # which can echo request content. `reply_error` is set when the reply
    # itself could not be sent.
    "reply_error", "failure_code", "failure_stage", "failure_type",
    "llm_input_tokens", "llm_output_tokens",
    # Write-verb outcomes. Unlike reads, minimization does NOT apply here
    # -- accountability for a write means the log should say exactly what
    # was sent/created/changed/deleted and to/on what, not just that some
    # verb ran (see module docstring point 2's read-side rationale, which
    # deliberately does not extend to these). The literal subject/body/
    # title text still isn't logged here -- that's what the AgentMail reply
    # thread is for, same "audit log = tamper-evident ids, email thread =
    # human-readable content" split as everything else.
    "draft_id", "draft_to", "created_event_id", "updated_event_id",
    "deleted_event_id", "drive_file_id",
]


@dataclass(frozen=True)
class AuditRecord:
    agentmail_message_id: str
    sender: str
    layer0_verdict: str
    layer1_verdict: str
    parsed_request_id: str | None = None
    parsed_verb: str | None = None
    parsed_source: str | None = None  # "block" | "llm" | "screened" | None
    # TypeSafe/Jev Noul probability that this email attempts a prompt
    # injection (app/injection_screen.py) -- None if the screen wasn't
    # configured or its call failed. Visibility only; never itself
    # authorizes or denies anything downstream of app/request_parser.py's
    # "screened" short-circuit -- see that module's docstring.
    injection_score: float | None = None
    policy_status: str | None = None
    policy_error_code: str | None = None
    reply_status: str | None = None
    reply_error_code: str | None = None
    result_count: int = 0
    gmail_message_ids: tuple[str, ...] = field(default_factory=tuple)
    # Event ids only, never a summary/title -- see app/calendar_executor.py
    # and app/pipeline.py's data-minimization comment for gmail_message_ids,
    # which applies identically here.
    calendar_event_ids: tuple[str, ...] = field(default_factory=tuple)
    reply_message_id: str | None = None
    reply_error: str | None = None
    failure_code: str | None = None
    failure_stage: str | None = None
    failure_type: str | None = None
    llm_input_tokens: int | None = None
    llm_output_tokens: int | None = None
    draft_id: str | None = None
    draft_to: str | None = None
    created_event_id: str | None = None
    updated_event_id: str | None = None
    deleted_event_id: str | None = None
    drive_file_id: str | None = None
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


def _canonical_json(data: dict) -> str:
    """Deterministic serialization: sorted keys, no incidental
    whitespace. This is what makes compute_entry_hash reproducible
    regardless of dict insertion order or json.dumps defaults changing
    between Python versions."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def compute_entry_hash(record_dict: dict, prev_hash: str) -> str:
    return hashlib.sha256((_canonical_json(record_dict) + prev_hash).encode()).hexdigest()


def _record_dict(record: AuditRecord) -> dict:
    full = asdict(record)
    return {key: (list(full[key]) if isinstance(full[key], tuple) else full[key]) for key in _FIELD_ORDER}


def verify_chain(entries: list[dict]) -> bool:
    """Recomputes every entry's hash from its own content and the
    previous entry's stored hash, and checks BOTH that the stored hash
    matches AND that each entry's prev_hash actually equals the previous
    entry's stored hash (so a deleted-and-reinserted entry, or two
    entries silently reordered, is caught even if each hash looks valid
    in isolation). Returns False on the first break -- a partially-valid
    chain is not a valid chain."""
    prev_hash = GENESIS_HASH
    for entry in entries:
        if entry.get("prev_hash") != prev_hash:
            return False
        expected = compute_entry_hash(entry["record"], entry["prev_hash"])
        if entry.get("hash") != expected:
            return False
        prev_hash = entry["hash"]
    return True


class AuditLog(Protocol):
    def append(self, record: AuditRecord) -> dict: ...
    def all_entries(self) -> list[dict]: ...


class JSONLAuditLog:
    """Dev/test backend: one JSON object per line, newest last. Reloads
    the last entry's hash on construction so the chain stays correct
    across process restarts -- an empty/missing file starts a fresh
    chain at GENESIS_HASH."""

    def __init__(self, path: str | Path):
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._prev_hash = self._load_last_hash()

    def _load_last_hash(self) -> str:
        if not self._path.exists():
            return GENESIS_HASH
        last_hash = GENESIS_HASH
        with self._path.open("r") as f:
            for line in f:
                line = line.strip()
                if line:
                    last_hash = json.loads(line)["hash"]
        return last_hash

    def append(self, record: AuditRecord) -> dict:
        record_dict = _record_dict(record)
        entry_hash = compute_entry_hash(record_dict, self._prev_hash)
        entry = {"record": record_dict, "prev_hash": self._prev_hash, "hash": entry_hash}
        with self._path.open("a") as f:
            f.write(json.dumps(entry) + "\n")
        self._prev_hash = entry_hash
        return entry

    def all_entries(self) -> list[dict]:
        if not self._path.exists():
            return []
        with self._path.open("r") as f:
            return [json.loads(line) for line in f if line.strip()]


class SheetsAuditLog:
    """Google-Sheets-backed AuditLog for prod. See the module docstring
    for the backend comparison and JSONLAuditLog for the dev/test one.

    NOT exercised against a live Sheets API call -- see the final build
    report's "could not verify" section."""

    _RANGE = "audit_log!A:A"  # one JSON blob per row, see append() below

    def __init__(self, spreadsheet_id: str | None = None, service=None):
        if service is None:
            from app.google_auth_helper import build_google_service

            service = build_google_service("sheets", "v4", scopes=["https://www.googleapis.com/auth/drive.file"])
        self._service = service
        self.spreadsheet_id = spreadsheet_id or self._get_or_create_spreadsheet()
        self._prev_hash = self._load_last_hash()

    def _get_or_create_spreadsheet(self) -> str:
        body = {
            "properties": {"title": "data-gatekeeper-audit-log"},
            "sheets": [{"properties": {"title": "audit_log"}}],
        }
        created = self._service.spreadsheets().create(body=body, fields="spreadsheetId").execute()
        spreadsheet_id = created["spreadsheetId"]
        logger.warning(
            "created a new audit-log spreadsheet (id=%s) -- set GOOGLE_SHEETS_LOG_SPREADSHEET_ID "
            "to this value so future runs append to it instead of creating another one",
            spreadsheet_id,
        )
        return spreadsheet_id

    def _load_last_hash(self) -> str:
        result = self._service.spreadsheets().values().get(spreadsheetId=self.spreadsheet_id, range=self._RANGE).execute()
        rows = result.get("values", [])
        return json.loads(rows[-1][0])["hash"] if rows else GENESIS_HASH

    def append(self, record: AuditRecord) -> dict:
        record_dict = _record_dict(record)
        entry_hash = compute_entry_hash(record_dict, self._prev_hash)
        entry = {"record": record_dict, "prev_hash": self._prev_hash, "hash": entry_hash}
        # One JSON blob per row, not one column per field: the record
        # shape is expected to grow (new verbs, new verdicts), and a
        # single-column append needs no migration when AuditRecord gains
        # a field. Costs "not human-skimmable without opening a cell" --
        # an accepted tradeoff, since the AgentMail thread is the
        # human-readable log; this one is the tamper-evident one.
        self._service.spreadsheets().values().append(
            spreadsheetId=self.spreadsheet_id,
            range=self._RANGE,
            valueInputOption="RAW",
            insertDataOption="INSERT_ROWS",
            body={"values": [[json.dumps(entry)]]},
        ).execute()
        self._prev_hash = entry_hash
        return entry

    def all_entries(self) -> list[dict]:
        result = self._service.spreadsheets().values().get(spreadsheetId=self.spreadsheet_id, range=self._RANGE).execute()
        return [json.loads(row[0]) for row in result.get("values", []) if row]
