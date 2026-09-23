"""
verify_audit_chain.py — check the PRODUCTION audit log's hash chain, and
summarize it, without printing any record content.

The Sheets audit log (app/audit_log.py) is tamper-EVIDENT, not
tamper-proof: the credential that appends rows could also rewrite them.
The sha256 chain is what makes a rewritten, deleted, reordered or forked
entry detectable -- but only if someone actually recomputes it. This is
that check. Run it after every deploy, and whenever something looks off.

A fork is the one failure the service can cause on its own: the chain's
last hash lives in process memory, and during a Cloud Run revision rollout
an old and a new instance can briefly both append. max-instances=1 plus the
process-wide request lock (app/main.py) rule it out otherwise.

Usage (read-only; nothing is written anywhere):

    uv run python scripts/verify_audit_chain.py
    uv run python scripts/verify_audit_chain.py --spreadsheet-id <id> --recent 10

Credentials: GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET / GOOGLE_REFRESH_TOKEN
from the environment (or .env) if set, else the local token written by
scripts/google_auth.py (~/.config/data-gatekeeper/token.json). The
spreadsheet id defaults to GOOGLE_SHEETS_LOG_SPREADSHEET_ID.

Output is ids-free: entry count, the first break (index + timestamp) if
any, and counts of verdicts/verbs/statuses. `--recent N` adds one line per
recent entry with its timestamp, verdicts, verb, status and scores -- still
no sender, message id, request id or content.
"""
from __future__ import annotations

import argparse
import collections
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.audit_log import GENESIS_HASH, compute_entry_hash  # noqa: E402
from app.config import GOOGLE_SHEETS_LOG_SPREADSHEET_ID, have_google_credentials  # noqa: E402

TOKEN_PATH = Path.home() / ".config" / "data-gatekeeper" / "token.json"
_SHEETS_SCOPE = "https://www.googleapis.com/auth/drive.file"


def _sheets_service():
    if have_google_credentials():
        from app.google_auth_helper import build_google_service

        return build_google_service("sheets", "v4", scopes=[_SHEETS_SCOPE])
    if not TOKEN_PATH.exists():
        sys.exit(f"No Google credentials in the environment and no token at {TOKEN_PATH} -- run scripts/google_auth.py first.")
    from google.oauth2.credentials import Credentials
    from googleapiclient.discovery import build

    creds = Credentials.from_authorized_user_info(json.loads(TOKEN_PATH.read_text()))
    return build("sheets", "v4", credentials=creds, cache_discovery=False)


def first_break(entries: list[dict]) -> int | None:
    """Index of the first entry whose link or hash doesn't verify, or None
    if the whole chain holds. Same rule as app/audit_log.verify_chain, but
    says WHERE it broke."""
    prev_hash = GENESIS_HASH
    for index, entry in enumerate(entries):
        if entry.get("prev_hash") != prev_hash:
            return index
        if entry.get("hash") != compute_entry_hash(entry["record"], entry["prev_hash"]):
            return index
        prev_hash = entry["hash"]
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n\n")[0])
    parser.add_argument("--spreadsheet-id", default=GOOGLE_SHEETS_LOG_SPREADSHEET_ID)
    parser.add_argument("--recent", type=int, default=0, help="also list the N most recent entries (no ids or content)")
    args = parser.parse_args()
    if not args.spreadsheet_id:
        sys.exit("No spreadsheet id: pass --spreadsheet-id or set GOOGLE_SHEETS_LOG_SPREADSHEET_ID.")

    rows = (
        _sheets_service().spreadsheets().values()
        .get(spreadsheetId=args.spreadsheet_id, range="audit_log!A:A").execute().get("values", [])
    )
    entries = [json.loads(row[0]) for row in rows if row]
    records = [e["record"] for e in entries]

    broken_at = first_break(entries)
    print(f"entries: {len(entries)}")
    if records:
        print(f"range:   {records[0]['timestamp'][:19]} .. {records[-1]['timestamp'][:19]} UTC")
    if broken_at is None:
        print("chain:   OK -- every entry's hash and link verify")
    else:
        print(f"chain:   BROKEN at entry {broken_at} ({records[broken_at]['timestamp'][:19]} UTC)")

    def count(key: str, subset=records) -> dict:
        return dict(collections.Counter(r.get(key) for r in subset).most_common())

    handled = [r for r in records if r.get("layer1_verdict") not in (None, "not_reached")]
    print(f"layer0:  {count('layer0_verdict')}")
    print(f"layer1:  {count('layer1_verdict')}")
    print(f"verbs:   {count('parsed_verb', handled)}")
    print(f"source:  {count('parsed_source', handled)}")
    print(f"replies: {count('reply_status', handled)}")
    failures = [r for r in records if r.get("failure_code") or r.get("reply_error")]
    if failures:
        print(f"failures: {len(failures)} -- {dict(collections.Counter((r.get('failure_code'), r.get('reply_error')) for r in failures))}")
    withheld = sum(r.get("output_withheld_count") or 0 for r in records)
    if withheld:
        print(f"withheld items (outbound screen): {withheld}")

    if args.recent:
        print(f"\nlast {args.recent}:")
        for r in records[-args.recent:]:
            print(
                f"  {r['timestamp'][:19]}  {r.get('layer0_verdict')}/{r.get('layer1_verdict')}  "
                f"{r.get('parsed_verb')}  {r.get('reply_status') or r.get('policy_status')}"
                f"  inj={r.get('injection_score')}  withheld={r.get('output_withheld_count', 0)}"
            )
    return 0 if broken_at is None else 1


if __name__ == "__main__":
    raise SystemExit(main())
