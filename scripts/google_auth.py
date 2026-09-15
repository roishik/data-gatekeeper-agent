#!/usr/bin/env python3
"""
scripts/google_auth.py — one-time, by-hand Google OAuth consent.

Run this ONCE, locally, to mint the refresh token the deployed service
uses forever after (until you rotate it -- see docs/RUNBOOK.md's kill
switch). The service itself never runs an OAuth consent flow; it only
ever exchanges a refresh token it's handed via env/Secret Manager for
short-lived access tokens (see app/google_auth_helper.py). Keeping the
interactive, browser-opening consent flow OUT of the deployed service is
deliberate: Cloud Run has no browser, and a consent-flow endpoint
reachable over the internet would be a second, unwanted way into this
system's Google access.

Usage:
    python scripts/google_auth.py --client-secret path/to/client_secret.json

`client_secret.json` is the Desktop-app OAuth client credentials file
downloaded from Google Cloud Console (APIs & Services > Credentials >
Create Credentials > OAuth client ID > Desktop app). It is NOT the same
as the refresh token this script produces, and is not needed again after
this script runs once.

Scopes requested: gmail.readonly, gmail.compose, calendar.readonly,
calendar.events, drive.readonly, contacts.readonly, drive.file.
gmail.compose and calendar.events are the write scopes added once the
owner explicitly decided to give the gatekeeper write access (see
CLAUDE.md): gmail.compose backs gmail.create_draft (app/gmail_executor.py
never calls a send endpoint with it -- see that module's docstring), and
calendar.events backs calendar.create_event/update_event/delete_event
(app/calendar_executor.py). The rest are requested now so a single
consent grant covers the rest of the README's MVP scope (calendar/drive/
contacts read, plus drive.file for the Sheets-backed audit log, state
store, and drive.create_file) without a second round of "please
re-consent" later.

Re-running this script against an account that already granted the
OLDER, narrower scope set (before gmail.compose/calendar.events existed)
requires re-consent -- Google will show the new scopes on the consent
screen; see the "did not return a refresh_token" note below if it
doesn't prompt.

The resulting token is written to ~/.config/data-gatekeeper/token.json
with owner-only (0600) permissions -- NEVER inside this repo, and NEVER
printed to stdout/stderr. Only the gcloud commands to load its pieces
into Secret Manager are printed, and even those read the secret VALUES
out of the file at the moment gcloud runs, never embedding them in the
printed text itself.
"""
from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from pathlib import Path

SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.compose",
    "https://www.googleapis.com/auth/calendar.readonly",
    "https://www.googleapis.com/auth/calendar.events",
    "https://www.googleapis.com/auth/drive.readonly",
    "https://www.googleapis.com/auth/contacts.readonly",
    "https://www.googleapis.com/auth/drive.file",
]

TOKEN_PATH = Path.home() / ".config" / "data-gatekeeper" / "token.json"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--client-secret",
        required=True,
        help="Path to the Desktop-app OAuth client_secret.json downloaded from Google Cloud Console.",
    )
    args = parser.parse_args()

    client_secret_path = Path(args.client_secret)
    if not client_secret_path.exists():
        print(f"error: {client_secret_path} does not exist", file=sys.stderr)
        return 1

    # Imported here, not at module top level, so `python scripts/google_auth.py --help`
    # works even if google-auth-oauthlib isn't installed in whatever
    # environment is just checking usage.
    from google_auth_oauthlib.flow import InstalledAppFlow

    flow = InstalledAppFlow.from_client_secrets_file(str(client_secret_path), SCOPES)
    # access_type=offline + prompt=consent: without both, Google will
    # only issue a refresh_token on the FIRST-ever consent for this
    # client+account pair, and silently omit it on any later re-consent
    # -- forcing prompt=consent makes this script idempotent to re-run.
    credentials = flow.run_local_server(port=0, access_type="offline", prompt="consent")

    if not credentials.refresh_token:
        print(
            "error: Google did not return a refresh_token. This usually means you've "
            "already consented before without revoking access -- revoke it at "
            "https://myaccount.google.com/connections and re-run this script.",
            file=sys.stderr,
        )
        return 1

    TOKEN_PATH.parent.mkdir(parents=True, exist_ok=True)
    TOKEN_PATH.write_text(credentials.to_json())
    os.chmod(TOKEN_PATH, stat.S_IRUSR | stat.S_IWUSR)  # 0600, owner read/write only

    print(f"Wrote credentials to {TOKEN_PATH} (0600). This file is NOT part of the repo.")
    print()
    print("Next: load its pieces into Secret Manager (values are read from the file")
    print("at the moment each command runs -- they are never printed here):")
    print()
    print(f"  PROJECT=data-gatekeeper-roishik")
    print(f"  TOKEN_FILE={TOKEN_PATH}")
    print(
        '  gcloud secrets create GOOGLE_CLIENT_ID --project="$PROJECT" '
        '--data-file=<(python3 -c "import json;print(json.load(open(\'$TOKEN_FILE\'))[\'client_id\'],end=\'\')")'
    )
    print(
        '  gcloud secrets create GOOGLE_CLIENT_SECRET --project="$PROJECT" '
        '--data-file=<(python3 -c "import json;print(json.load(open(\'$TOKEN_FILE\'))[\'client_secret\'],end=\'\')")'
    )
    print(
        '  gcloud secrets create GOOGLE_REFRESH_TOKEN --project="$PROJECT" '
        '--data-file=<(python3 -c "import json;print(json.load(open(\'$TOKEN_FILE\'))[\'refresh_token\'],end=\'\')")'
    )
    print()
    print("(Re-running this script after the secrets already exist? Use `gcloud secrets")
    print(" versions add NAME --data-file=...` instead of `create` for each line above.)")
    print()
    print("See docs/RUNBOOK.md for the full deploy sequence and the kill switch.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
