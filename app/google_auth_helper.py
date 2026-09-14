"""
google_auth_helper.py — build short-lived Google API credentials from
the long-lived refresh token + OAuth client id/secret in env.

Shared by gmail_executor.py (gmail.readonly) and the Sheets-backed
audit_log.py / state_store.py implementations (drive.file) -- one place
builds Credentials objects, so there's exactly one thing to get right
about how the refresh token is used, no matter which Google API is being
called or which scope it needs.

The refresh token itself is minted ONCE, by hand, outside this service
-- see scripts/google_auth.py.
"""
from __future__ import annotations

from app.config import GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_REFRESH_TOKEN


def build_google_credentials(scopes: list[str]):
    """Returns a google.oauth2.credentials.Credentials built from the
    refresh token. No access token is passed in (token=None) -- the
    googleapiclient http layer mints and refreshes one automatically on
    first use, which is what keeps the only long-lived secret here the
    refresh token itself, never a short-lived access token sitting in
    env."""
    from google.oauth2.credentials import Credentials  # lazy: keep this module importable without the package

    if not (GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET and GOOGLE_REFRESH_TOKEN):
        raise RuntimeError(
            "GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET / GOOGLE_REFRESH_TOKEN must all be "
            "set to build Google API credentials."
        )
    return Credentials(
        token=None,
        refresh_token=GOOGLE_REFRESH_TOKEN,
        token_uri="https://oauth2.googleapis.com/token",
        client_id=GOOGLE_CLIENT_ID,
        client_secret=GOOGLE_CLIENT_SECRET,
        scopes=scopes,
    )
