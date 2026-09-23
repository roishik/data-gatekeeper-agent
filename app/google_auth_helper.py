"""
google_auth_helper.py — build Google API credentials and service objects
from the long-lived refresh token + OAuth client id/secret in env.

Shared by every executor (gmail/calendar/drive) and the Sheets-backed
audit_log.py / state_store.py implementations -- one place builds
Credentials and service objects, so there's exactly one thing to get right
about how the refresh token is used, no matter which Google API is being
called or which scope it needs.

Both are cached per scope set for the life of the process (added
2026-09-22). Before that, every request built fresh Credentials with no
access token, so every Google call started with a token refresh round
trip. A cached Credentials object refreshes itself only when its access
token actually expires. Scopes are still requested per operation -- the
cache key IS the scope set, so a gmail.readonly caller never receives a
service minted for gmail.compose.

Every service gets a hard HTTP timeout (GOOGLE_HTTP_TIMEOUT_SECONDS) --
httplib2's default is to wait forever, which is how a slow Google call
could previously run a request into Cloud Run's own request timeout.

Thread safety: httplib2-backed service objects are NOT safe to share
across threads. That's fine here because app/main.py runs handle_webhook
under a single process-wide lock, so at most one thread touches Google at
a time. Anything that starts using these from worker threads must build
its own service instead.

The refresh token itself is minted ONCE, by hand, outside this service
-- see scripts/google_auth.py.
"""
from __future__ import annotations

import threading
from typing import Any

from app.config import GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_REFRESH_TOKEN

GOOGLE_HTTP_TIMEOUT_SECONDS = 15

_cache_lock = threading.Lock()
_credentials_cache: dict[tuple[str, ...], Any] = {}
_service_cache: dict[tuple[str, str, tuple[str, ...]], Any] = {}


def _scope_key(scopes: list[str]) -> tuple[str, ...]:
    return tuple(sorted(set(scopes)))


def build_google_credentials(scopes: list[str]):
    """Returns a google.oauth2.credentials.Credentials built from the
    refresh token, cached per scope set. No access token is passed in
    (token=None) -- the http layer mints one on first use and refreshes it
    on expiry, which keeps the only long-lived secret here the refresh
    token itself, never a short-lived access token sitting in env."""
    from google.oauth2.credentials import Credentials  # lazy: keep this module importable without the package

    if not (GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET and GOOGLE_REFRESH_TOKEN):
        raise RuntimeError(
            "GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET / GOOGLE_REFRESH_TOKEN must all be "
            "set to build Google API credentials."
        )
    key = _scope_key(scopes)
    with _cache_lock:
        creds = _credentials_cache.get(key)
        if creds is None:
            creds = Credentials(
                token=None,
                refresh_token=GOOGLE_REFRESH_TOKEN,
                token_uri="https://oauth2.googleapis.com/token",
                client_id=GOOGLE_CLIENT_ID,
                client_secret=GOOGLE_CLIENT_SECRET,
                scopes=list(key),
            )
            _credentials_cache[key] = creds
        return creds


def build_google_service(api: str, version: str, scopes: list[str]):
    """A googleapiclient service object for `api`/`version`, authorized for
    exactly `scopes`, with a hard HTTP timeout. Cached per (api, version,
    scope set) -- see the module docstring for the thread-safety caveat."""
    import google_auth_httplib2  # lazy: keep this module importable without the packages
    import httplib2
    from googleapiclient.discovery import build

    key = (api, version, _scope_key(scopes))
    with _cache_lock:
        service = _service_cache.get(key)
    if service is not None:
        return service

    creds = build_google_credentials(scopes)
    http = google_auth_httplib2.AuthorizedHttp(creds, http=httplib2.Http(timeout=GOOGLE_HTTP_TIMEOUT_SECONDS))
    service = build(api, version, http=http, cache_discovery=False)
    with _cache_lock:
        return _service_cache.setdefault(key, service)
