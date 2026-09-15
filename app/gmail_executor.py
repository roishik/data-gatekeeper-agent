"""
gmail_executor.py — Layer 4: the only module that touches Gmail.

Executes gmail.search against the real Gmail API via
`users.messages.list` + `users.messages.get(format="metadata")`. Returns
only from/subject/date/snippet -- NEVER a body, NEVER an attachment. That
restriction is enforced in code (format="metadata" plus an explicit,
short `metadataHeaders` allowlist below), not left as a convention
someone could quietly widen later.

Also executes gmail.create_draft via `users.drafts.create` -- this
creates a Gmail DRAFT only, and NEVER calls drafts.send or
messages.send anywhere in this module. That is a deliberate, owner-
chosen design (see CLAUDE.md): the owner reviews and sends the draft
themselves in Gmail, which is the approval step for this verb. Note the
`gmail.compose` OAuth scope this needs is, per Google's own scope
description, broader than "drafts only" (it also grants the ability to
send) -- the guarantee here is enforced by this code never calling a
send endpoint, not by the scope alone.

Scopes: gmail.readonly for search, gmail.compose for create_draft --
requested separately per call so the narrowest possible scope is always
the one presented to Google for a given operation, built from a refresh
token + OAuth client id/secret in env (see app/google_auth_helper.py and
scripts/google_auth.py).

NOT exercised against a live Gmail API call -- the users.messages.list /
get(format=metadata) / users.drafts.create request/response shapes below
come from Google's published REST reference (fetched during this
build). See the final build report's "could not verify" section.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from app.config import GOOGLE_GMAIL_USER
from app.google_auth_helper import build_google_credentials

GMAIL_READONLY_SCOPE = "https://www.googleapis.com/auth/gmail.readonly"
GMAIL_COMPOSE_SCOPE = "https://www.googleapis.com/auth/gmail.compose"

# The only headers this service ever reads out of a message -- anything
# else (including the body) is never requested from the API in the
# first place, which is a stronger guarantee than "we don't use it".
_METADATA_HEADERS = ("From", "Subject", "Date")


@dataclass(frozen=True)
class GmailResult:
    message_id: str
    sender: str
    subject: str
    date: str
    snippet: str


@dataclass(frozen=True)
class DraftResult:
    draft_id: str
    to: str
    subject: str


class GmailClient(Protocol):
    def search(self, query: str, max_results: int, newer_than_days: int | None) -> list[GmailResult]: ...
    def create_draft(self, to: str, subject: str, body: str) -> DraftResult: ...


def build_search_query(query: str, newer_than_days: int | None) -> str:
    """Gmail's own search syntax supports `newer_than:<N>d` directly --
    simpler and less error-prone than computing a calendar date and
    appending `after:YYYY/MM/DD`, and it avoids an entire timezone/
    off-by-one bug class. Pure function, unit-tested on its own."""
    if newer_than_days is None:
        return query
    return f"{query} newer_than:{newer_than_days}d"


class GoogleGmailClient:
    """Real implementation, gated behind having Google OAuth credentials
    configured (checked in google_auth_helper.build_google_credentials)."""

    def __init__(self, user: str = GOOGLE_GMAIL_USER):
        self._user = user

    def _service(self, scopes: list[str]):
        from googleapiclient.discovery import build  # lazy: keep this module importable without the package

        creds = build_google_credentials(scopes=scopes)
        return build("gmail", "v1", credentials=creds, cache_discovery=False)

    def search(self, query: str, max_results: int, newer_than_days: int | None) -> list[GmailResult]:
        service = self._service([GMAIL_READONLY_SCOPE])
        full_query = build_search_query(query, newer_than_days)
        list_resp = (
            service.users()
            .messages()
            .list(userId=self._user, q=full_query, maxResults=max_results)
            .execute()
        )
        message_ids = [m["id"] for m in list_resp.get("messages", [])]

        results: list[GmailResult] = []
        for message_id in message_ids:
            msg = (
                service.users()
                .messages()
                .get(
                    userId=self._user,
                    id=message_id,
                    format="metadata",
                    metadataHeaders=list(_METADATA_HEADERS),
                )
                .execute()
            )
            headers = {h["name"]: h["value"] for h in msg.get("payload", {}).get("headers", [])}
            results.append(
                GmailResult(
                    message_id=message_id,
                    sender=headers.get("From", ""),
                    subject=headers.get("Subject", ""),
                    date=headers.get("Date", ""),
                    snippet=msg.get("snippet", ""),
                )
            )
        return results

    def create_draft(self, to: str, subject: str, body: str) -> DraftResult:
        import base64
        from email.mime.text import MIMEText

        service = self._service([GMAIL_COMPOSE_SCOPE])
        message = MIMEText(body)
        message["to"] = to
        message["subject"] = subject
        raw = base64.urlsafe_b64encode(message.as_bytes()).decode("ascii")

        # drafts.create, never drafts.send or messages.send -- see the
        # module docstring. The draft sits in the owner's own Gmail
        # Drafts folder until they send it themselves.
        draft = (
            service.users()
            .drafts()
            .create(userId=self._user, body={"message": {"raw": raw}})
            .execute()
        )
        return DraftResult(draft_id=draft.get("id", ""), to=to, subject=subject)
