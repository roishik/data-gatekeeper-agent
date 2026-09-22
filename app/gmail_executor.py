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
themselves in Gmail, which is the approval step for this verb. An
optional `thread_id` (a value the requester copies from a prior
gmail.search reply) files the draft into that existing conversation as a
reply-in-thread instead of a new email; it changes only which thread the
UNSENT draft lands in, never the never-sends guarantee. Note the
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
from app.google_auth_helper import build_google_service

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
    # Gmail's opaque thread id, exposed in the reply so a follow-up
    # gmail.create_draft can be filed into this same conversation (a
    # reply-in-thread rather than a brand-new email). Like a calendar
    # event_id, it's a Google-generated token, not attacker-controlled
    # content -- see app/reply_guard.py, which appends it raw (never
    # through the redaction pass) exactly as it does event_id.
    thread_id: str = ""


@dataclass(frozen=True)
class DraftResult:
    draft_id: str
    to: str
    subject: str
    # The thread the draft was filed into, when create_draft was asked to
    # reply within an existing conversation (None for a new-email draft).
    thread_id: str | None = None


class GmailClient(Protocol):
    def search(self, query: str, max_results: int, newer_than_days: int | None) -> list[GmailResult]: ...
    def create_draft(self, to: str, subject: str, body: str, thread_id: str | None = None) -> DraftResult: ...


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
        return build_google_service("gmail", "v1", scopes=scopes)

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
                    # threadId is a top-level field on the message resource,
                    # returned regardless of format="metadata" -- no extra
                    # scope or field beyond what search already reads.
                    thread_id=msg.get("threadId", ""),
                )
            )
        return results

    def create_draft(self, to: str, subject: str, body: str, thread_id: str | None = None) -> DraftResult:
        import base64
        from email.mime.text import MIMEText

        service = self._service([GMAIL_COMPOSE_SCOPE])
        message = MIMEText(body)
        message["to"] = to
        message["subject"] = subject
        raw = base64.urlsafe_b64encode(message.as_bytes()).decode("ascii")

        # When thread_id is given, the draft is filed into that existing
        # conversation (a reply-in-thread) rather than starting a new one.
        # threadId is a field on the Message resource; Gmail also requires
        # the Subject to be consistent with the thread (the requester sends
        # a "Re: ..." subject). The thread_id itself is validated in
        # app/policy.py before it reaches here. Still drafts.create only --
        # NEVER drafts.send/messages.send (see the module docstring); the
        # draft sits unsent in the owner's Drafts folder until they send it.
        message_body: dict = {"raw": raw}
        if thread_id:
            message_body["threadId"] = thread_id
        draft = (
            service.users()
            .drafts()
            .create(userId=self._user, body={"message": message_body})
            .execute()
        )
        # Reflect the thread the draft actually landed in (from the API
        # response) rather than echoing the request, so the reply reports
        # what really happened.
        created_thread_id = draft.get("message", {}).get("threadId") or (thread_id or None)
        return DraftResult(draft_id=draft.get("id", ""), to=to, subject=subject, thread_id=created_thread_id)
