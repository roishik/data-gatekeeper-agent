"""
calendar_executor.py — Layer 4: the only module that touches Google
Calendar.

Executes calendar.list_events via `events.list(calendarId="primary",
singleEvents=True, orderBy="startTime", timeMin=..., timeMax=...)`.
Returns only: an event id (for the audit log only -- never shown in a
reply), summary, start, end, an all-day flag, and the attendee COUNT --
never attendee emails, description, location, conference links
(hangoutLink/conferenceData), or attachments. That restriction is
enforced by only ever reading five keys off each raw event dict below,
never by trusting a caller not to look further (the same discipline as
app/gmail_executor.py's `_METADATA_HEADERS` allowlist).

Scope: calendar.readonly only, same refresh-token credential plumbing as
app/gmail_executor.py (see app/google_auth_helper.py).

The timeMin/timeMax window is computed entirely in Python
(app/calendar_window.py) from day_offset/days -- Layer 2's LLM never
sees or produces a date/timestamp, only small bounded integers.

Field names -- `timeMin`/`timeMax` as RFC3339 with a mandatory offset
(timeMin bounds an event's END time, timeMax bounds its START time, both
exclusive), `singleEvents`/`orderBy="startTime"` to expand recurring
events into flat instances in chronological order, and each event's
`start`/`end` objects carrying EITHER `date` (all-day) OR
`dateTime`+`timeZone` (timed), plus `attendees` as a list -- were
confirmed against Google's current Calendar API v3 reference (fetched
during this build, raw HTML/embedded-JSON, not just an AI-summarized
pass). NOT exercised against a live Calendar API call. See the final
build report's "could not verify" section.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from app.google_auth_helper import build_google_credentials

CALENDAR_READONLY_SCOPE = "https://www.googleapis.com/auth/calendar.readonly"


@dataclass(frozen=True)
class CalendarEvent:
    event_id: str
    summary: str
    start: str  # ISO date (all-day) or RFC3339 datetime, exactly as returned by the API
    end: str
    all_day: bool
    attendee_count: int


class CalendarClient(Protocol):
    def list_events(self, time_min: str, time_max: str, max_results: int) -> list[CalendarEvent]: ...


class GoogleCalendarClient:
    """Real implementation, gated behind having Google OAuth credentials
    configured (checked in google_auth_helper.build_google_credentials)."""

    def _service(self):
        from googleapiclient.discovery import build  # lazy: keep this module importable without the package

        creds = build_google_credentials(scopes=[CALENDAR_READONLY_SCOPE])
        return build("calendar", "v3", credentials=creds, cache_discovery=False)

    def list_events(self, time_min: str, time_max: str, max_results: int) -> list[CalendarEvent]:
        service = self._service()
        resp = (
            service.events()
            .list(
                calendarId="primary",
                timeMin=time_min,
                timeMax=time_max,
                singleEvents=True,
                orderBy="startTime",
                maxResults=max_results,
            )
            .execute()
        )

        results: list[CalendarEvent] = []
        for event in resp.get("items", []):
            start = event.get("start", {}) or {}
            end = event.get("end", {}) or {}
            all_day = "date" in start
            results.append(
                CalendarEvent(
                    event_id=event.get("id", ""),
                    summary=event.get("summary", "") or "",
                    start=start.get("date") or start.get("dateTime") or "",
                    end=end.get("date") or end.get("dateTime") or "",
                    all_day=all_day,
                    attendee_count=len(event.get("attendees", []) or []),
                )
            )
        return results
