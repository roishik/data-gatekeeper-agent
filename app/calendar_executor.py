"""
calendar_executor.py — Layer 4: the only module that touches Google
Calendar.

Executes calendar.list_events via `events.list(calendarId="primary",
singleEvents=True, orderBy="startTime", timeMin=..., timeMax=...)`.
Returns only: an event id (for the audit log only -- never shown in a
reply), summary, start, end, an all-day flag, location, and the attendee
COUNT -- never attendee emails, description, conference links
(hangoutLink/conferenceData), or attachments. Location and summary are
free text an attacker with calendar-write access controls directly, so
both go through app/reply_guard.py's redaction pass before ever reaching
a reply, same as a Gmail snippet. That restriction is enforced by only
ever reading six keys off each raw event dict below, never by trusting a
caller not to look further (the same discipline as
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

That last point mattered in practice: a live run showed an all-day event
from the day before the window start still coming back from
`events.list`. A `date`-only boundary has no timezone of its own, so
Google's own timeMin/timeMax filtering for all-day events doesn't
reliably line up with the owner's local midnight the way a `dateTime`
boundary does -- e.g. a `timeMin` of local midnight in a positive UTC
offset is *earlier*, in UTC, than that same instant, so an all-day event
that (in the owner's timezone) already ended can still satisfy Google's
own end-time check. `_overlaps_window` below re-checks every result
against the requested window using the owner's timezone for all-day
dates (the same interpretation `_start_sort_key` already uses for
sorting), rather than trusting the API to have applied it.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Protocol
from zoneinfo import ZoneInfo

from app.config import OWNER_TIMEZONE
from app.google_auth_helper import build_google_credentials

CALENDAR_READONLY_SCOPE = "https://www.googleapis.com/auth/calendar.readonly"

logger = logging.getLogger("gatekeeper.calendar_executor")


@dataclass(frozen=True)
class CalendarEvent:
    event_id: str
    summary: str
    start: str  # ISO date (all-day) or RFC3339 datetime, exactly as returned by the API
    end: str
    all_day: bool
    attendee_count: int
    location: str = ""


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

        results: list[CalendarEvent] = []
        seen: set[str] = set()
        raw_counts: dict[str, int] = {}
        for calendar_id in _visible_calendar_ids(service):
            resp = (
                service.events()
                .list(
                    calendarId=calendar_id,
                    timeMin=time_min,
                    timeMax=time_max,
                    singleEvents=True,
                    orderBy="startTime",
                    maxResults=max_results,
                )
                .execute()
            )
            items = resp.get("items", [])
            raw_counts[calendar_id] = len(items)
            for event in items:
                # The same meeting can sit on several calendars (e.g. an invite that
                # also lands on a shared family calendar); iCalUID + start identifies
                # one occurrence across all of them.
                start = event.get("start", {}) or {}
                end = event.get("end", {}) or {}
                start_value = start.get("date") or start.get("dateTime") or ""
                key = f"{event.get('iCalUID') or event.get('id', '')}|{start_value}"
                if key in seen:
                    continue
                seen.add(key)
                results.append(
                    CalendarEvent(
                        event_id=event.get("id", ""),
                        summary=event.get("summary", "") or "",
                        start=start_value,
                        end=end.get("date") or end.get("dateTime") or "",
                        all_day="date" in start,
                        attendee_count=len(event.get("attendees", []) or []),
                        location=event.get("location", "") or "",
                    )
                )

        deduped_count = len(results)
        results = [e for e in results if _overlaps_window(e, time_min, time_max)]
        out_of_window_count = deduped_count - len(results)
        results.sort(key=_start_sort_key)
        final = results[:max_results]
        # Counts only, never a summary/location/id -- same minimization
        # discipline as the audit log (app/audit_log.py). This is the
        # difference between "no events" and "an event was dropped
        # somewhere" being diagnosable after the fact, without logging
        # any calendar content. INFO, not DEBUG: app/main.py's
        # logging.basicConfig runs at INFO, so a DEBUG line here would
        # silently never reach Cloud Run's logs at all (caught by an e2e
        # test against the deployed service -- see the build notes).
        logger.info(
            "calendar.list_events raw_per_calendar=%s deduped=%d dropped_out_of_window=%d returned=%d",
            raw_counts, deduped_count, out_of_window_count, len(final),
        )
        return final


def _visible_calendar_ids(service) -> list[str]:
    """The calendars the owner has switched on in the Google Calendar UI
    (`selected`), plus primary. That matches "what I see on my calendar"
    rather than only the primary one, which misses shared calendars such
    as a family calendar someone else created."""
    ids: list[str] = []
    page_token = None
    while True:
        resp = service.calendarList().list(pageToken=page_token).execute()
        for cal in resp.get("items", []):
            if cal.get("selected") or cal.get("primary"):
                ids.append(cal["id"])
        page_token = resp.get("nextPageToken")
        if not page_token:
            break
    return ids or ["primary"]


def _instant(value: str, all_day: bool) -> datetime:
    """An event's start or end value as a timezone-aware instant. All-day
    `date` values have no offset of their own, so (matching
    `_start_sort_key`) they're interpreted at local midnight in the
    owner's timezone rather than left to whatever Google's own
    timeMin/timeMax comparison assumed."""
    dt = datetime.fromisoformat(value)
    if all_day:
        return dt.replace(tzinfo=ZoneInfo(OWNER_TIMEZONE))
    return dt


def _overlaps_window(event: CalendarEvent, time_min: str, time_max: str) -> bool:
    """Re-checks a result against the requested window rather than
    trusting `events.list` to have applied it correctly for an all-day
    event (see the module docstring). Same exclusive-bounds semantics as
    the API call itself: the event's end must be after the window start,
    and its start before the window end. Never drops an event over a
    parse failure -- silently hiding a real event is worse than showing
    one with a malformed timestamp."""
    try:
        return _instant(event.end, event.all_day) > datetime.fromisoformat(time_min) and _instant(
            event.start, event.all_day
        ) < datetime.fromisoformat(time_max)
    except ValueError:
        return True


def _start_sort_key(event: CalendarEvent) -> tuple[datetime, int]:
    """Chronological across calendars by real instant. Calendars report
    different offsets (a shared calendar may return `...T14:00:00Z` for a
    17:00 Israel-time event), so the date prefix of the raw string can't be
    trusted. All-day events start at local midnight in the owner's timezone
    and sort before timed events at the same instant."""
    try:
        if event.all_day:
            start = datetime.fromisoformat(event.start).replace(tzinfo=ZoneInfo(OWNER_TIMEZONE))
            return (start.astimezone(timezone.utc), 0)
        return (datetime.fromisoformat(event.start).astimezone(timezone.utc), 1)
    except ValueError:
        return (datetime.max.replace(tzinfo=timezone.utc), 1)
