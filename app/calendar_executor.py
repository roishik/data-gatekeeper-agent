"""
calendar_executor.py — Layer 4: the only module that touches Google
Calendar.

Executes calendar.list_events via `events.list(calendarId=<each visible
calendar, or the one asked for>, singleEvents=True, orderBy="startTime",
timeMin=..., timeMax=...)`, and calendar.list_calendars via
`calendarList.list`. Returns only: an event id (shown in the reply as an opaque `event_id` --
the only way a request can later reference this same event via
calendar.update_event/delete_event, per the owner's explicit choice to
expose it once it became clear there was otherwise no way to reference
an existing event at all; the id itself carries no attacker-controlled
content, unlike summary/location below), the id of the calendar it is on
(an opaque token too, needed to address the event again), summary, start,
end, an all-day flag, location, and the attendee COUNT -- never attendee
emails, description, conference links (hangoutLink/conferenceData), or
attachments. Location and summary are free text an attacker with
calendar-write access controls directly, so both go through
app/reply_guard.py's redaction pass before ever reaching a reply, same
as a Gmail snippet. That restriction is enforced by only ever reading
a fixed handful of keys off each raw event dict below, never by trusting a
caller not to look further (the same discipline as app/gmail_executor.py's
`_METADATA_HEADERS` allowlist). A calendar list entry is held to the same
rule: only its id, its name (`summaryOverride` else `summary`), its
`accessRole` and its `primary` flag are ever read.

Scopes: calendar.readonly for list_events; calendar.events (events only --
not calendar settings or ACLs) for create/update/delete_event. Same
refresh-token credential plumbing as app/gmail_executor.py (see
app/google_auth_helper.py).

The timeMin/timeMax window is computed entirely in Python
(app/calendar_window.py) from day_offset/days -- Layer 2's LLM never
sees or produces a date/timestamp, only small bounded integers.

Field names -- `timeMin`/`timeMax` as RFC3339 with a mandatory offset
(timeMin bounds an event's END time, timeMax bounds its START time, both
exclusive), `singleEvents`/`orderBy="startTime"` to expand recurring
events into flat instances in chronological order, and each event's
`start`/`end` objects carrying EITHER `date` (all-day) OR
`dateTime`+`timeZone` (timed), plus `attendees` as a list -- were
confirmed against Google's Calendar API v3 reference. list_events has run
in prod since 2026-09-15; as of 2026-09-22 the three write methods had not
yet run live (tests/test_e2e_live.py is what exercises them for real).

Write containment (added 2026-09-22, owner's decision)
------------------------------------------------------
Every event create_event makes is tagged with a private extended property
(`gatekeeper=1`, plus the request_id that created it). update_event and
delete_event fetch the event first and refuse -- `not_gatekeeper_event` --
anything without that tag. Before this, both could touch ANY event on the
primary calendar, so one injected request could cancel a real meeting (with
a cancellation email to every guest) or add an outsider to it (who'd then
receive its full invite: description, conferencing link, and all).
Creating events stays fully autonomous.

Attendee changes are additive: `add_attendees` / `remove_attendees` are
merged into the event's EXISTING guest list, keeping each existing guest's
response status. The old `attendees` field replaced the whole list, so "add
Dana" would silently uninvite everyone else. Adding attendees also runs the
caller's invite guard on the event's title AND location first
(app/output_screen.py): an invite sends both to third parties immediately.

`location` (added 2026-09-22, owner's request) is a plain string on both
create_event and update_event -- a room, address, or video-call link.
Google delivers it to attendees verbatim, so it goes through the same
invite guard as the title, not through app/reply_guard.py's redaction
(that only applies to what THIS service tells Instinct back, never to
what Google itself sends out). On update_event, `None` leaves the
location untouched and `""` clears it.

Choosing a calendar (added 2026-09-25)
--------------------------------------
Every event verb takes an optional `calendar_id`. Writes default to
"primary" (Google's alias for the account's own calendar), exactly as before.
list_events is the exception: with no `calendar_id` it still reads EVERY
calendar switched on in Google Calendar (that is what it did before
calendar_id existed, and what the shared family calendar relies on); given
one, it reads just that calendar.

Nothing but "primary" is passed to Google unchecked. Any other id must be in
the account's own calendar list with enough access -- owner or writer to
write, anything but free/busy-only to read (`_resolve_calendar`) -- otherwise
the request is denied (`invalid_params`), never sent on to fail at Google.
Which calendars a request can name is therefore exactly what
calendar.list_calendars reports. That lookup needs `calendar.readonly` next
to `calendar.events` (which alone cannot list calendars); both are already
granted, so no new consent is needed.

Write containment is per calendar copy: update/delete fetch the event from
the named calendar and still refuse anything without the private
`gatekeeper=1` tag. That tag is what this service sets on its own inserts,
so an event created on the family calendar is changeable there, and a
family member's own event is not. Whether the tag stays readable on a shared
calendar's copy of the event has not been confirmed against a live shared
calendar; if it isn't, the failure is a refusal (`not_gatekeeper_event`),
never a wrongful edit.

Time (added 2026-09-25)
-----------------------
create_event/update_event take a timed event as a start plus EITHER a
duration OR an end (`end_day_offset` + `end_time`, so an event can run
overnight or for days -- at most 14), or an all-day event by first day and
optional last day, the last day INCLUDED. Google's all-day `end.date` is
exclusive, so app/calendar_window.py's resolve_all_day_range adds the day.
An update fills in whatever a request leaves out from the existing event,
and never changes what it wasn't asked to: `all_day` omitted keeps the
event's kind, and moving an event by day_offset alone keeps its length. The
patch API merges nested objects, so switching an event between all-day and
timed has to null out the other kind's field (`_timing_body`).

sendUpdates: an insert with no attendees is sent with `sendUpdates="none"`,
not "all". The two are equivalent for an event with no guests, but this makes
"no invites unless attendees are given" a property of the request itself
rather than of Google's behavior -- which matters on a shared calendar.

The list-events path below is otherwise unchanged.

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
from datetime import datetime, time, timedelta, timezone
from typing import Callable, Protocol
from zoneinfo import ZoneInfo

from app.calendar_window import (
    EventTimeSpan,
    resolve_all_day_range,
    resolve_event_datetime,
    resolve_event_range,
)
from app.config import OWNER_TIMEZONE
from app.failures import GatekeeperDenied
from app.google_auth_helper import build_google_service
from app.policy import (
    EVENT_ATTENDEES_MAX,
    PRIMARY_CALENDAR_ID,
    all_day_span_problem,
    timed_span_minutes,
    timed_span_problem,
)

CALENDAR_READONLY_SCOPE = "https://www.googleapis.com/auth/calendar.readonly"
# Read/write access to events only (not calendar settings/ACLs/calendar
# creation) -- least privilege for create/update/delete_event. Requested
# only for those three write calls; list_events keeps using the
# narrower *.readonly scope above, unchanged.
CALENDAR_EVENTS_SCOPE = "https://www.googleapis.com/auth/calendar.events"

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
    # The calendar the event is on (an opaque id, or "primary") -- what a
    # follow-up update/delete has to name to reach an event that isn't on the
    # primary calendar. "" only when a caller didn't set it.
    calendar_id: str = ""


@dataclass(frozen=True)
class CalendarInfo:
    """One entry of calendar.list_calendars. `name` is free text anyone who
    shared the calendar with the owner controls, so it is screened and
    redacted like an event title before it reaches a reply."""

    calendar_id: str
    name: str
    access_role: str  # "owner" | "writer"
    primary: bool = False


# Roles that may write to a calendar, and roles that may read event details
# from one (`freeBusyReader` sees only busy blocks, no titles).
_WRITE_ROLES = frozenset({"owner", "writer"})
_READ_ROLES = frozenset({"owner", "writer", "reader"})

# The private extended property that marks an event as created by this
# service (see "Write containment" in the module docstring).
GATEKEEPER_TAG_KEY = "gatekeeper"
GATEKEEPER_TAG_VALUE = "1"
GATEKEEPER_REQUEST_ID_KEY = "gatekeeper_request_id"


class CalendarClient(Protocol):
    def list_calendars(self) -> list[CalendarInfo]: ...
    def list_events(
        self, time_min: str, time_max: str, max_results: int,
        calendar_id: str | None = None, query: str | None = None,
    ) -> list[CalendarEvent]: ...
    def create_event(
        self, title: str, day_offset: int, start_time: str | None, duration_minutes: int | None,
        attendees: tuple[str, ...], request_id: str, location: str = "", *,
        calendar_id: str = PRIMARY_CALENDAR_ID, end_day_offset: int | None = None,
        end_time: str | None = None, all_day: bool = False,
    ) -> CalendarEvent: ...
    def update_event(
        self,
        event_id: str,
        title: str | None,
        day_offset: int | None,
        start_time: str | None,
        duration_minutes: int | None,
        add_attendees: tuple[str, ...],
        remove_attendees: tuple[str, ...],
        invite_guard: Callable[[str, str], None],
        location: str | None = None,
        *,
        calendar_id: str = PRIMARY_CALENDAR_ID,
        end_day_offset: int | None = None,
        end_time: str | None = None,
        all_day: bool | None = None,
    ) -> CalendarEvent: ...
    def delete_event(self, event_id: str, calendar_id: str = PRIMARY_CALENDAR_ID) -> None: ...


def is_gatekeeper_event(event: dict) -> bool:
    private = ((event.get("extendedProperties") or {}).get("private") or {})
    return private.get(GATEKEEPER_TAG_KEY) == GATEKEEPER_TAG_VALUE


def merge_attendees(existing: list[dict], add: tuple[str, ...], remove: tuple[str, ...]) -> list[dict]:
    """Existing guests keep their full attendee objects (responseStatus and
    all); removals and duplicate additions match case-insensitively."""
    removing = {a.lower() for a in remove}
    merged = [a for a in existing if (a.get("email") or "").lower() not in removing]
    present = {(a.get("email") or "").lower() for a in merged}
    for email in add:
        if email.lower() not in present:
            merged.append({"email": email})
            present.add(email.lower())
    return merged


class GoogleCalendarClient:
    """Real implementation, gated behind having Google OAuth credentials
    configured (checked in google_auth_helper.build_google_credentials)."""

    def _service(self, scopes: list[str]):
        return build_google_service("calendar", "v3", scopes=scopes)

    def list_calendars(self) -> list[CalendarInfo]:
        service = self._service([CALENDAR_READONLY_SCOPE])
        infos = [
            CalendarInfo(
                calendar_id=entry["id"],
                name=entry.get("summaryOverride") or entry.get("summary") or "",
                access_role=entry["accessRole"],
                primary=bool(entry.get("primary")),
            )
            for entry in _calendar_list_entries(service)
            if entry.get("accessRole") in _WRITE_ROLES
        ]
        infos.sort(key=lambda c: (not c.primary, c.name.lower()))
        return infos

    def list_events(
        self, time_min: str, time_max: str, max_results: int,
        calendar_id: str | None = None, query: str | None = None,
    ) -> list[CalendarEvent]:
        service = self._service([CALENDAR_READONLY_SCOPE])

        # No calendar_id: everything switched on in Google Calendar (the
        # behavior before calendar_id existed). One given: just that calendar,
        # checked against the account's own calendar list.
        calendar_ids = (
            _visible_calendar_ids(service)
            if calendar_id is None
            else [_resolve_calendar(service, calendar_id, write=False)]
        )
        results: list[CalendarEvent] = []
        seen: set[str] = set()
        raw_counts: dict[str, int] = {}
        for cal_id in calendar_ids:
            list_kwargs = dict(
                calendarId=cal_id,
                timeMin=time_min,
                timeMax=time_max,
                singleEvents=True,
                orderBy="startTime",
                maxResults=max_results,
            )
            if query is not None:
                # Google matches this against summary, description, location
                # and attendees; none of the last two are ever returned.
                list_kwargs["q"] = query
            resp = service.events().list(**list_kwargs).execute()
            items = resp.get("items", [])
            raw_counts[cal_id] = len(items)
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
                        calendar_id=cal_id,
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

    def create_event(
        self, title: str, day_offset: int, start_time: str | None, duration_minutes: int | None,
        attendees: tuple[str, ...], request_id: str, location: str = "", *,
        calendar_id: str = PRIMARY_CALENDAR_ID, end_day_offset: int | None = None,
        end_time: str | None = None, all_day: bool = False,
    ) -> CalendarEvent:
        service = self._service(_write_scopes(calendar_id))
        target = _resolve_calendar(service, calendar_id, write=True)
        span = _resolve_new_timing(day_offset, start_time, duration_minutes, end_day_offset, end_time, all_day)
        body = {
            "summary": title,
            "location": location,
            **_timing_body(span),
            "attendees": [{"email": a} for a in attendees],
            # The containment tag: only events carrying it can later be
            # updated or deleted through this service.
            "extendedProperties": {
                "private": {GATEKEEPER_TAG_KEY: GATEKEEPER_TAG_VALUE, GATEKEEPER_REQUEST_ID_KEY: request_id},
            },
        }
        # Attendees get a real invite email immediately (sendUpdates="all"),
        # by the owner's explicit choice (CLAUDE.md) -- there is no approval
        # step for this verb. With NO attendees nothing is sent at all
        # ("none"): equivalent for an event with no guests, but it makes "no
        # invites unless attendees were given" hold by construction, whatever
        # calendar (e.g. a shared family one) the event lands on.
        event = (
            service.events()
            .insert(calendarId=target, body=body, sendUpdates="all" if attendees else "none")
            .execute()
        )
        return _event_from_raw(event, target)

    def _get_own_event(self, service, calendar_id: str, event_id: str) -> dict:
        """The event, if (and only if) this service created it. A missing
        event surfaces as Google's own 404/410 (-> `not_found`)."""
        existing = service.events().get(calendarId=calendar_id, eventId=event_id).execute()
        if not is_gatekeeper_event(existing):
            raise GatekeeperDenied("not_gatekeeper_event", "the event was not created by the gatekeeper")
        return existing

    def update_event(
        self,
        event_id: str,
        title: str | None,
        day_offset: int | None,
        start_time: str | None,
        duration_minutes: int | None,
        add_attendees: tuple[str, ...],
        remove_attendees: tuple[str, ...],
        invite_guard: Callable[[str, str], None],
        location: str | None = None,
        *,
        calendar_id: str = PRIMARY_CALENDAR_ID,
        end_day_offset: int | None = None,
        end_time: str | None = None,
        all_day: bool | None = None,
    ) -> CalendarEvent:
        service = self._service(_write_scopes(calendar_id))
        target = _resolve_calendar(service, calendar_id, write=True)
        existing = self._get_own_event(service, target, event_id)
        body: dict = {}
        if title is not None:
            body["summary"] = title
        if location is not None:
            body["location"] = location

        merged_attendees: list[dict] | None = None
        if add_attendees or remove_attendees:
            merged_attendees = merge_attendees(existing.get("attendees") or [], add_attendees, remove_attendees)
            if len(merged_attendees) > EVENT_ATTENDEES_MAX:
                raise GatekeeperDenied(
                    "too_many_attendees",
                    f"the event would have {len(merged_attendees)} attendees; the limit is {EVENT_ATTENDEES_MAX}",
                )
            body["attendees"] = merged_attendees

        # The invite guard screens title+location before either reaches a
        # real attendee. It must run whenever the patch will actually
        # notify someone: new guests are always notified (add_attendees),
        # and sendUpdates="all" below notifies EXISTING guests of ANY
        # changed field too -- so a title/location-only rename on an
        # event that already has guests is just as much an "invite" as
        # adding one. Guarding only on add_attendees (the original
        # 2026-09-22 implementation) missed that second case entirely.
        resulting_attendees = merged_attendees if merged_attendees is not None else (existing.get("attendees") or [])
        if resulting_attendees and (add_attendees or title is not None or location is not None):
            invite_guard(
                title if title is not None else (existing.get("summary") or ""),
                location if location is not None else (existing.get("location") or ""),
            )

        timing_fields = (day_offset, start_time, duration_minutes, end_day_offset, end_time, all_day)
        if any(value is not None for value in timing_fields):
            span = _resolve_updated_timing(
                existing, day_offset=day_offset, start_time=start_time, duration_minutes=duration_minutes,
                end_day_offset=end_day_offset, end_time=end_time, all_day=all_day,
            )
            body.update(_timing_body(span, switching_kind=span.all_day != _is_all_day(existing)))

        event = (
            service.events()
            .patch(calendarId=target, eventId=event_id, body=body, sendUpdates="all")
            .execute()
        )
        return _event_from_raw(event, target)

    def delete_event(self, event_id: str, calendar_id: str = PRIMARY_CALENDAR_ID) -> None:
        service = self._service(_write_scopes(calendar_id))
        target = _resolve_calendar(service, calendar_id, write=True)
        self._get_own_event(service, target, event_id)
        # sendUpdates="all": attendees (if any) get a real cancellation
        # email immediately, same owner-chosen, no-approval design as
        # create_event above. No invite guard runs here -- the
        # cancellation email carries the event's EXISTING title, which
        # was already screened either at create_event or by update_event's
        # guard above; deletion itself introduces no new unscreened text.
        service.events().delete(calendarId=target, eventId=event_id, sendUpdates="all").execute()


def _write_scopes(calendar_id: str) -> list[str]:
    """The primary calendar needs only the events scope, as it always has.
    Any other calendar_id is checked against the account's calendar list
    first, which `calendar.events` alone cannot read."""
    if calendar_id == PRIMARY_CALENDAR_ID:
        return [CALENDAR_EVENTS_SCOPE]
    return [CALENDAR_READONLY_SCOPE, CALENDAR_EVENTS_SCOPE]


def _calendar_list_entries(service) -> list[dict]:
    entries: list[dict] = []
    page_token = None
    while True:
        resp = service.calendarList().list(pageToken=page_token).execute()
        entries.extend(resp.get("items", []))
        page_token = resp.get("nextPageToken")
        if not page_token:
            return entries


def unusable_calendar_reason(*, write: bool) -> str:
    """The one wording for "that calendar_id can't be used" -- shared with
    the test fake so a reply test sees exactly what a requester would."""
    return (
        f"calendar_id is not a calendar this account can {'write to' if write else 'read'} "
        "-- use an id from calendar.list_calendars, or omit it for the primary calendar"
    )


def _resolve_calendar(service, calendar_id: str, *, write: bool) -> str:
    """The id to send to Google for `calendar_id`, or a denial. "primary" is
    Google's own alias and needs no lookup. Anything else must be a calendar
    in the account's own list with enough access (see the module docstring),
    matched case-insensitively and returned in Google's own spelling. The
    reason never echoes the requested id."""
    if calendar_id == PRIMARY_CALENDAR_ID:
        return PRIMARY_CALENDAR_ID
    allowed = _WRITE_ROLES if write else _READ_ROLES
    wanted = calendar_id.lower()
    for entry in _calendar_list_entries(service):
        if (entry.get("id") or "").lower() == wanted and entry.get("accessRole") in allowed:
            return entry["id"]
    raise GatekeeperDenied("invalid_params", unusable_calendar_reason(write=write))


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


def _event_from_raw(event: dict, calendar_id: str = "") -> CalendarEvent:
    """Same fixed-key extraction discipline as the inline construction in
    list_events (see the module docstring) -- used by create_event/
    update_event, which get a single event dict back from the API
    instead of a list. `calendar_id` is the calendar the call targeted:
    Google's response doesn't say which calendar an event is on."""
    start = event.get("start", {}) or {}
    end = event.get("end", {}) or {}
    return CalendarEvent(
        event_id=event.get("id", ""),
        summary=event.get("summary", "") or "",
        start=start.get("date") or start.get("dateTime") or "",
        end=end.get("date") or end.get("dateTime") or "",
        all_day="date" in start,
        attendee_count=len(event.get("attendees", []) or []),
        location=event.get("location", "") or "",
        calendar_id=calendar_id,
    )


def _is_all_day(event: dict) -> bool:
    return "date" in (event.get("start") or {})


def _timing_body(span: EventTimeSpan, *, switching_kind: bool = False) -> dict:
    """The `start`/`end` part of an insert or patch body. `switching_kind`
    (an update that turns a timed event all-day, or the reverse): the patch
    API MERGES nested objects, so the old kind's field has to be nulled or
    the event would end up with both a `date` and a `dateTime`."""
    if span.all_day:
        start: dict = {"date": span.start}
        end: dict = {"date": span.end}
        if switching_kind:
            start["dateTime"] = end["dateTime"] = None
    else:
        start = {"dateTime": span.start, "timeZone": OWNER_TIMEZONE}
        end = {"dateTime": span.end, "timeZone": OWNER_TIMEZONE}
        if switching_kind:
            start["date"] = end["date"] = None
    return {"start": start, "end": end}


def _resolve_new_timing(
    day_offset: int, start_time: str | None, duration_minutes: int | None,
    end_day_offset: int | None, end_time: str | None, all_day: bool,
) -> EventTimeSpan:
    """create_event's timing, from what app/policy.py already validated. The
    branches are re-checked rather than trusted: a combination policy would
    have denied is a denial here too, never a TypeError."""
    if all_day:
        return resolve_all_day_range(
            day_offset, day_offset if end_day_offset is None else end_day_offset, OWNER_TIMEZONE
        )
    if start_time is None:
        raise GatekeeperDenied("invalid_params", "a timed event needs a start_time")
    if end_day_offset is not None and end_time is not None and duration_minutes is None:
        return resolve_event_range(day_offset, start_time, end_day_offset, end_time, OWNER_TIMEZONE)
    if duration_minutes is not None and end_day_offset is None and end_time is None:
        return resolve_event_datetime(day_offset, start_time, duration_minutes, OWNER_TIMEZONE)
    raise GatekeeperDenied("invalid_params", "give either duration_minutes or end_day_offset + end_time")


def _resolve_updated_timing(
    existing: dict,
    *,
    day_offset: int | None,
    start_time: str | None,
    duration_minutes: int | None,
    end_day_offset: int | None,
    end_time: str | None,
    all_day: bool | None,
    now: datetime | None = None,
) -> EventTimeSpan:
    """update_event lets a request change only some of the timing fields --
    this fills in whichever weren't given from the event's CURRENT start/end
    (fetched by the caller), so e.g. changing only start_time doesn't
    silently reset the event's day or duration to something unintended, and
    moving an event by day_offset alone keeps its length (in hours for a
    timed event, in days for an all-day one). `all_day` omitted keeps the
    event's kind; the request has to say so to convert it. Anything the
    request and the existing event together can't make sense of is a denial
    with the reason, not a guess."""
    tz = ZoneInfo(OWNER_TIMEZONE)
    now = now or datetime.now(tz)

    def _as_local(raw: dict) -> datetime:
        value = raw.get("dateTime") or raw.get("date")
        dt = datetime.fromisoformat(value)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=tz)
        return dt.astimezone(tz)

    existing_all_day = _is_all_day(existing)
    existing_start = _as_local(existing.get("start", {}) or {})
    existing_end = _as_local(existing.get("end", {}) or {})
    today = now.astimezone(tz).date()
    existing_start_offset = (existing_start.date() - today).days
    target_all_day = existing_all_day if all_day is None else all_day
    time_fields = [
        name for name, value in (("start_time", start_time), ("end_time", end_time), ("duration_minutes", duration_minutes))
        if value is not None
    ]

    if target_all_day:
        if time_fields:
            if all_day is None:
                raise GatekeeperDenied(
                    "invalid_params",
                    "this is an all-day event: to give it a time of day send all_day: false together with "
                    "start_time and duration_minutes (or end_day_offset + end_time); otherwise remove "
                    + ", ".join(time_fields),
                )
            raise GatekeeperDenied("invalid_params", f"an all-day event has no time of day: remove {', '.join(time_fields)}")
        # How many calendar days the event covers now, so a move keeps it.
        # An all-day `end` is exclusive; a timed event ending exactly at
        # midnight doesn't touch the day that starts there.
        first = existing_start.date()
        if existing_all_day:
            last = (existing_end - timedelta(days=1)).date()
        else:
            last = existing_end.date()
            if existing_end.time() == time(0, 0) and last > first:
                last -= timedelta(days=1)
        start_offset = day_offset if day_offset is not None else existing_start_offset
        last_offset = end_day_offset if end_day_offset is not None else start_offset + (last - first).days
        problem = all_day_span_problem(start_offset, last_offset)
        if problem:
            raise GatekeeperDenied("invalid_params", problem)
        return resolve_all_day_range(start_offset, last_offset, OWNER_TIMEZONE, now=now)

    if (end_day_offset is None) != (end_time is None):
        raise GatekeeperDenied("invalid_params", "a timed event's end needs both end_day_offset and end_time")
    if existing_all_day:
        # Nothing to preserve: an all-day event has no time of day or duration.
        if start_time is None or (duration_minutes is None and end_time is None):
            raise GatekeeperDenied(
                "invalid_params",
                "making an all-day event timed needs start_time and either duration_minutes or end_day_offset + end_time",
            )
        base_start_time, base_duration = start_time, None
    else:
        base_start_time = start_time if start_time is not None else existing_start.strftime("%H:%M")
        base_duration = int((existing_end - existing_start).total_seconds() // 60)

    start_offset = day_offset if day_offset is not None else existing_start_offset
    if end_time is not None and end_day_offset is not None:
        minutes = timed_span_minutes(start_offset, base_start_time, end_day_offset, end_time)
        span = resolve_event_range(start_offset, base_start_time, end_day_offset, end_time, OWNER_TIMEZONE, now=now)
    else:
        minutes = duration_minutes if duration_minutes is not None else base_duration
        if minutes is None:  # unreachable: the all-day branch above guarantees a duration
            raise GatekeeperDenied("invalid_params", "the event's length could not be determined")
        span = resolve_event_datetime(start_offset, base_start_time, minutes, OWNER_TIMEZONE, now=now)
    problem = timed_span_problem(minutes)
    if problem:
        raise GatekeeperDenied("invalid_params", problem)
    return span
