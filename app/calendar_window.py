"""
calendar_window.py — deterministically resolves a day_offset/days pair
into a Google Calendar API timeMin/timeMax window, and formats an
event's start/end back into the owner's local time for the reply.
Entirely in Python; no LLM involved on either path.

This is the whole point of keeping day_offset/days as small bounded
integers all the way through Layers 2 and 3 (research/03 section 2.4's
"low-capacity output type" principle): "tomorrow" becomes day_offset=1
in the reader LLM's structured output, and everything from there --
what calendar date that actually IS, in which timezone, accounting for
DST -- is plain, testable code that never asks an LLM to do date
arithmetic.

Uses the stdlib `zoneinfo` (Python 3.9+, no extra dependency) rather
than pytz: zoneinfo is IANA-tzdata-backed and DST-correct by
construction -- a datetime built with tzinfo=ZoneInfo("Asia/Jerusalem")
reports the correct UTC offset for THAT SPECIFIC DATE (+02:00 or +03:00
depending on whether Israel is observing DST that day), which is exactly
what Google's Calendar API requires ("RFC3339 timestamp with mandatory
time zone offset" -- confirmed against the current events.list
reference during this build) and exactly what a naive fixed-offset
computation would get wrong across a DST transition.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo


@dataclass(frozen=True)
class CalendarWindow:
    time_min: str  # RFC3339 with offset, e.g. "2026-09-15T00:00:00+03:00"
    time_max: str


def resolve_window(day_offset: int, days: int, timezone_name: str, now: datetime | None = None) -> CalendarWindow:
    """Local midnight to local midnight, in `timezone_name`, starting
    `day_offset` days from today and spanning `days` days.
    `now` defaults to the real current time; tests pass a fixed value
    for reproducibility (see tests/test_calendar_window.py's DST case).
    Pure function -- no I/O, no dependence on anything but its
    arguments and (by default) the wall clock."""
    tz = ZoneInfo(timezone_name)
    current = (now or datetime.now(tz)).astimezone(tz)
    today_midnight = current.replace(hour=0, minute=0, second=0, microsecond=0)
    start = today_midnight + timedelta(days=day_offset)
    end = start + timedelta(days=days)
    return CalendarWindow(time_min=start.isoformat(), time_max=end.isoformat())


def format_event_time(iso_value: str, all_day: bool, timezone_name: str) -> str:
    """Renders a raw start/end value from the Calendar API (either an
    all-day `date` like "2026-09-15", or a timed `dateTime` like
    "2026-09-15T14:00:00+03:00") into a short, human-readable string in
    the owner's local timezone -- so the reply never shows a UTC or
    event-native offset the recipient has to mentally convert.

    All-day events have no time-of-day or timezone component to convert
    (Google's Calendar API returns a bare date for them, deliberately)
    -- shown as-is.
    """
    if all_day or "T" not in iso_value:
        return f"{iso_value} (all day)"
    try:
        dt = datetime.fromisoformat(iso_value)
    except ValueError:
        return iso_value  # never crash the reply over a malformed timestamp; show it verbatim
    if dt.tzinfo is not None:
        dt = dt.astimezone(ZoneInfo(timezone_name))
    return dt.strftime("%a %b %d, %H:%M")


def format_event_range(start: str, end: str, all_day: bool, timezone_name: str) -> str:
    """Renders a start/end pair for the reply -- the single-value
    `format_event_time` above only ever showed the start, which left a
    reply unable to say when a meeting ends. All-day events still
    collapse to one "(all day)" marker (there's no time-of-day to range
    over); a timed event's end is shown as just a time when it falls on
    the same local day as the start, since repeating the date adds
    nothing.
    """
    start_str = format_event_time(start, all_day, timezone_name)
    if all_day or "T" not in start or "T" not in end:
        return start_str
    try:
        start_dt = datetime.fromisoformat(start)
        end_dt = datetime.fromisoformat(end)
    except ValueError:
        return start_str
    if start_dt.tzinfo is not None:
        start_dt = start_dt.astimezone(ZoneInfo(timezone_name))
    if end_dt.tzinfo is not None:
        end_dt = end_dt.astimezone(ZoneInfo(timezone_name))
    if start_dt.date() == end_dt.date():
        return f"{start_str}–{end_dt.strftime('%H:%M')}"
    return f"{start_str}–{format_event_time(end, all_day, timezone_name)}"
