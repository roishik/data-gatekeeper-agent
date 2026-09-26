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
from datetime import date, datetime, timedelta
from zoneinfo import ZoneInfo


@dataclass(frozen=True)
class CalendarWindow:
    time_min: str  # RFC3339 with offset, e.g. "2026-09-15T00:00:00+03:00"
    time_max: str


@dataclass(frozen=True)
class EventTimeSpan:
    start: str  # RFC3339 with offset -- or an ISO date when all_day
    end: str  # for an all-day span this is Google's EXCLUSIVE end date (the day after the last day)
    all_day: bool = False


def resolve_event_datetime(
    day_offset: int, start_time: str, duration_minutes: int, timezone_name: str, now: datetime | None = None
) -> EventTimeSpan:
    """Same 'the LLM only ever picks small bounded tokens, Python does
    the date arithmetic' discipline as resolve_window, extended to a
    single timed event: day_offset (which day) + start_time (an
    'HH:MM' string, already validated by app/policy.py) + duration_minutes
    -> a concrete start/end RFC3339 pair in the owner's timezone. The
    reader LLM never produces a date, a full timestamp, or a timezone --
    only these three bounded fields."""
    tz = ZoneInfo(timezone_name)
    current = (now or datetime.now(tz)).astimezone(tz)
    today_midnight = current.replace(hour=0, minute=0, second=0, microsecond=0)
    day = today_midnight + timedelta(days=day_offset)
    hour, _, minute = start_time.partition(":")
    start = day.replace(hour=int(hour), minute=int(minute))
    end = start + timedelta(minutes=duration_minutes)
    return EventTimeSpan(start=start.isoformat(), end=end.isoformat())


def _local_midnight(timezone_name: str, now: datetime | None) -> datetime:
    tz = ZoneInfo(timezone_name)
    current = (now or datetime.now(tz)).astimezone(tz)
    return current.replace(hour=0, minute=0, second=0, microsecond=0)


def resolve_event_range(
    day_offset: int, start_time: str, end_day_offset: int, end_time: str, timezone_name: str,
    now: datetime | None = None,
) -> EventTimeSpan:
    """A timed event given by its START and END rather than a duration:
    (day_offset, start_time) -> (end_day_offset, end_time), all in the owner's
    timezone. This is how an overnight or multi-day event is expressed (e.g.
    day 6 at 16:00 to day 7 at 11:00 is 19 hours) -- a duration_minutes
    field tops out at 8 hours. Same discipline as resolve_event_datetime:
    only small bounded tokens go in, Python does every date calculation, and
    each end of the span gets the UTC offset of ITS OWN date (so a span
    across the DST switch carries two different offsets)."""
    midnight = _local_midnight(timezone_name, now)
    start_hour, _, start_minute = start_time.partition(":")
    end_hour, _, end_minute = end_time.partition(":")
    start = (midnight + timedelta(days=day_offset)).replace(hour=int(start_hour), minute=int(start_minute))
    end = (midnight + timedelta(days=end_day_offset)).replace(hour=int(end_hour), minute=int(end_minute))
    return EventTimeSpan(start=start.isoformat(), end=end.isoformat())


def resolve_all_day_range(
    day_offset: int, last_day_offset: int, timezone_name: str, now: datetime | None = None
) -> EventTimeSpan:
    """An all-day event from day `day_offset` through day `last_day_offset`,
    the last day INCLUDED (that's how a person says it). Google's all-day
    `end.date` is EXCLUSIVE, so the span's end is the day after the last
    day -- the one place that off-by-one is handled."""
    midnight = _local_midnight(timezone_name, now)
    first = (midnight + timedelta(days=day_offset)).date()
    end_exclusive = (midnight + timedelta(days=last_day_offset + 1)).date()
    return EventTimeSpan(start=first.isoformat(), end=end_exclusive.isoformat(), all_day=True)


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


def window_spans_other_years(
    time_min: str, time_max: str, timezone_name: str, now: datetime | None = None
) -> bool:
    """Whether a list window touches any calendar year other than the
    current one (owner's timezone). The reply then spells the year out in
    the window label and on every event line: "Sep 25" is ambiguous in a
    search over the past 12 months, and otherwise the year is left off, as
    it always was. `time_max` is exclusive, as in resolve_window."""
    tz = ZoneInfo(timezone_name)
    current_year = (now or datetime.now(tz)).astimezone(tz).year
    first = datetime.fromisoformat(time_min).astimezone(tz).date()
    last = (datetime.fromisoformat(time_max).astimezone(tz) - timedelta(days=1)).date()
    return first.year != current_year or last.year != current_year


def _date_format(with_year: bool) -> str:
    return "%a %b %d %Y" if with_year else "%a %b %d"


def format_event_time(iso_value: str, all_day: bool, timezone_name: str, with_year: bool = False) -> str:
    """Renders a raw start/end value from the Calendar API (either an
    all-day `date` like "2026-09-15", or a timed `dateTime` like
    "2026-09-15T14:00:00+03:00") into a short, human-readable string in
    the owner's local timezone -- so the reply never shows a UTC or
    event-native offset the recipient has to mentally convert.

    All-day events have no time-of-day or timezone component to convert
    (Google's Calendar API returns a bare date for them, deliberately)
    -- shown as-is. `with_year` adds the year to a timed value's date
    (an all-day date already carries it).
    """
    if all_day or "T" not in iso_value:
        return f"{iso_value} (all day)"
    try:
        dt = datetime.fromisoformat(iso_value)
    except ValueError:
        return iso_value  # never crash the reply over a malformed timestamp; show it verbatim
    if dt.tzinfo is not None:
        dt = dt.astimezone(ZoneInfo(timezone_name))
    return dt.strftime(f"{_date_format(with_year)}, %H:%M")


def format_window_range(time_min: str, time_max: str, timezone_name: str, with_year: bool = False) -> str:
    """Renders the day_offset/days window resolve_window resolved into a
    short human-readable date (or date range), e.g. "Tue Sep 23" for a
    single day or "Tue Sep 23 - Thu Sep 25" for a span -- so a
    calendar.list_events reply states which dates it actually searched
    (an email sent near local midnight can otherwise land on a different
    day than the sender expected day_offset to mean; this makes the
    resolved window checkable, the same way create_event's reply already
    echoes its resolved time). `time_max` is exclusive (local midnight
    the day AFTER the last day included), matching resolve_window."""
    tz = ZoneInfo(timezone_name)
    fmt = _date_format(with_year)
    start_date = datetime.fromisoformat(time_min).astimezone(tz).date()
    last_included = (datetime.fromisoformat(time_max).astimezone(tz) - timedelta(days=1)).date()
    if start_date == last_included:
        return start_date.strftime(fmt)
    return f"{start_date.strftime(fmt)} - {last_included.strftime(fmt)}"


def _format_all_day_range(start: str, end: str) -> str | None:
    """"2026-09-27 to 2026-09-29 (all day)" for a multi-day all-day event,
    or None for a single day (or anything unparseable) so the caller falls
    back to the one-date form. Google's all-day `end` is EXCLUSIVE, so the
    last day shown is the day before it."""
    try:
        first = date.fromisoformat(start)
        last = date.fromisoformat(end) - timedelta(days=1)
    except ValueError:
        return None
    return f"{first.isoformat()} to {last.isoformat()} (all day)" if last > first else None


def format_event_range(start: str, end: str, all_day: bool, timezone_name: str, with_year: bool = False) -> str:
    """Renders a start/end pair for the reply -- the single-value
    `format_event_time` above only ever showed the start, which left a
    reply unable to say when a meeting ends. A single all-day event
    collapses to one "(all day)" marker (there's no time-of-day to range
    over), a multi-day one shows its first and last day; a timed event's
    end is shown as just a time when it falls on the same local day as the
    start, since repeating the date adds nothing.
    """
    start_str = format_event_time(start, all_day, timezone_name, with_year)
    if all_day:
        return _format_all_day_range(start, end) or start_str
    if "T" not in start or "T" not in end:
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
    return f"{start_str}–{format_event_time(end, all_day, timezone_name, with_year)}"
