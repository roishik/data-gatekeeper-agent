"""
GoogleCalendarClient against a fake googleapiclient service: it must read
every calendar the owner has switched on (not just primary), skip hidden
ones, de-duplicate an event that appears on two calendars, and return a
single chronological list capped at max_results.
"""
from __future__ import annotations

from app.calendar_executor import GoogleCalendarClient


class _Call:
    def __init__(self, result):
        self._result = result

    def execute(self):
        return self._result


class _CalendarList:
    def __init__(self, pages):
        self._pages = pages

    def list(self, pageToken=None):
        return _Call(self._pages[pageToken])


class _Events:
    def __init__(self, by_calendar):
        self._by_calendar = by_calendar
        self.requested: list[str] = []

    def list(self, calendarId, **_kwargs):
        self.requested.append(calendarId)
        return _Call({"items": self._by_calendar.get(calendarId, [])})


class _Service:
    def __init__(self, pages, by_calendar):
        self._calendar_list = _CalendarList(pages)
        self._events = _Events(by_calendar)

    def calendarList(self):
        return self._calendar_list

    def events(self):
        return self._events


def _timed(event_id, summary, start, uid=None):
    return {
        "id": event_id,
        "iCalUID": uid or f"{event_id}@google.com",
        "summary": summary,
        "start": {"dateTime": start},
        "end": {"dateTime": start},
    }


def _client(service):
    client = GoogleCalendarClient()
    client._service = lambda: service  # type: ignore[method-assign]
    return client


PAGES = {
    None: {
        "items": [
            {"id": "me@gmail.com", "primary": True, "selected": True},
            {"id": "family@group.calendar.google.com", "selected": True},
        ],
        "nextPageToken": "p2",
    },
    "p2": {"items": [{"id": "hidden@group.calendar.google.com"}]},  # not selected
}

EVENTS = {
    "me@gmail.com": [
        _timed("a", "Interview", "2026-09-16T10:00:00+03:00"),
        _timed("b", "Meetup", "2026-09-16T17:30:00+03:00", uid="shared@x"),
    ],
    "family@group.calendar.google.com": [
        _timed("c", "Parents meeting", "2026-09-16T17:00:00+03:00"),
        _timed("b2", "Meetup", "2026-09-16T17:30:00+03:00", uid="shared@x"),  # same occurrence
        _timed("d", "Evening", "2026-09-16T20:30:00+03:00"),
    ],
    "hidden@group.calendar.google.com": [_timed("h", "Should not appear", "2026-09-16T12:00:00+03:00")],
}


def test_reads_all_selected_calendars_skips_hidden_and_dedupes():
    service = _Service(PAGES, EVENTS)
    events = _client(service).list_events("t0", "t1", max_results=10)

    assert [e.summary for e in events] == ["Interview", "Parents meeting", "Meetup", "Evening"]
    assert "hidden@group.calendar.google.com" not in service._events.requested


def test_orders_by_utc_instant_across_offsets_and_caps_results():
    events_by_cal = {
        "me@gmail.com": [_timed("x", "Later", "2026-09-16T10:00:00+03:00")],  # 07:00 UTC
        "family@group.calendar.google.com": [_timed("y", "Earlier", "2026-09-16T08:00:00+02:00")],  # 06:00 UTC
    }
    events = _client(_Service(PAGES, events_by_cal)).list_events("t0", "t1", max_results=1)
    assert [e.summary for e in events] == ["Earlier"]


def test_falls_back_to_primary_when_calendar_list_is_empty():
    service = _Service({None: {"items": []}}, {"primary": [_timed("p", "Solo", "2026-09-16T09:00:00+03:00")]})
    events = _client(service).list_events("t0", "t1", max_results=5)
    assert [e.summary for e in events] == ["Solo"]
    assert service._events.requested == ["primary"]
