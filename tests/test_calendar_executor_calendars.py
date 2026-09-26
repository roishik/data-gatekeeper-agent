"""
GoogleCalendarClient tests for the 2026-09-25 extensions: choosing a
calendar (list_calendars, calendar_id), overnight / multi-day / all-day
events, and a past window with a query.

"Today" is frozen at Fri 2026-09-25 (Asia/Jerusalem, +03:00 until the DST
switch on Oct 25), so every expected timestamp is a literal:
    day_offset 6 = Thu 2026-10-01, day_offset 7 = Fri 2026-10-02, ...
The fake Google services are the same shape as test_calendar_executor.py's.
"""
from __future__ import annotations

from datetime import datetime
from zoneinfo import ZoneInfo

import pytest

from app.calendar_executor import (
    CALENDAR_EVENTS_SCOPE,
    CALENDAR_READONLY_SCOPE,
    GoogleCalendarClient,
    is_gatekeeper_event,
)
from app.failures import GatekeeperDenied
from tests.test_calendar_executor import _OWN, _Call, _CalendarList, _no_guard, _timed, _WriteEvents

FAMILY = "family123@group.calendar.google.com"
_TZ = ZoneInfo("Asia/Jerusalem")


@pytest.fixture(autouse=True)
def frozen_today(monkeypatch):
    class _Frozen(datetime):
        @classmethod
        def now(cls, _tz=None):
            return datetime(2026, 9, 25, 12, 0, tzinfo=_TZ)

    monkeypatch.setattr("app.calendar_window.datetime", _Frozen)
    monkeypatch.setattr("app.calendar_executor.datetime", _Frozen)


def _entry(calendar_id, role, name="", primary=False, override=None, selected=True):
    entry = {"id": calendar_id, "accessRole": role, "summary": name, "selected": selected}
    if primary:
        entry["primary"] = True
    if override:
        entry["summaryOverride"] = override
    return entry


ENTRIES = [
    _entry("shared-reader@group.calendar.google.com", "reader", "Read only"),
    _entry("busy@example.com", "freeBusyReader", "Free/busy only"),
    _entry(FAMILY, "writer", "Family", override="למשפחה"),
    _entry("me@gmail.com", "owner", "Roi", primary=True),
    _entry("work@group.calendar.google.com", "owner", "Work"),
]


class _ListEvents:
    """events().list that records every kwarg (the query, the window)."""

    def __init__(self, by_calendar=None):
        self.by_calendar = by_calendar or {}
        self.list_calls: list[dict] = []

    def list(self, calendarId, **kwargs):
        self.list_calls.append({"calendarId": calendarId, **kwargs})
        return _Call({"items": self.by_calendar.get(calendarId, [])})


class _Service:
    def __init__(self, events, entries=ENTRIES):
        self._events = events
        self._calendar_list = _CalendarList({None: {"items": entries}})
        self.calendar_list_calls = 0

    def calendarList(self):
        self.calendar_list_calls += 1
        return self._calendar_list

    def events(self):
        return self._events


def _client(service):
    """The client plus the log of scope sets it asked Google credentials for."""
    scopes_log: list[list[str]] = []
    client = GoogleCalendarClient()

    def _service(scopes=None):
        scopes_log.append(list(scopes or []))
        return service

    client._service = _service  # type: ignore[method-assign]
    return client, scopes_log


def _create(client, **overrides):
    kwargs = dict(title="Trip", day_offset=6, start_time="16:00", duration_minutes=None, attendees=(), request_id="req_1")
    kwargs.update(overrides)
    return client.create_event(**kwargs)


def _update(client, **overrides):
    kwargs = dict(event_id="ev1", title=None, day_offset=None, start_time=None, duration_minutes=None,
                  add_attendees=(), remove_attendees=(), invite_guard=_no_guard)
    kwargs.update(overrides)
    return client.update_event(**kwargs)


# ── calendar.list_calendars ─────────────────────────────────────────────


def test_list_calendars_returns_only_calendars_the_account_can_write_to():
    client, scopes = _client(_Service(_ListEvents()))
    calendars = client.list_calendars()

    # Primary first, then by name (code-point order: "Work" sorts before Hebrew "למשפחה").
    assert [c.calendar_id for c in calendars] == ["me@gmail.com", "work@group.calendar.google.com", FAMILY]
    assert [c.access_role for c in calendars] == ["owner", "owner", "writer"]
    assert scopes == [[CALENDAR_READONLY_SCOPE]]  # a read: no write scope involved


def test_list_calendars_puts_primary_first_and_prefers_the_users_own_name_for_a_calendar():
    calendars = _client(_Service(_ListEvents()))[0].list_calendars()
    assert calendars[0].primary and calendars[0].name == "Roi"
    family = next(c for c in calendars if c.calendar_id == FAMILY)
    assert family.name == "למשפחה" and not family.primary  # summaryOverride, not the calendar's own title


# ── calendar.list_events: calendar_id ───────────────────────────────────


def test_list_events_with_a_calendar_id_reads_only_that_calendar():
    events = _ListEvents({
        FAMILY: [_timed("f1", "Dinner", "2026-09-26T19:00:00+03:00")],
        "me@gmail.com": [_timed("m1", "Standup", "2026-09-26T09:00:00+03:00")],
    })
    client, _ = _client(_Service(events))
    result = client.list_events("2026-09-26T00:00:00+03:00", "2026-09-27T00:00:00+03:00", 10, calendar_id=FAMILY)

    assert [c["calendarId"] for c in events.list_calls] == [FAMILY]
    assert [(e.summary, e.calendar_id) for e in result] == [("Dinner", FAMILY)]


def test_list_events_without_a_calendar_id_still_reads_every_visible_calendar_and_tags_each_event():
    events = _ListEvents({
        FAMILY: [_timed("f1", "Dinner", "2026-09-26T19:00:00+03:00")],
        "me@gmail.com": [_timed("m1", "Standup", "2026-09-26T09:00:00+03:00")],
    })
    result = _client(_Service(events))[0].list_events("2026-09-26T00:00:00+03:00", "2026-09-27T00:00:00+03:00", 10)

    assert {c["calendarId"] for c in events.list_calls} >= {FAMILY, "me@gmail.com"}
    assert {e.summary: e.calendar_id for e in result} == {"Dinner": FAMILY, "Standup": "me@gmail.com"}


def test_list_events_primary_alias_needs_no_calendar_list_lookup():
    service = _Service(_ListEvents({"primary": [_timed("p1", "Solo", "2026-09-26T09:00:00+03:00")]}))
    result = _client(service)[0].list_events(
        "2026-09-26T00:00:00+03:00", "2026-09-27T00:00:00+03:00", 10, calendar_id="primary"
    )
    assert [e.calendar_id for e in result] == ["primary"]
    assert service.calendar_list_calls == 0


def test_list_events_reads_a_read_only_calendar_but_not_a_free_busy_one_or_an_unknown_one():
    events = _ListEvents({"shared-reader@group.calendar.google.com": [_timed("r", "Shared", "2026-09-26T10:00:00+03:00")]})
    client, _ = _client(_Service(events))
    window = ("2026-09-26T00:00:00+03:00", "2026-09-27T00:00:00+03:00", 10)

    assert client.list_events(*window, calendar_id="shared-reader@group.calendar.google.com")[0].summary == "Shared"
    for refused in ("busy@example.com", "nobody@group.calendar.google.com"):
        with pytest.raises(GatekeeperDenied) as denied:
            client.list_events(*window, calendar_id=refused)
        assert denied.value.error_code == "invalid_params"
    assert [c["calendarId"] for c in events.list_calls] == ["shared-reader@group.calendar.google.com"]


# ── calendar.list_events: a past window with a query ────────────────────


def test_list_events_over_a_past_window_with_a_query():
    events = _ListEvents({
        "me@gmail.com": [
            _timed("old1", "Coffee with Dana", "2025-11-03T10:00:00+02:00"),
            _timed("old2", "Dana / roadmap", "2026-03-12T15:30:00+02:00"),
            _timed("gone", "Before the window", "2025-09-24T10:00:00+03:00"),  # Google returned it anyway
        ],
    })
    client, _ = _client(_Service(events, entries=[_entry("me@gmail.com", "owner", primary=True)]))

    result = client.list_events(
        time_min="2025-09-25T00:00:00+03:00", time_max="2026-09-25T00:00:00+03:00", max_results=25, query="Dana",
    )

    assert [e.summary for e in result] == ["Coffee with Dana", "Dana / roadmap"]  # chronological, window re-checked
    (call,) = events.list_calls
    assert call["q"] == "Dana"
    assert call["timeMin"] == "2025-09-25T00:00:00+03:00" and call["timeMax"] == "2026-09-25T00:00:00+03:00"
    assert call["singleEvents"] is True and call["maxResults"] == 25


def test_list_events_sends_no_q_when_there_is_no_query():
    events = _ListEvents()
    _client(_Service(events))[0].list_events("t0", "t1", 5, calendar_id="primary")
    assert "q" not in events.list_calls[0]


# ── calendar.create_event: overnight / multi-day ────────────────────────


def test_create_event_19_hours_across_midnight():
    events = _WriteEvents()
    client, scopes = _client(_Service(events))

    result = _create(client, end_day_offset=7, end_time="11:00")

    (call,) = events.insert_calls
    assert call["calendarId"] == "primary"
    assert call["body"]["start"] == {"dateTime": "2026-10-01T16:00:00+03:00", "timeZone": "Asia/Jerusalem"}
    assert call["body"]["end"] == {"dateTime": "2026-10-02T11:00:00+03:00", "timeZone": "Asia/Jerusalem"}
    assert (result.start, result.end, result.all_day) == ("2026-10-01T16:00:00+03:00", "2026-10-02T11:00:00+03:00", False)
    assert scopes == [[CALENDAR_EVENTS_SCOPE]]  # the primary calendar: the same single scope as before


def test_create_event_span_across_the_dst_switch_carries_each_ends_own_offset():
    """Israel leaves DST on Oct 25: 20:00 on the 24th is +03:00, 10:00 on the 25th is +02:00."""
    events = _WriteEvents()
    _create(_client(_Service(events))[0], day_offset=29, start_time="20:00", end_day_offset=30, end_time="10:00")
    body = events.insert_calls[0]["body"]
    assert body["start"]["dateTime"] == "2026-10-24T20:00:00+03:00"
    assert body["end"]["dateTime"] == "2026-10-25T10:00:00+02:00"


def test_create_event_with_a_duration_is_unchanged():
    events = _WriteEvents()
    _create(_client(_Service(events))[0], duration_minutes=90)
    body = events.insert_calls[0]["body"]
    assert body["start"]["dateTime"] == "2026-10-01T16:00:00+03:00"
    assert body["end"]["dateTime"] == "2026-10-01T17:30:00+03:00"


# ── calendar.create_event: all-day ──────────────────────────────────────


def test_create_all_day_event_across_several_days_ends_the_day_after_the_last_day():
    events = _WriteEvents()
    result = _create(_client(_Service(events))[0], start_time=None, all_day=True, end_day_offset=8)

    body = events.insert_calls[0]["body"]
    # Oct 1 through Oct 3, the last day included -> Google's exclusive end is Oct 4.
    assert body["start"] == {"date": "2026-10-01"}
    assert body["end"] == {"date": "2026-10-04"}
    assert "dateTime" not in body["start"] and "timeZone" not in body["start"]
    assert (result.start, result.end, result.all_day) == ("2026-10-01", "2026-10-04", True)


def test_create_all_day_event_without_an_end_is_one_day():
    events = _WriteEvents()
    _create(_client(_Service(events))[0], start_time=None, all_day=True)
    body = events.insert_calls[0]["body"]
    assert (body["start"], body["end"]) == ({"date": "2026-10-01"}, {"date": "2026-10-02"})


# ── calendar.create_event: another calendar, and no invites ─────────────


def test_create_on_a_non_primary_calendar_without_attendees_sends_no_invites():
    events = _WriteEvents()
    client, scopes = _client(_Service(events))

    result = _create(client, duration_minutes=60, calendar_id=FAMILY)

    (call,) = events.insert_calls
    assert call["calendarId"] == FAMILY
    assert call["body"]["attendees"] == []
    assert call["sendUpdates"] == "none"  # nothing is mailed to anyone
    assert is_gatekeeper_event(call["body"])  # still tagged: it can be updated/deleted there later
    assert result.calendar_id == FAMILY
    assert scopes == [[CALENDAR_READONLY_SCOPE, CALENDAR_EVENTS_SCOPE]]  # the calendar list needs the read scope too


def test_create_on_a_non_primary_calendar_with_attendees_still_invites_them():
    events = _WriteEvents()
    _create(_client(_Service(events))[0], duration_minutes=60, calendar_id=FAMILY, attendees=("dana@example.com",))
    (call,) = events.insert_calls
    assert call["sendUpdates"] == "all" and call["body"]["attendees"] == [{"email": "dana@example.com"}]


def test_create_without_attendees_on_the_primary_calendar_also_sends_none():
    events = _WriteEvents()
    _create(_client(_Service(events))[0], duration_minutes=60)
    assert events.insert_calls[0]["sendUpdates"] == "none"


@pytest.mark.parametrize("calendar_id", [
    "shared-reader@group.calendar.google.com",  # can read it, can't write to it
    "busy@example.com",
    "nobody@group.calendar.google.com",  # not in the account's calendar list at all
])
def test_create_on_a_calendar_the_account_cannot_write_to_is_denied_before_any_insert(calendar_id):
    events = _WriteEvents()
    with pytest.raises(GatekeeperDenied) as denied:
        _create(_client(_Service(events))[0], duration_minutes=60, calendar_id=calendar_id)
    assert denied.value.error_code == "invalid_params"
    assert calendar_id not in denied.value.reason  # never echoes the requested id
    assert events.insert_calls == []


def test_calendar_id_matches_case_insensitively_and_is_sent_in_googles_own_spelling():
    events = _WriteEvents()
    _create(_client(_Service(events))[0], duration_minutes=60, calendar_id=FAMILY.upper())
    assert events.insert_calls[0]["calendarId"] == FAMILY


def test_the_primary_alias_needs_no_calendar_list_lookup_for_a_write():
    service = _Service(_WriteEvents())
    _create(_client(service)[0], duration_minutes=60, calendar_id="primary")
    assert service.calendar_list_calls == 0


# ── calendar.update_event ───────────────────────────────────────────────


def _existing(start, end, **extra):
    return {**_OWN, "summary": "Trip", "start": start, "end": end, **extra}


TIMED_19H = _existing({"dateTime": "2026-10-01T16:00:00+03:00"}, {"dateTime": "2026-10-02T11:00:00+03:00"})
ALL_DAY_3D = _existing({"date": "2026-10-01"}, {"date": "2026-10-04"})  # Oct 1-3 inclusive


def test_update_on_another_calendar_fetches_and_patches_that_calendar():
    events = _WriteEvents(get_result=dict(TIMED_19H))
    calls: list[tuple] = []
    original_get, original_patch = events.get, events.patch
    events.get = lambda calendarId, eventId: (calls.append(("get", calendarId)), original_get(calendarId, eventId))[1]
    events.patch = lambda calendarId, eventId, body, sendUpdates: (
        calls.append(("patch", calendarId)), original_patch(calendarId, eventId, body, sendUpdates))[1]

    result = _update(_client(_Service(events))[0], title="Renamed", calendar_id=FAMILY)

    assert calls == [("get", FAMILY), ("patch", FAMILY)]
    assert result.calendar_id == FAMILY


def test_update_and_delete_on_another_calendar_still_refuse_events_the_gatekeeper_did_not_create():
    events = _WriteEvents(get_result={"summary": "A family member's own event"})  # no gatekeeper tag
    client, _ = _client(_Service(events))
    with pytest.raises(GatekeeperDenied) as denied:
        _update(client, title="hijack", calendar_id=FAMILY)
    assert denied.value.error_code == "not_gatekeeper_event"
    with pytest.raises(GatekeeperDenied) as denied:
        client.delete_event("ev1", calendar_id=FAMILY)
    assert denied.value.error_code == "not_gatekeeper_event"
    assert events.patch_calls == [] and events.delete_calls == []


def test_update_or_delete_on_a_calendar_the_account_cannot_write_to_is_denied_without_touching_the_event():
    events = _WriteEvents()
    client, _ = _client(_Service(events))
    with pytest.raises(GatekeeperDenied) as denied:
        _update(client, title="x", calendar_id="shared-reader@group.calendar.google.com")
    assert denied.value.error_code == "invalid_params"
    with pytest.raises(GatekeeperDenied):
        client.delete_event("ev1", calendar_id="nobody@group.calendar.google.com")
    assert events.get_calls == [] and events.patch_calls == [] and events.delete_calls == []


def test_delete_on_another_calendar():
    events = _WriteEvents()
    client, scopes = _client(_Service(events))
    client.delete_event("ev1", calendar_id=FAMILY)
    assert events.get_calls == ["ev1"]
    assert events.delete_calls == [{"calendarId": FAMILY, "eventId": "ev1", "sendUpdates": "all"}]
    assert scopes == [[CALENDAR_READONLY_SCOPE, CALENDAR_EVENTS_SCOPE]]


def test_update_moves_the_end_of_a_timed_event_and_keeps_its_start():
    events = _WriteEvents(get_result=_existing({"dateTime": "2026-10-01T10:00:00+03:00"}, {"dateTime": "2026-10-01T11:00:00+03:00"}))
    _update(_client(_Service(events))[0], end_day_offset=7, end_time="11:00")
    body = events.patch_calls[0]["body"]
    assert body["start"]["dateTime"] == "2026-10-01T10:00:00+03:00"
    assert body["end"]["dateTime"] == "2026-10-02T11:00:00+03:00"
    assert "date" not in body["start"]  # timed -> timed: no null companions


def test_update_moving_a_19_hour_event_by_day_keeps_its_length():
    events = _WriteEvents(get_result=dict(TIMED_19H))
    _update(_client(_Service(events))[0], day_offset=8)
    body = events.patch_calls[0]["body"]
    assert body["start"]["dateTime"] == "2026-10-03T16:00:00+03:00"
    assert body["end"]["dateTime"] == "2026-10-04T11:00:00+03:00"


def test_update_start_time_alone_keeps_the_duration_of_an_overnight_event():
    events = _WriteEvents(get_result=dict(TIMED_19H))
    _update(_client(_Service(events))[0], start_time="18:00")
    body = events.patch_calls[0]["body"]
    assert body["start"]["dateTime"] == "2026-10-01T18:00:00+03:00"
    assert body["end"]["dateTime"] == "2026-10-02T13:00:00+03:00"  # still 19 hours


def test_update_moving_an_all_day_event_keeps_its_length_in_days():
    events = _WriteEvents(get_result=dict(ALL_DAY_3D))
    _update(_client(_Service(events))[0], day_offset=10)  # Oct 5
    body = events.patch_calls[0]["body"]
    assert (body["start"], body["end"]) == ({"date": "2026-10-05"}, {"date": "2026-10-08"})  # Oct 5-7 inclusive


def test_update_can_extend_an_all_day_event_to_a_new_last_day():
    events = _WriteEvents(get_result=dict(ALL_DAY_3D))
    _update(_client(_Service(events))[0], end_day_offset=9)  # through Oct 4
    body = events.patch_calls[0]["body"]
    assert (body["start"], body["end"]) == ({"date": "2026-10-01"}, {"date": "2026-10-05"})


def test_update_turning_a_timed_event_all_day_nulls_the_datetime_fields():
    """events.patch merges nested objects: without the nulls the event would
    carry both a `date` and a `dateTime`."""
    events = _WriteEvents(get_result=dict(TIMED_19H))
    result = _update(_client(_Service(events))[0], all_day=True)
    body = events.patch_calls[0]["body"]
    # Oct 1 16:00 - Oct 2 11:00 touches two calendar days: Oct 1-2 inclusive.
    assert body["start"] == {"date": "2026-10-01", "dateTime": None}
    assert body["end"] == {"date": "2026-10-03", "dateTime": None}
    assert result.all_day is True


def test_update_turning_an_all_day_event_timed_needs_a_time_and_a_length_and_nulls_the_date():
    events = _WriteEvents(get_result=dict(ALL_DAY_3D))
    client, _ = _client(_Service(events))
    for incomplete in ({}, {"start_time": "10:00"}, {"duration_minutes": 60}):
        with pytest.raises(GatekeeperDenied) as denied:
            _update(client, all_day=False, **incomplete)
        assert denied.value.error_code == "invalid_params" and "timed" in denied.value.reason
    assert events.patch_calls == []

    _update(client, all_day=False, start_time="10:00", duration_minutes=60)
    body = events.patch_calls[0]["body"]
    assert body["start"] == {"dateTime": "2026-10-01T10:00:00+03:00", "timeZone": "Asia/Jerusalem", "date": None}
    assert body["end"] == {"dateTime": "2026-10-01T11:00:00+03:00", "timeZone": "Asia/Jerusalem", "date": None}


def test_update_giving_an_all_day_event_a_time_without_saying_all_day_false_is_denied_with_the_fix():
    events = _WriteEvents(get_result=dict(ALL_DAY_3D))
    with pytest.raises(GatekeeperDenied) as denied:
        _update(_client(_Service(events))[0], start_time="10:00")
    assert denied.value.error_code == "invalid_params" and "all_day: false" in denied.value.reason
    assert events.patch_calls == []


def test_update_end_day_offset_without_end_time_on_a_timed_event_is_denied():
    events = _WriteEvents(get_result=dict(TIMED_19H))
    with pytest.raises(GatekeeperDenied) as denied:
        _update(_client(_Service(events))[0], end_day_offset=9)
    assert denied.value.error_code == "invalid_params" and "end_time" in denied.value.reason
    assert events.patch_calls == []


def test_update_that_would_make_an_event_longer_than_14_days_or_end_before_it_starts_is_denied():
    events = _WriteEvents(get_result=dict(TIMED_19H))
    client, _ = _client(_Service(events))
    for overrides, fragment in (
        ({"end_day_offset": 21, "end_time": "16:01"}, "14 days"),  # Oct 1 16:00 -> Oct 15 16:01
        ({"end_day_offset": 6, "end_time": "15:00"}, "at least"),  # ends before the Oct 1 16:00 start
    ):
        with pytest.raises(GatekeeperDenied) as denied:
            _update(client, **overrides)
        assert denied.value.error_code == "invalid_params" and fragment in denied.value.reason
    with pytest.raises(GatekeeperDenied):
        _update(_client(_Service(_WriteEvents(get_result=dict(ALL_DAY_3D))))[0], end_day_offset=6 + 14)  # 15 days
    assert events.patch_calls == []


def test_update_the_invite_guard_still_covers_an_event_on_another_calendar_with_guests():
    seen: list[tuple[str, str]] = []
    events = _WriteEvents(get_result={**TIMED_19H, "attendees": [{"email": "guest@example.com"}]})
    _update(_client(_Service(events))[0], title="New title", calendar_id=FAMILY,
            invite_guard=lambda t, l: seen.append((t, l)))
    assert seen == [("New title", "")]
