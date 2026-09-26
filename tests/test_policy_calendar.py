"""Layer 3 tests for the 2026-09-25 calendar extensions: calendar selection
(calendar.list_calendars, calendar_id), multi-day / all-day events, and a
past window with a query for list_events. The older bounds live in
test_policy.py."""
from __future__ import annotations

import pytest

from app.policy import (
    EVENT_SPAN_MAX_DAYS,
    VERB_SPECS,
    CalendarCreateEventParams,
    CalendarDeleteEventParams,
    CalendarListCalendarsParams,
    CalendarListEventsParams,
    CalendarUpdateEventParams,
    Verb,
    evaluate_policy,
)

_FAMILY = "abc123def456@group.calendar.google.com"


def _create(**overrides):
    params = {"title": "Trip", "day_offset": 6, "start_time": "16:00"}
    params.update(overrides)
    return evaluate_policy("calendar.create_event", {k: v for k, v in params.items() if v is not ...})


def _update(**overrides):
    return evaluate_policy("calendar.update_event", {"event_id": "ev1", **overrides})


def _denied(decision, fragment: str | None = None):
    assert decision.status == "denied" and decision.error_code == "invalid_params", decision
    if fragment:
        assert fragment in decision.reason, decision.reason


# ── calendar.list_calendars ─────────────────────────────────────────────


def test_list_calendars_takes_no_params_and_is_a_read():
    decision = evaluate_policy("calendar.list_calendars", {})
    assert decision.status == "allowed" and decision.params == CalendarListCalendarsParams()
    assert Verb.CALENDAR_LIST_CALENDARS not in {v for v in VERB_SPECS if VERB_SPECS[v].is_write}


def test_list_calendars_ignores_and_reports_extra_params():
    decision = evaluate_policy("calendar.list_calendars", {"calendar_id": _FAMILY})
    assert decision.status == "allowed" and decision.ignored_params == ("calendar_id",)


# ── calendar.list_events: calendar_id, past window, query ───────────────


def test_list_events_without_calendar_id_or_query_means_every_visible_calendar():
    params = evaluate_policy("calendar.list_events", {}).params
    assert params.calendar_id is None and params.query is None


def test_list_events_over_a_past_window_with_a_query():
    decision = evaluate_policy(
        "calendar.list_events", {"day_offset": -365, "days": 366, "query": "Dana Levi", "max_results": 25}
    )
    assert decision.status == "allowed"
    assert decision.params == CalendarListEventsParams(
        day_offset=-365, days=366, max_results=25, calendar_id=None, query="Dana Levi"
    )


@pytest.mark.parametrize("calendar_id", ["primary", _FAMILY, "me@gmail.com", "en.jewish#holiday@group.v.calendar.google.com"])
def test_list_events_accepts_a_calendar_id(calendar_id):
    decision = evaluate_policy("calendar.list_events", {"calendar_id": calendar_id})
    assert decision.status == "allowed" and decision.params.calendar_id == calendar_id


@pytest.mark.parametrize("calendar_id", [
    "", "   ", None, 7, ["primary"], "a/b", "a b", "cal?x=1", "../primary", "cal\nid", "x" * 257,
])
def test_calendar_id_shape_is_checked(calendar_id):
    _denied(evaluate_policy("calendar.list_events", {"calendar_id": calendar_id}), "calendar_id")
    _denied(evaluate_policy("calendar.delete_event", {"event_id": "ev1", "calendar_id": calendar_id}), "calendar_id")


@pytest.mark.parametrize("query", ["", "  ", None, 5, "two\nlines", "x" * 201])
def test_list_events_query_is_checked(query):
    _denied(evaluate_policy("calendar.list_events", {"query": query}), "query")


# ── calendar.create_event: calendar_id ──────────────────────────────────


def test_create_event_calendar_id_defaults_to_primary():
    assert _create(duration_minutes=30).params.calendar_id == "primary"


def test_create_event_on_another_calendar():
    decision = _create(duration_minutes=30, calendar_id=_FAMILY)
    assert decision.status == "allowed" and decision.params.calendar_id == _FAMILY
    assert decision.params.attendees == ()  # a calendar_id never adds guests


# ── calendar.create_event: overnight / multi-day (end_day_offset + end_time) ─


def test_create_event_19_hours_across_midnight():
    """The case Instinct hit: day 6 at 16:00 to day 7 at 11:00."""
    decision = _create(end_day_offset=7, end_time="11:00")
    assert decision.status == "allowed"
    assert decision.params == CalendarCreateEventParams(
        title="Trip", day_offset=6, start_time="16:00", duration_minutes=None,
        end_day_offset=7, end_time="11:00",
    )


def test_create_event_end_pair_is_not_capped_at_the_8_hour_duration_limit():
    assert _create(duration_minutes=481).status == "denied"
    assert _create(end_day_offset=6, end_time="23:59").status == "allowed"  # 7h59 the same day
    assert _create(end_day_offset=7, end_time="16:00").status == "allowed"  # 24h


@pytest.mark.parametrize("overrides", [
    {"duration_minutes": 60, "end_day_offset": 7, "end_time": "11:00"},
    {"duration_minutes": 60, "end_day_offset": 7},
    {"duration_minutes": 60, "end_time": "11:00"},
])
def test_create_event_rejects_duration_together_with_an_end(overrides):
    _denied(_create(**overrides), "not both")


@pytest.mark.parametrize("overrides", [{"end_day_offset": 7}, {"end_time": "11:00"}])
def test_create_event_end_pair_must_be_complete(overrides):
    _denied(_create(**overrides), "together")


def test_create_event_needs_a_duration_or_an_end():
    _denied(_create(), "duration_minutes")


def test_create_event_timed_needs_a_start_time():
    _denied(_create(start_time=..., duration_minutes=30), "start_time")


@pytest.mark.parametrize("end_day_offset, end_time", [
    (6, "16:00"),  # zero length
    (6, "16:04"),  # under the 5-minute minimum
    (6, "15:00"),  # ends before it starts
    (5, "23:00"),  # a day earlier
])
def test_create_event_end_must_be_after_start(end_day_offset, end_time):
    _denied(_create(end_day_offset=end_day_offset, end_time=end_time))


def test_create_event_span_is_capped_at_14_days():
    assert _create(end_day_offset=6 + EVENT_SPAN_MAX_DAYS, end_time="16:00").status == "allowed"  # exactly 14 days
    _denied(_create(end_day_offset=6 + EVENT_SPAN_MAX_DAYS, end_time="16:01"), "14 days")
    _denied(_create(end_day_offset=6 + EVENT_SPAN_MAX_DAYS + 1, end_time="10:00"), "14 days")


@pytest.mark.parametrize("bad", ["25:00", "9:00", "noon", 900, None, True])
def test_create_event_end_time_must_be_hh_mm(bad):
    _denied(_create(end_day_offset=7, end_time=bad), "end_time")


@pytest.mark.parametrize("bad", [-1, True, "7", 1.5, 380, None])
def test_create_event_end_day_offset_must_be_a_bounded_int(bad):
    _denied(_create(end_day_offset=bad, end_time="11:00"), "end_day_offset")


# ── calendar.create_event: all-day ──────────────────────────────────────


def test_create_all_day_event_is_a_single_day_unless_an_end_is_given():
    decision = _create(start_time=..., all_day=True)
    assert decision.status == "allowed"
    assert decision.params.all_day is True
    assert decision.params.day_offset == 6 and decision.params.end_day_offset == 6
    assert decision.params.start_time is None and decision.params.duration_minutes is None


def test_create_all_day_event_across_several_days():
    decision = _create(start_time=..., all_day=True, end_day_offset=8)
    assert decision.status == "allowed"
    assert (decision.params.day_offset, decision.params.end_day_offset) == (6, 8)


@pytest.mark.parametrize("clash", [{"start_time": "10:00"}, {"end_time": "11:00"}, {"duration_minutes": 30}])
def test_create_all_day_event_has_no_time_of_day(clash):
    overrides = {"start_time": ..., "all_day": True, **clash}
    _denied(_create(**overrides), "no time of day")


def test_all_day_span_is_capped_at_14_days_the_last_day_included():
    assert _create(start_time=..., all_day=True, end_day_offset=6 + EVENT_SPAN_MAX_DAYS - 1).status == "allowed"
    _denied(_create(start_time=..., all_day=True, end_day_offset=6 + EVENT_SPAN_MAX_DAYS), "14 days")


def test_all_day_end_may_not_precede_the_start():
    _denied(_create(start_time=..., all_day=True, end_day_offset=5), "not be before")


@pytest.mark.parametrize("value", [True, "true", "True", " TRUE "])
def test_all_day_accepts_true_however_yaml_delivers_it(value):
    """app/yaml_safe.py leaves an unquoted `true` a STRING, so "true" has to work."""
    assert _create(start_time=..., all_day=value).params.all_day is True


@pytest.mark.parametrize("value", [False, "false", "False"])
def test_all_day_false_is_an_ordinary_timed_event(value):
    decision = _create(duration_minutes=30, all_day=value)
    assert decision.status == "allowed" and decision.params.all_day is False
    _denied(_create(all_day=value), "duration_minutes")  # a start but no length: still incomplete


@pytest.mark.parametrize("value", ["yes", "on", "1", 1, 0, None, "", [True], "maybe"])
def test_all_day_rejects_anything_else(value):
    _denied(_create(duration_minutes=30, all_day=value), "all_day")


# ── calendar.update_event ───────────────────────────────────────────────


def test_update_event_calendar_id():
    assert _update(title="x").params.calendar_id == "primary"
    assert _update(title="x", calendar_id=_FAMILY).params.calendar_id == _FAMILY
    _denied(_update(title="x", calendar_id="a/b"), "calendar_id")


def test_update_event_moves_the_end_with_end_day_offset_and_end_time():
    decision = _update(end_day_offset=7, end_time="11:00")
    assert decision.status == "allowed"
    assert decision.params == CalendarUpdateEventParams(event_id="ev1", end_day_offset=7, end_time="11:00")


def test_update_event_19_hours_across_midnight():
    decision = _update(day_offset=6, start_time="16:00", end_day_offset=7, end_time="11:00")
    assert decision.status == "allowed"


def test_update_event_all_day_alone_is_an_update():
    for value in (True, False):
        decision = _update(all_day=value)
        assert decision.status == "allowed" and decision.params.all_day is value
    assert _update().status == "denied"  # nothing to change at all


def test_update_event_all_day_with_a_range():
    decision = _update(all_day=True, day_offset=3, end_day_offset=5)
    assert decision.status == "allowed"
    _denied(_update(all_day=True, day_offset=3, end_day_offset=2), "not be before")
    _denied(_update(all_day=True, day_offset=3, end_day_offset=3 + EVENT_SPAN_MAX_DAYS), "14 days")


@pytest.mark.parametrize("clash", [{"start_time": "10:00"}, {"end_time": "11:00"}, {"duration_minutes": 30}])
def test_update_event_all_day_true_has_no_time_of_day(clash):
    _denied(_update(all_day=True, **clash), "no time of day")


def test_update_event_all_day_omitted_leaves_the_kind_to_the_executor():
    """An end_day_offset alone could be an all-day event's new last day or
    half of a timed end; only the existing event says which."""
    assert _update(end_day_offset=9).status == "allowed"


@pytest.mark.parametrize("overrides, fragment", [
    ({"duration_minutes": 30, "end_day_offset": 7, "end_time": "11:00"}, "not both"),
    ({"duration_minutes": 30, "end_day_offset": 7}, "not both"),
    ({"end_time": "11:00"}, "together"),
    ({"all_day": False, "end_day_offset": 7}, "together"),
])
def test_update_event_timing_combinations_that_never_make_sense(overrides, fragment):
    _denied(_update(**overrides), fragment)


def test_update_event_full_timed_range_is_bounds_checked():
    _denied(_update(day_offset=6, start_time="16:00", end_day_offset=6, end_time="16:02"), "at least")
    _denied(_update(day_offset=6, start_time="16:00", end_day_offset=21, end_time="16:01"), "14 days")


def test_update_event_partial_range_is_finished_by_the_executor():
    assert _update(end_day_offset=7, end_time="11:00", start_time="09:00").status == "allowed"


# ── calendar.delete_event ───────────────────────────────────────────────


def test_delete_event_calendar_id():
    assert evaluate_policy("calendar.delete_event", {"event_id": "ev1"}).params == CalendarDeleteEventParams(event_id="ev1")
    decision = evaluate_policy("calendar.delete_event", {"event_id": "ev1", "calendar_id": _FAMILY})
    assert decision.params == CalendarDeleteEventParams(event_id="ev1", calendar_id=_FAMILY)


# ── the registry (what `capabilities` reports) ─────────────────────────


def test_every_declared_param_is_documented_in_its_verbs_bounds():
    """capabilities is read from param_bounds: a param a verb accepts but
    that no bound line names would be invisible to Instinct."""
    for verb, spec in VERB_SPECS.items():
        documented = {line.split(":", 1)[0] for line in spec.param_bounds}
        assert spec.param_names <= documented, (verb, spec.param_names - documented)


def test_the_new_params_are_in_the_registry():
    specs = {verb.value: spec for verb, spec in VERB_SPECS.items()}
    assert specs["calendar.list_calendars"].param_names == frozenset()
    assert {"calendar_id", "query"} <= specs["calendar.list_events"].param_names
    for verb in ("calendar.create_event", "calendar.update_event"):
        assert {"calendar_id", "end_day_offset", "end_time", "all_day"} <= specs[verb].param_names
    assert "calendar_id" in specs["calendar.delete_event"].param_names
    assert not specs["calendar.list_calendars"].is_write
    assert all(specs[v].is_write for v in ("calendar.create_event", "calendar.update_event", "calendar.delete_event"))
