"""app/calendar_window.py tests: deterministic day_offset/days -> RFC3339
window resolution, including a DST-transition case, plus the event-time
formatter used by the reply."""
from __future__ import annotations

from datetime import datetime
from zoneinfo import ZoneInfo

from app.calendar_window import (
    format_event_range,
    format_event_time,
    format_window_range,
    resolve_all_day_range,
    resolve_event_datetime,
    resolve_event_range,
    resolve_window,
    window_spans_other_years,
)


def test_today_window_is_local_midnight_to_midnight():
    now = datetime(2026, 9, 14, 15, 30, tzinfo=ZoneInfo("Asia/Jerusalem"))
    window = resolve_window(day_offset=0, days=1, timezone_name="Asia/Jerusalem", now=now)
    assert window.time_min.startswith("2026-09-14T00:00:00")
    assert window.time_max.startswith("2026-09-15T00:00:00")


def test_tomorrow_window_offsets_by_one_day():
    now = datetime(2026, 9, 14, 9, 0, tzinfo=ZoneInfo("Asia/Jerusalem"))
    window = resolve_window(day_offset=1, days=1, timezone_name="Asia/Jerusalem", now=now)
    assert window.time_min.startswith("2026-09-15T00:00:00")
    assert window.time_max.startswith("2026-09-16T00:00:00")


def test_multi_day_window_spans_days():
    now = datetime(2026, 9, 14, 9, 0, tzinfo=ZoneInfo("Asia/Jerusalem"))
    window = resolve_window(day_offset=0, days=7, timezone_name="Asia/Jerusalem", now=now)
    assert window.time_min.startswith("2026-09-14T00:00:00")
    assert window.time_max.startswith("2026-09-21T00:00:00")


def test_format_window_range_single_day():
    now = datetime(2026, 9, 14, 9, 0, tzinfo=ZoneInfo("Asia/Jerusalem"))
    window = resolve_window(day_offset=1, days=1, timezone_name="Asia/Jerusalem", now=now)
    assert format_window_range(window.time_min, window.time_max, "Asia/Jerusalem") == "Tue Sep 15"


def test_format_window_range_multi_day_span():
    now = datetime(2026, 9, 14, 9, 0, tzinfo=ZoneInfo("Asia/Jerusalem"))
    window = resolve_window(day_offset=0, days=7, timezone_name="Asia/Jerusalem", now=now)
    # time_max is exclusive (local midnight the day AFTER the last day
    # included), so the last included day is one before it, not seven
    # full days after the start.
    assert format_window_range(window.time_min, window.time_max, "Asia/Jerusalem") == "Mon Sep 14 - Sun Sep 20"


def test_window_carries_a_mandatory_utc_offset():
    """Google's API requires an RFC3339 timestamp with a mandatory
    timezone offset -- not a bare/naive timestamp."""
    now = datetime(2026, 9, 14, 9, 0, tzinfo=ZoneInfo("Asia/Jerusalem"))
    window = resolve_window(day_offset=0, days=1, timezone_name="Asia/Jerusalem", now=now)
    assert "+" in window.time_min or "-" in window.time_min[10:]


def test_dst_transition_produces_a_different_offset_before_and_after():
    """Israel (Asia/Jerusalem) switches out of DST in late October. A
    window resolved the day before the switch and one resolved the day
    after must carry DIFFERENT UTC offsets (+03:00 during DST,
    +02:00 standard time) -- proving the offset is computed per-date via
    zoneinfo, not hardcoded or computed once and reused."""
    before_switch = datetime(2026, 10, 20, 9, 0, tzinfo=ZoneInfo("Asia/Jerusalem"))
    after_switch = datetime(2026, 11, 10, 9, 0, tzinfo=ZoneInfo("Asia/Jerusalem"))

    window_before = resolve_window(day_offset=0, days=1, timezone_name="Asia/Jerusalem", now=before_switch)
    window_after = resolve_window(day_offset=0, days=1, timezone_name="Asia/Jerusalem", now=after_switch)

    offset_before = window_before.time_min[-6:]
    offset_after = window_after.time_min[-6:]
    assert offset_before != offset_after
    assert offset_before == "+03:00"
    assert offset_after == "+02:00"


def test_format_event_time_all_day():
    assert format_event_time("2026-09-15", all_day=True, timezone_name="Asia/Jerusalem") == "2026-09-15 (all day)"


def test_format_event_time_timed_converts_to_owner_timezone():
    # A time expressed in UTC should render in Asia/Jerusalem (+03:00 in September).
    result = format_event_time("2026-09-15T10:00:00+00:00", all_day=False, timezone_name="Asia/Jerusalem")
    assert "13:00" in result  # 10:00 UTC == 13:00 Jerusalem (DST, +03:00)


def test_format_event_time_malformed_value_is_returned_verbatim_not_crashed():
    # Contains "T" (so it isn't routed down the all-day path) but is not
    # a parseable ISO datetime -- must not raise, must show the raw value.
    malformed = "2026-13-45T99:99:99"
    assert format_event_time(malformed, all_day=False, timezone_name="Asia/Jerusalem") == malformed


def test_format_event_range_same_day_shows_start_and_end_time():
    result = format_event_range(
        "2026-09-15T09:00:00+03:00", "2026-09-15T09:30:00+03:00", all_day=False, timezone_name="Asia/Jerusalem"
    )
    assert result == "Tue Sep 15, 09:00–09:30"


def test_format_event_range_crossing_midnight_shows_full_end_datetime():
    result = format_event_range(
        "2026-09-15T23:00:00+03:00", "2026-09-16T01:00:00+03:00", all_day=False, timezone_name="Asia/Jerusalem"
    )
    assert result == "Tue Sep 15, 23:00–Wed Sep 16, 01:00"


def test_format_event_range_all_day_ignores_end():
    result = format_event_range("2026-09-15", "2026-09-16", all_day=True, timezone_name="Asia/Jerusalem")
    assert result == "2026-09-15 (all day)"


def test_format_event_range_malformed_end_falls_back_to_start_only():
    result = format_event_range(
        "2026-09-15T09:00:00+03:00", "not-a-date", all_day=False, timezone_name="Asia/Jerusalem"
    )
    assert result == "Tue Sep 15, 09:00"


def test_resolve_event_datetime_today_at_given_time():
    now = datetime(2026, 9, 14, 8, 0, tzinfo=ZoneInfo("Asia/Jerusalem"))
    span = resolve_event_datetime(day_offset=0, start_time="14:30", duration_minutes=30, timezone_name="Asia/Jerusalem", now=now)
    assert span.start.startswith("2026-09-14T14:30:00")
    assert span.end.startswith("2026-09-14T15:00:00")


def test_resolve_event_datetime_future_day_offset():
    now = datetime(2026, 9, 14, 8, 0, tzinfo=ZoneInfo("Asia/Jerusalem"))
    span = resolve_event_datetime(day_offset=3, start_time="09:00", duration_minutes=60, timezone_name="Asia/Jerusalem", now=now)
    assert span.start.startswith("2026-09-17T09:00:00")
    assert span.end.startswith("2026-09-17T10:00:00")


def test_resolve_event_datetime_duration_crosses_midnight():
    now = datetime(2026, 9, 14, 8, 0, tzinfo=ZoneInfo("Asia/Jerusalem"))
    span = resolve_event_datetime(day_offset=0, start_time="23:30", duration_minutes=90, timezone_name="Asia/Jerusalem", now=now)
    assert span.start.startswith("2026-09-14T23:30:00")
    assert span.end.startswith("2026-09-15T01:00:00")


def test_resolve_event_datetime_carries_a_mandatory_utc_offset():
    now = datetime(2026, 9, 14, 8, 0, tzinfo=ZoneInfo("Asia/Jerusalem"))
    span = resolve_event_datetime(day_offset=0, start_time="10:00", duration_minutes=30, timezone_name="Asia/Jerusalem", now=now)
    assert "+" in span.start or "-" in span.start[10:]


# ── overnight / multi-day / all-day (2026-09-25) ─────────────────────────

_NOW = datetime(2026, 9, 25, 12, 0, tzinfo=ZoneInfo("Asia/Jerusalem"))


def test_resolve_event_range_19_hours_across_midnight():
    span = resolve_event_range(6, "16:00", 7, "11:00", "Asia/Jerusalem", now=_NOW)
    assert span.start == "2026-10-01T16:00:00+03:00"
    assert span.end == "2026-10-02T11:00:00+03:00"
    assert span.all_day is False
    length = datetime.fromisoformat(span.end) - datetime.fromisoformat(span.start)
    assert length.total_seconds() == 19 * 3600


def test_resolve_event_range_gives_each_end_the_offset_of_its_own_date():
    span = resolve_event_range(29, "20:00", 30, "10:00", "Asia/Jerusalem", now=_NOW)  # Oct 24 -> Oct 25, DST ends
    assert span.start.endswith("+03:00") and span.end.endswith("+02:00")
    real = datetime.fromisoformat(span.end) - datetime.fromisoformat(span.start)
    assert real.total_seconds() == 15 * 3600  # 14 clock hours, plus the hour the clocks went back


def test_resolve_all_day_range_end_is_exclusive_so_it_lands_on_the_day_after_the_last_day():
    span = resolve_all_day_range(6, 8, "Asia/Jerusalem", now=_NOW)  # Oct 1 through Oct 3, last day included
    assert (span.start, span.end, span.all_day) == ("2026-10-01", "2026-10-04", True)
    single = resolve_all_day_range(6, 6, "Asia/Jerusalem", now=_NOW)
    assert (single.start, single.end) == ("2026-10-01", "2026-10-02")


def test_resolve_all_day_range_is_a_date_not_an_instant():
    span = resolve_all_day_range(0, 0, "Asia/Jerusalem", now=datetime(2026, 9, 25, 23, 59, tzinfo=ZoneInfo("Asia/Jerusalem")))
    assert "T" not in span.start and "T" not in span.end
    assert span.start == "2026-09-25"  # late in the owner's evening is still the owner's today


def test_format_event_range_multi_day_all_day_shows_first_and_last_day():
    # Google's all-day end is exclusive: 2026-10-04 means "through Oct 3".
    assert format_event_range("2026-10-01", "2026-10-04", True, "Asia/Jerusalem") == "2026-10-01 to 2026-10-03 (all day)"
    assert format_event_range("2026-10-01", "2026-10-02", True, "Asia/Jerusalem") == "2026-10-01 (all day)"
    assert format_event_range("not-a-date", "also-bad", True, "Asia/Jerusalem") == "not-a-date (all day)"


def test_format_event_range_overnight_event():
    result = format_event_range("2026-10-01T16:00:00+03:00", "2026-10-02T11:00:00+03:00", False, "Asia/Jerusalem")
    assert result == "Thu Oct 01, 16:00–Fri Oct 02, 11:00"


def test_year_is_added_only_when_asked_for():
    start, end = "2025-11-03T10:00:00+02:00", "2025-11-03T11:00:00+02:00"
    assert format_event_range(start, end, False, "Asia/Jerusalem") == "Mon Nov 03, 10:00–11:00"
    assert format_event_range(start, end, False, "Asia/Jerusalem", with_year=True) == "Mon Nov 03 2025, 10:00–11:00"
    assert format_event_time(start, False, "Asia/Jerusalem", with_year=True) == "Mon Nov 03 2025, 10:00"
    overnight = format_event_range(
        "2025-12-31T22:00:00+02:00", "2026-01-01T02:00:00+02:00", False, "Asia/Jerusalem", with_year=True
    )
    assert overnight == "Wed Dec 31 2025, 22:00–Thu Jan 01 2026, 02:00"


def test_window_label_with_year():
    window = resolve_window(day_offset=-365, days=366, timezone_name="Asia/Jerusalem", now=_NOW)
    assert format_window_range(window.time_min, window.time_max, "Asia/Jerusalem", with_year=True) == \
        "Thu Sep 25 2025 - Fri Sep 25 2026"
    one_day = resolve_window(day_offset=-30, days=1, timezone_name="Asia/Jerusalem", now=_NOW)
    assert format_window_range(one_day.time_min, one_day.time_max, "Asia/Jerusalem", with_year=True) == "Wed Aug 26 2026"
    assert format_window_range(one_day.time_min, one_day.time_max, "Asia/Jerusalem") == "Wed Aug 26"


def test_window_spans_other_years():
    def spans(day_offset, days):
        window = resolve_window(day_offset, days, "Asia/Jerusalem", now=_NOW)
        return window_spans_other_years(window.time_min, window.time_max, "Asia/Jerusalem", now=_NOW)

    assert spans(0, 1) is False  # today
    assert spans(-30, 7) is False  # last month, same year
    assert spans(0, 7) is False  # the ordinary "next 7 days"
    assert spans(-365, 366) is True  # the past 12 months
    assert spans(-300, 1) is True  # Nov 2025
    # Sep 25 is day 268 of 2026: offset -267 is Jan 1, -268 is Dec 31 of the year before.
    assert spans(-267, 268) is False  # Jan 1 through today: the whole window is inside 2026
    assert spans(-268, 1) is True  # Dec 31 2025
    assert spans(90, 7) is False  # Dec 24-30 2026
    assert spans(97, 5) is True  # Dec 31 2026 into Jan 2027 (Jan 1 = offset 98)
