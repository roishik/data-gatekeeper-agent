"""app/calendar_window.py tests: deterministic day_offset/days -> RFC3339
window resolution, including a DST-transition case, plus the event-time
formatter used by the reply."""
from __future__ import annotations

from datetime import datetime
from zoneinfo import ZoneInfo

from app.calendar_window import format_event_time, resolve_window


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
