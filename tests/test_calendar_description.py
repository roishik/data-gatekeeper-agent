"""Event description and popup reminder (added 2026-10-05, Instinct's
request): `description` on calendar.create_event/update_event, and
`reminder_minutes` on calendar.create_event. Covers every layer -- Layer 3
bounds, the payload rail, the Google client's request body, the invite guard,
the reply echo and `capabilities` -- plus that nothing changes when neither
param is sent."""
from __future__ import annotations

import pytest

from app.capabilities import build_capabilities_info
from app.failures import GatekeeperDenied
from app.pipeline import handle_webhook
from app.policy import (
    EVENT_DESCRIPTION_MAX_CHARS,
    MAX_RESULTS_MAX,
    CAL_MAX_RESULTS_MAX,
    CalendarCreateEventParams,
    CalendarUpdateEventParams,
    evaluate_policy,
)
from app.state_store import InMemoryStateStore
from tests.fakes import (
    FakeAgentMailClient,
    FakeCalendarClient,
    FakeDriveClient,
    FakeGmailClient,
    FakeInjectionScreen,
    FakeOutputScreen,
    FakeReaderLLM,
)
from tests.test_calendar_executor import _OWN, _update, _write_client, _WriteEvents, _WriteService
from tests.webhook_helpers import make_body, sign

# Multi-line, blank lines, tabs, and URLs with query strings and fragments --
# everything that must come out the other end byte for byte.
_NOTES = (
    "Agenda:\n"
    "\t1. Budget review\n"
    "\n"
    "Join: https://meet.example.com/abc-defg-hij?pwd=a1b2&lang=he#start\n"
    "Doc: https://docs.example.com/d/1AbC_dEf/edit?usp=sharing\n"
    "  — bring the printout"
)


def _create(**overrides):
    params = {"title": "Sync", "day_offset": 1, "start_time": "10:00", "duration_minutes": 30}
    params.update(overrides)
    return evaluate_policy("calendar.create_event", params)


def _update_policy(**overrides):
    return evaluate_policy("calendar.update_event", {"event_id": "ev1", **overrides})


def _denied(decision, fragment: str):
    assert decision.status == "denied" and decision.error_code == "invalid_params", decision
    assert fragment in decision.reason, decision.reason


# ── Layer 3: description ───────────────────────────────────────────────


def test_create_with_a_description_keeps_it_exactly():
    decision = _create(description=_NOTES)
    assert decision.status == "allowed"
    assert decision.params.description == _NOTES


def test_create_without_the_new_params_is_unchanged():
    decision = _create()
    assert decision.params == CalendarCreateEventParams(
        title="Sync", day_offset=1, start_time="10:00", duration_minutes=30,
    )
    assert decision.params.description == "" and decision.params.reminder_minutes is None
    assert decision.ignored_params == ()


def test_description_at_the_limit_is_allowed_one_over_is_refused_not_cut():
    assert _create(description="x" * EVENT_DESCRIPTION_MAX_CHARS).params.description == "x" * EVENT_DESCRIPTION_MAX_CHARS
    _denied(_create(description="x" * (EVENT_DESCRIPTION_MAX_CHARS + 1)), f"exceeds {EVENT_DESCRIPTION_MAX_CHARS}")
    _denied(_update_policy(description="x" * (EVENT_DESCRIPTION_MAX_CHARS + 1)), "'description' exceeds")


@pytest.mark.parametrize("value", [42, ["a"], {"a": 1}, None, True])
def test_description_must_be_a_string(value):
    _denied(_create(description=value), "'description' must be a string")
    _denied(_update_policy(description=value), "'description' must be a string")


def test_description_refuses_control_characters_but_keeps_tabs_and_newlines():
    _denied(_create(description="ok\x07bell"), "control characters")
    assert _create(description="a\tb\nc").params.description == "a\tb\nc"


def test_update_description_set_clear_and_omitted():
    assert _update_policy(description=_NOTES).params == CalendarUpdateEventParams(event_id="ev1", description=_NOTES)
    assert _update_policy(description="").params.description == ""  # "" clears it
    assert _update_policy(title="Renamed").params.description is None  # omitted: left alone


def test_a_description_alone_is_a_valid_update():
    assert _update_policy(description="new notes").status == "allowed"


# ── Layer 3: reminder_minutes ──────────────────────────────────────────


@pytest.mark.parametrize("minutes", [1, 10, 30, 1440])
def test_valid_reminder_minutes(minutes):
    decision = _create(reminder_minutes=minutes)
    assert decision.status == "allowed" and decision.params.reminder_minutes == minutes


@pytest.mark.parametrize("minutes", [0, -5, 1441, 100000])
def test_reminder_minutes_out_of_range(minutes):
    _denied(_create(reminder_minutes=minutes), "'reminder_minutes' must be between 1 and 1440")


@pytest.mark.parametrize("minutes", [1.5, 30.0, "30", "", None, True, False, [30], {"minutes": 30}])
def test_reminder_minutes_must_be_an_integer(minutes):
    _denied(_create(reminder_minutes=minutes), "'reminder_minutes' must be an integer")


def test_reminder_minutes_is_not_an_update_event_param():
    """create_event only, as asked. On update it is an unknown param: never
    read, and reported back in ignored_params (the existing rule)."""
    decision = _update_policy(title="Renamed", reminder_minutes=10)
    assert decision.ignored_params == ("reminder_minutes",)
    assert not hasattr(decision.params, "reminder_minutes")


# ── capabilities ───────────────────────────────────────────────────────


def test_capabilities_reports_the_new_params_and_keeps_existing_limits():
    verbs = {v.verb: v for v in build_capabilities_info().verbs}

    def bound(verb: str, param: str) -> str:
        return next(line for line in verbs[verb].param_bounds if line.startswith(f"{param}:"))

    assert "max 2000 chars" in bound("calendar.create_event", "description")
    assert "\"\" clears it" in bound("calendar.update_event", "description")
    assert "1-1440" in bound("calendar.create_event", "reminder_minutes")
    assert not any(line.startswith("reminder_minutes:") for line in verbs["calendar.update_event"].param_bounds)
    # Unchanged limits.
    assert (MAX_RESULTS_MAX, CAL_MAX_RESULTS_MAX) == (30, 25)
    assert "1-30" in bound("gmail.search", "max_results")
    assert "1-25" in bound("calendar.list_events", "max_results")


# ── Layer 4: the Google request body ───────────────────────────────────


def _insert(events, **kwargs):
    client = _write_client(_WriteService(events))
    return client.create_event(
        title="Sync", day_offset=1, start_time="10:00", duration_minutes=30, attendees=(), request_id="r", **kwargs,
    )


def test_create_sends_the_description_verbatim_and_echoes_only_its_length():
    events = _WriteEvents()
    result = _insert(events, description=_NOTES)
    assert events.insert_calls[0]["body"]["description"] == _NOTES
    assert result.description_chars == len(_NOTES)
    assert not hasattr(result, "description")  # the text itself never comes back


def test_create_without_the_new_params_sends_neither_key():
    events = _WriteEvents()
    result = _insert(events)
    body = events.insert_calls[0]["body"]
    assert "description" not in body and "reminders" not in body  # calendar defaults apply, as before
    assert result.description_chars == 0 and result.popup_reminder_minutes is None


def test_create_with_a_reminder_sets_one_popup_override():
    events = _WriteEvents()
    result = _insert(events, reminder_minutes=15)
    assert events.insert_calls[0]["body"]["reminders"] == {
        "useDefault": False, "overrides": [{"method": "popup", "minutes": 15}],
    }
    assert result.popup_reminder_minutes == 15


def test_update_description_omitted_set_and_cleared():
    events = _WriteEvents(get_result={**_OWN, "description": "old notes"})
    client = _write_client(_WriteService(events))

    _update(client, title="Renamed")
    assert "description" not in events.patch_calls[0]["body"]  # omitted: untouched

    result = _update(client, description=_NOTES)
    assert events.patch_calls[1]["body"]["description"] == _NOTES
    assert result.description_chars == len(_NOTES)

    result = _update(client, description="")
    assert events.patch_calls[2]["body"]["description"] == ""  # cleared
    assert result.description_chars == 0


# ── Layer 4: the invite guard ──────────────────────────────────────────


def test_create_invite_guard_is_unchanged_without_attendees():
    """Owner's decision (2026-09-26): no extra screening without attendees."""
    calendar = FakeCalendarClient()
    screen = FakeOutputScreen(withhold={"invite"})
    reply = _call(_block("calendar.create_event", "  title: Sync\n  day_offset: 1\n  start_time: '10:00'\n"
                         "  duration_minutes: 30\n  description: notes\n"), calendar, screen)
    assert "status: completed" in reply
    assert "invite" not in (screen.item_calls[0] if screen.item_calls else {})


def test_update_description_on_an_event_with_guests_runs_the_guard_with_it():
    events = _WriteEvents(get_result={
        **_OWN, "summary": "Sync", "location": "Room 4B", "attendees": [{"email": "a@example.com"}],
    })
    client = _write_client(_WriteService(events))
    seen: list[tuple[str, str, str]] = []
    _update(client, description=_NOTES, invite_guard=lambda t, l, d: seen.append((t, l, d)))
    assert seen == [("Sync", "Room 4B", _NOTES)]


def test_adding_a_guest_screens_the_existing_description_they_will_receive():
    events = _WriteEvents(get_result={**_OWN, "summary": "Sync", "description": "existing notes"})
    client = _write_client(_WriteService(events))
    seen: list[tuple[str, str, str]] = []
    _update(client, add_attendees=("b@example.com",), invite_guard=lambda t, l, d: seen.append((t, l, d)))
    assert seen == [("Sync", "", "existing notes")]


def test_a_time_only_change_still_does_not_run_the_guard():
    events = _WriteEvents(get_result={
        **_OWN, "summary": "Sync", "description": "notes", "attendees": [{"email": "a@example.com"}],
        "start": {"dateTime": "2026-10-06T10:00:00+03:00"}, "end": {"dateTime": "2026-10-06T10:30:00+03:00"},
    })
    client = _write_client(_WriteService(events))
    seen: list = []
    _update(client, start_time="11:00", invite_guard=lambda t, l, d: seen.append((t, l, d)))
    assert seen == []


def test_a_refused_description_stops_the_patch():
    events = _WriteEvents(get_result={**_OWN, "attendees": [{"email": "a@example.com"}]})
    client = _write_client(_WriteService(events))

    def refuse(title: str, location: str, description: str) -> None:
        raise GatekeeperDenied("sensitive_content_refused")

    with pytest.raises(GatekeeperDenied):
        _update(client, description="bad", invite_guard=refuse)
    assert events.patch_calls == []


# ── end to end through the pipeline ────────────────────────────────────


def _block(verb: str, params: str, request_id: str = "req_desc") -> str:
    return f"---GATEKEEPER-REQUEST---\nrequest_id: {request_id}\nverb: {verb}\nparams:\n{params}---END---\n"


def _call(text: str, calendar: FakeCalendarClient, output_screen=None) -> str:
    body = make_body(text=text)
    svix_id, ts, sig = sign(body)
    agentmail = FakeAgentMailClient()
    handle_webhook(
        body, svix_id=svix_id, svix_timestamp=ts, svix_signature=sig,
        state_store=InMemoryStateStore(), reader_llm=FakeReaderLLM(), injection_screen=FakeInjectionScreen(),
        gmail_client_factory=FakeGmailClient, calendar_client_factory=lambda: calendar,
        drive_client_factory=FakeDriveClient, agentmail_client=agentmail, audit_log=_AUDIT[0],
        output_screen=output_screen,
    )
    return agentmail.calls[0]["text"]


_AUDIT: list = [None]


@pytest.fixture(autouse=True)
def _env(configured_env, audit_log):
    _AUDIT[0] = audit_log
    return configured_env


def test_a_description_on_the_payload_rail_arrives_byte_for_byte():
    calendar = FakeCalendarClient()
    text = _block(
        "calendar.create_event",
        "  title: Sync\n  day_offset: 1\n  start_time: '10:00'\n  duration_minutes: 30\n"
        "  description: ---PAYLOAD-notes---\n  reminder_minutes: 30\n",
    ) + f"\n---GATEKEEPER-PAYLOAD-notes---\n{_NOTES}\n---END-PAYLOAD-notes---\n"
    reply = _call(text, calendar)
    assert "status: completed" in reply, reply
    assert calendar.calls[0]["description"] == _NOTES
    assert calendar.calls[0]["reminder_minutes"] == 30
    assert f"description {len(_NOTES)} chars" in reply
    assert "popup reminder 30 min before" in reply


def test_a_yaml_block_scalar_description_keeps_its_lines():
    """Inline YAML keeps the lines and the URL; the final newline is block
    framing (the payload rail is the byte-exact path, tested above)."""
    calendar = FakeCalendarClient()
    text = _block(
        "calendar.create_event",
        "  title: Sync\n  day_offset: 1\n  start_time: '10:00'\n  duration_minutes: 30\n"
        "  description: |\n    line one\n    https://example.com/a?b=c&d=e\n",
    )
    reply = _call(text, calendar)
    assert "status: completed" in reply, reply
    assert calendar.calls[0]["description"].rstrip("\n") == "line one\nhttps://example.com/a?b=c&d=e"


def test_create_with_attendees_screens_the_description_and_refuses_the_whole_write():
    calendar = FakeCalendarClient()
    screen = FakeOutputScreen(withhold={"invite"})
    text = _block(
        "calendar.create_event",
        "  title: Sync\n  day_offset: 1\n  start_time: '10:00'\n  duration_minutes: 30\n"
        "  attendees: [dana@example.com]\n  description: 'Your code is 448812'\n",
    )
    reply = _call(text, calendar, screen)
    assert screen.item_calls[0]["invite"] == {"title": "Sync", "location": "", "description": "Your code is 448812"}
    assert "error_code: sensitive_content_refused" in reply
    assert "title, location or description" in reply
    assert calendar.calls == []  # refused outright, not written with the description dropped


def test_update_description_on_an_event_with_guests_is_screened_end_to_end():
    calendar = FakeCalendarClient(existing_title="Sync", existing_attendees=("a@example.com",))
    screen = FakeOutputScreen(withhold={"invite"})
    reply = _call(_block("calendar.update_event", "  event_id: ownevent1\n  description: bad\n"), calendar, screen)
    assert "error_code: sensitive_content_refused" in reply
    assert calendar.calls == []


def test_containment_is_unchanged_for_a_description_update():
    calendar = FakeCalendarClient(foreign_event_ids={"realmeeting1"})
    reply = _call(_block("calendar.update_event", "  event_id: realmeeting1\n  description: hi\n"), calendar)
    assert "error_code: not_gatekeeper_event" in reply
    assert calendar.calls == []


def test_an_over_long_description_is_an_explicit_invalid_params_reply():
    calendar = FakeCalendarClient()
    text = _block(
        "calendar.create_event",
        "  title: Sync\n  day_offset: 1\n  start_time: '10:00'\n  duration_minutes: 30\n"
        "  description: ---PAYLOAD-1---\n",
    ) + "\n---GATEKEEPER-PAYLOAD-1---\n" + "x" * 2001 + "\n---END-PAYLOAD-1---\n"
    reply = _call(text, calendar)
    assert "error_code: invalid_params" in reply
    assert "'description' exceeds 2000 characters" in reply
    assert calendar.calls == []


def test_an_invalid_reminder_is_an_explicit_invalid_params_reply():
    calendar = FakeCalendarClient()
    reply = _call(_block(
        "calendar.create_event",
        "  title: Sync\n  day_offset: 1\n  start_time: '10:00'\n  duration_minutes: 30\n  reminder_minutes: 1441\n",
    ), calendar)
    assert "error_code: invalid_params" in reply and "'reminder_minutes' must be between 1 and 1440" in reply
    assert calendar.calls == []


def test_other_fields_still_cannot_take_a_payload():
    calendar = FakeCalendarClient()
    text = _block(
        "calendar.create_event",
        "  title: ---PAYLOAD-1---\n  day_offset: 1\n  start_time: '10:00'\n  duration_minutes: 30\n",
    ) + "\n---GATEKEEPER-PAYLOAD-1---\nSync\n---END-PAYLOAD-1---\n"
    reply = _call(text, calendar)
    assert "error_code: invalid_payload" in reply
    assert calendar.calls == []
