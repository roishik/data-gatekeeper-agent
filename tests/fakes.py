"""
fakes.py — test doubles for every interface app/pipeline.py depends on.

Every provider-boundary module in app/ (reader_llm, gmail_executor,
agentmail_client) is written against a Protocol precisely so tests never
touch the network, a real Google/AgentMail/Anthropic API, or a real
credential -- see each module's docstring. These fakes are the other
half of that contract.
"""
from __future__ import annotations

from app.agentmail_client import ReplyResult
from app.calendar_executor import CalendarEvent
from app.drive_executor import DriveFileResult
from app.failures import GatekeeperDenied
from app.injection_screen import InboundScreenResult
from app.output_screen import ItemVerdict, OutputScreenResult
from app.gmail_executor import DraftResult, GmailResult
from app.reader_llm import LLMExtraction


class FakeReaderLLM:
    """Scripted quarantined-LLM stand-in. Returns a fixed
    `response` (or None, simulating a call/parse failure) regardless of
    what `email_text` says -- this is the point: a REAL quarantined LLM
    is untrusted precisely because injected text in `email_text` might
    influence it, but this fake demonstrates that even a maximally
    naive stand-in can't leak anything beyond its scripted schema-shaped
    response, because ReaderLLM.extract()'s return type has no room for
    anything else. Records every call for assertions."""

    def __init__(self, response: LLMExtraction | None = None, failure: str | None = None):
        self.response = response
        self.calls: list[str] = []
        self.last_usage: dict[str, int] | None = {"input_tokens": 42, "output_tokens": 7}
        self.last_failure: str | None = failure

    def extract(self, email_text: str) -> LLMExtraction | None:
        self.calls.append(email_text)
        return self.response


class FakeInjectionScreen:
    """Scripted TypeSafe/Jev stand-in. Every part scores the fixed `score`
    (or None, simulating "no signal" -- see app/injection_screen.py)
    regardless of what it says, unless `part_scores` names a part
    explicitly. Records every call for assertions: `calls` gets one entry
    per screened part text, `part_calls` one dict per screen_parts() call."""

    def __init__(self, score: float | None = None, part_scores: dict[str, float | None] | None = None):
        self.score = score
        self.part_scores = part_scores or {}
        self.calls: list[str] = []
        self.part_calls: list[dict[str, str]] = []

    def screen(self, text: str) -> float | None:
        self.calls.append(text)
        return self.score

    def screen_parts(self, parts: dict[str, str]) -> InboundScreenResult:
        self.part_calls.append(dict(parts))
        self.calls.extend(parts.values())
        scores = {name: self.part_scores.get(name, self.score) for name in parts}
        return InboundScreenResult(scores=scores, status="ok")


class FakeGmailClient:
    """Returns a fixed list of GmailResult regardless of the query --
    tests that care about query construction assert against
    `self.calls` instead of branching behavior on the query string."""

    def __init__(self, results: list[GmailResult] | None = None):
        self.results = results if results is not None else []
        self.calls: list[dict] = []

    def search(self, query: str, max_results: int, newer_than_days: int | None) -> list[GmailResult]:
        self.calls.append({"query": query, "max_results": max_results, "newer_than_days": newer_than_days})
        return self.results[:max_results]

    def create_draft(self, to: str, subject: str, body: str, thread_id: str | None = None) -> DraftResult:
        self.calls.append({"to": to, "subject": subject, "body": body, "thread_id": thread_id})
        return DraftResult(draft_id="draft_1", to=to, subject=subject, thread_id=thread_id)


class FakeCalendarClient:
    """Mirrors FakeGmailClient: returns a fixed list of CalendarEvent
    regardless of the requested window, and records every call so tests
    can assert on the resolved time_min/time_max/max_results instead of
    branching fake behavior on them. create_event/update_event echo the
    given fields back into a CalendarEvent instead of returning a fixed
    result, since tests need to check exactly what was created/changed."""

    def __init__(self, results: list[CalendarEvent] | None = None, foreign_event_ids: set[str] | None = None,
                 existing_title: str = "(unchanged)", existing_location: str = "",
                 existing_attendees: tuple[str, ...] = ()):
        self.results = results if results is not None else []
        self.calls: list[dict] = []
        # Event ids the fake treats as NOT created by the gatekeeper.
        self.foreign_event_ids = set(foreign_event_ids or ())
        self.existing_title = existing_title
        self.existing_location = existing_location
        # Emails already on the event before this update -- lets tests
        # exercise the invite guard on a title/location-only change to an
        # event that already has guests (see GoogleCalendarClient.update_event).
        self.existing_attendees = tuple(existing_attendees)

    def list_events(self, time_min: str, time_max: str, max_results: int) -> list[CalendarEvent]:
        self.calls.append({"time_min": time_min, "time_max": time_max, "max_results": max_results})
        return self.results[:max_results]

    def create_event(
        self, title: str, day_offset: int, start_time: str, duration_minutes: int, attendees: tuple[str, ...],
        request_id: str = "", location: str = "",
    ) -> CalendarEvent:
        self.calls.append(
            {
                "op": "create_event", "title": title, "day_offset": day_offset,
                "start_time": start_time, "duration_minutes": duration_minutes, "attendees": attendees,
                "request_id": request_id, "location": location,
            }
        )
        return CalendarEvent(
            event_id="event_created_1", summary=title,
            start=f"2026-01-0{1 + day_offset}T{start_time}:00+02:00",
            end=f"2026-01-0{1 + day_offset}T{start_time}:00+02:00",
            all_day=False, attendee_count=len(attendees), location=location,
        )

    def update_event(
        self,
        event_id: str,
        title: str | None,
        day_offset: int | None,
        start_time: str | None,
        duration_minutes: int | None,
        add_attendees: tuple[str, ...] = (),
        remove_attendees: tuple[str, ...] = (),
        invite_guard=None,
        location: str | None = None,
    ) -> CalendarEvent:
        # Mirrors GoogleCalendarClient's containment check and invite guard:
        # the guard fires whenever the resulting attendee list is
        # non-empty AND title/location is changing (not only when a new
        # guest is being added -- sendUpdates="all" notifies EXISTING
        # guests of any changed field too).
        if event_id in self.foreign_event_ids:
            raise GatekeeperDenied("not_gatekeeper_event")
        resulting_has_attendees = bool(add_attendees or self.existing_attendees)
        if resulting_has_attendees and invite_guard is not None and (
            add_attendees or title is not None or location is not None
        ):
            invite_guard(
                title if title is not None else self.existing_title,
                location if location is not None else self.existing_location,
            )
        self.calls.append(
            {
                "op": "update_event", "event_id": event_id, "title": title, "day_offset": day_offset,
                "start_time": start_time, "duration_minutes": duration_minutes,
                "add_attendees": add_attendees, "remove_attendees": remove_attendees, "location": location,
            }
        )
        return CalendarEvent(
            event_id=event_id, summary=title or self.existing_title,
            start="2026-01-01T10:00:00+02:00", end="2026-01-01T10:30:00+02:00",
            all_day=False, attendee_count=len(add_attendees),
            location=location if location is not None else self.existing_location,
        )

    def delete_event(self, event_id: str) -> None:
        if event_id in self.foreign_event_ids:
            raise GatekeeperDenied("not_gatekeeper_event")
        self.calls.append({"op": "delete_event", "event_id": event_id})


class FakeDriveClient:
    """Records every create_file() call and returns a deterministic
    DriveFileResult -- mirrors the other fakes' style."""

    def __init__(self):
        self.calls: list[dict] = []

    def create_file(self, name: str, content: str) -> DriveFileResult:
        self.calls.append({"name": name, "content": content})
        return DriveFileResult(file_id="file_1", name=name)


class FakeAgentMailClient:
    """Records every reply() call instead of sending anything -- tests
    assert on `self.calls` to check who got mailed, which is exactly what
    the "reply only to the verified sender, no cc/bcc" test needs. Set
    `fail_with` to make reply() raise, for the failed-reply paths."""

    def __init__(self):
        self.calls: list[dict] = []
        self._next_id = 0
        self.fail_with: BaseException | None = None

    def reply(self, inbox_id: str, message_id: str, to: str, text: str) -> ReplyResult:
        self._next_id += 1
        self.calls.append({"inbox_id": inbox_id, "message_id": message_id, "to": to, "text": text})
        if self.fail_with is not None:
            raise self.fail_with
        return ReplyResult(message_id=f"reply-{self._next_id}", thread_id=f"thread-{self._next_id}")


class FakeOutputScreen:
    """Scripted outbound-screen stand-in. Items whose key is in `withhold`
    come back flagged sensitive; everything else clean. `fail_with` makes
    screen_items() raise, for the pipeline's fail-closed path. Records every
    call: `item_calls` (the items dict) and `text_calls` (whole-reply text)."""

    def __init__(self, withhold: set[str] | None = None, fail_with: BaseException | None = None,
                 reply_scores: tuple[float | None, float | None] = (0.05, 0.05)):
        self.withhold = set(withhold or ())
        self.fail_with = fail_with
        self.reply_scores = reply_scores
        self.item_calls: list[dict[str, dict[str, str]]] = []
        self.text_calls: list[str] = []

    def screen_items(self, items: dict[str, dict[str, str]]) -> OutputScreenResult:
        self.item_calls.append({k: dict(v) for k, v in items.items()})
        if self.fail_with is not None:
            raise self.fail_with
        verdicts = {
            key: ItemVerdict(
                sensitive=0.95 if key in self.withhold else 0.05,
                targets_reader=0.05,
                category="one_time_code" if key in self.withhold else "none",
                withheld=key in self.withhold,
                screened=True,
            )
            for key in items
        }
        return OutputScreenResult(verdicts=verdicts, status="ok")

    def screen_text(self, text: str) -> tuple[float | None, float | None]:
        self.text_calls.append(text)
        return self.reply_scores
