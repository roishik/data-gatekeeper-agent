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

    def __init__(self, response: LLMExtraction | None = None):
        self.response = response
        self.calls: list[str] = []
        self.last_usage: dict[str, int] | None = {"input_tokens": 42, "output_tokens": 7}

    def extract(self, email_text: str) -> LLMExtraction | None:
        self.calls.append(email_text)
        return self.response


class FakeInjectionScreen:
    """Scripted TypeSafe/Jev stand-in. Returns a fixed `score` (or None,
    simulating "no signal" -- see app/injection_screen.py) regardless of
    what `text` says. Records every call for assertions."""

    def __init__(self, score: float | None = None):
        self.score = score
        self.calls: list[str] = []

    def screen(self, text: str) -> float | None:
        self.calls.append(text)
        return self.score


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

    def __init__(self, results: list[CalendarEvent] | None = None):
        self.results = results if results is not None else []
        self.calls: list[dict] = []

    def list_events(self, time_min: str, time_max: str, max_results: int) -> list[CalendarEvent]:
        self.calls.append({"time_min": time_min, "time_max": time_max, "max_results": max_results})
        return self.results[:max_results]

    def create_event(
        self, title: str, day_offset: int, start_time: str, duration_minutes: int, attendees: tuple[str, ...]
    ) -> CalendarEvent:
        self.calls.append(
            {
                "op": "create_event", "title": title, "day_offset": day_offset,
                "start_time": start_time, "duration_minutes": duration_minutes, "attendees": attendees,
            }
        )
        return CalendarEvent(
            event_id="event_created_1", summary=title,
            start=f"2026-01-0{1 + day_offset}T{start_time}:00+02:00",
            end=f"2026-01-0{1 + day_offset}T{start_time}:00+02:00",
            all_day=False, attendee_count=len(attendees),
        )

    def update_event(
        self,
        event_id: str,
        title: str | None,
        day_offset: int | None,
        start_time: str | None,
        duration_minutes: int | None,
        attendees: tuple[str, ...] | None,
    ) -> CalendarEvent:
        self.calls.append(
            {
                "op": "update_event", "event_id": event_id, "title": title, "day_offset": day_offset,
                "start_time": start_time, "duration_minutes": duration_minutes, "attendees": attendees,
            }
        )
        return CalendarEvent(
            event_id=event_id, summary=title or "(unchanged)",
            start="2026-01-01T10:00:00+02:00", end="2026-01-01T10:30:00+02:00",
            all_day=False, attendee_count=len(attendees) if attendees is not None else 0,
        )

    def delete_event(self, event_id: str) -> None:
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
    assert on `self.calls` to check who got mailed and what BCC was
    set, which is exactly what the "reply only to the verified sender,
    with BCC set" test needs."""

    def __init__(self):
        self.calls: list[dict] = []
        self._next_id = 0

    def reply(self, inbox_id: str, message_id: str, to: str, bcc: str, text: str) -> ReplyResult:
        self._next_id += 1
        self.calls.append({"inbox_id": inbox_id, "message_id": message_id, "to": to, "bcc": bcc, "text": text})
        return ReplyResult(message_id=f"reply-{self._next_id}", thread_id=f"thread-{self._next_id}")
