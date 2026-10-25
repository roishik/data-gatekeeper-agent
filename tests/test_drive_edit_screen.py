"""Tests for app/drive_edit_screen.py and the pipeline's drive edit guard
(added 2026-10-22): Jev judges every drive.update_file / append_file
before it's written, and a malicious, unreasonable or unscreenable edit is
refused (`edit_refused`) with nothing written.

Unit tests use a stub typesafe_sdk client (same pattern as
tests/test_output_screen.py); pipeline tests use tests/fakes.py's
FakeDriveEditScreen."""
from __future__ import annotations

import pytest

from app import drive_edit_screen as des
from app.drive_edit_screen import DriveEdit, NoOpDriveEditScreen, TypeSafeDriveEditScreen, edit_states
from app.pipeline import handle_webhook
from app.state_store import InMemoryStateStore
from tests.fakes import (
    FakeAgentMailClient,
    FakeCalendarClient,
    FakeDriveClient,
    FakeDriveEditScreen,
    FakeGmailClient,
    FakeInjectionScreen,
    FakeReaderLLM,
)
from tests.webhook_helpers import make_body, sign

# ── unit: the state Jev sees ────────────────────────────────────────────


def test_a_short_file_is_shown_whole_with_the_sizes():
    [state] = edit_states(DriveEdit("replace", "notes.txt", "old text", "new text"))
    assert state["file_name"] == "notes.txt"
    assert state["operation"].startswith("replace the file's whole content")
    assert state["current_content"] == {"chars": 8, "excerpt_is": "the whole file", "excerpt": "old text"}
    assert state["new_text"] == {"chars": 8, "part": "1 of 1", "text": "new text"}


def test_emptying_a_file_is_still_judged():
    [state] = edit_states(DriveEdit("replace", "notes.txt", "a long-kept list", ""))
    assert state["new_text"] == {"chars": 0, "part": "1 of 1", "text": ""}


def test_a_long_file_shows_its_start_for_a_replace_and_its_end_for_an_append(monkeypatch):
    monkeypatch.setattr(des, "JEV_CHUNK_CHARS", 10)
    current = "HEAD" + "x" * 20 + "TAIL"
    [replace] = edit_states(DriveEdit("replace", "f.txt", current, "short"))
    [append] = edit_states(DriveEdit("append", "f.txt", current, "short"))
    assert replace["current_content"]["excerpt"].startswith("HEAD")
    assert replace["current_content"]["excerpt_is"] == "the first 10 characters"
    assert append["current_content"]["excerpt"].endswith("TAIL")
    assert append["current_content"]["excerpt_is"] == "the last 10 characters"
    assert replace["current_content"]["chars"] == len(current)


# ── unit: TypeSafeDriveEditScreen against a stub SDK ────────────────────


class _Noul:
    def __init__(self, noul):
        self.noul = noul


class _Response:
    def __init__(self, questions, malicious, unreasonable):
        self.nouls = {"malicious": _Noul(malicious)}
        if "unreasonable" in questions:
            self.nouls["unreasonable"] = _Noul(unreasonable)


class _StubClient:
    """Scores by marker substring in the chunk's text: a key of `rules`
    gives that (malicious, unreasonable); others are clean. `fail` makes
    every call raise."""

    rules: dict[str, tuple[float, float]] = {}
    fail: bool = False
    calls: list[dict] = []

    def __init__(self, **kwargs):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def system_one(self, *, state, questions):
        _StubClient.calls.append({"state": state, "questions": set(questions)})
        if _StubClient.fail:
            raise RuntimeError("typesafe down")
        for marker, (malicious, unreasonable) in _StubClient.rules.items():
            if marker in state["new_text"]["text"]:
                return _Response(questions, malicious, unreasonable)
        return _Response(questions, 0.04, 0.06)


@pytest.fixture
def stub_sdk(monkeypatch):
    import typesafe_sdk

    monkeypatch.setattr(des, "TYPESAFE_API_KEY", "test-key")
    monkeypatch.setattr(typesafe_sdk, "TypeSafeClient", _StubClient)
    _StubClient.rules, _StubClient.fail, _StubClient.calls = {}, False, []
    return _StubClient


def test_an_ordinary_edit_passes_with_both_scores(stub_sdk):
    verdict = TypeSafeDriveEditScreen().screen_edit(DriveEdit("append", "log.txt", "day 1", "day 2"))
    assert (verdict.malicious, verdict.unreasonable, verdict.refused, verdict.status) == (0.04, 0.06, False, "ok")
    assert stub_sdk.calls[0]["questions"] == {"malicious", "unreasonable"}


@pytest.mark.parametrize("scores", [(0.92, 0.1), (0.1, 0.81), (0.7, 0.0)])
def test_either_score_at_or_above_the_threshold_refuses(stub_sdk, scores):
    stub_sdk.rules = {"FLAG": scores}
    verdict = TypeSafeDriveEditScreen().screen_edit(DriveEdit("replace", "notes.txt", "old", "FLAG"))
    assert verdict.refused and verdict.status == "ok"


def test_a_failed_call_refuses_the_edit(stub_sdk):
    stub_sdk.fail = True
    verdict = TypeSafeDriveEditScreen().screen_edit(DriveEdit("replace", "notes.txt", "old", "new"))
    assert verdict.refused and verdict.status == "degraded"
    assert verdict.malicious is None and verdict.unreasonable is None


def test_unreasonable_is_asked_once_and_malicious_on_every_chunk(stub_sdk, monkeypatch):
    monkeypatch.setattr("app.jev.JEV_CHUNK_CHARS", 10)
    monkeypatch.setattr("app.jev.JEV_CHUNK_OVERLAP", 0)
    stub_sdk.rules = {"EVIL": (0.95, 0.0)}
    verdict = TypeSafeDriveEditScreen().screen_edit(DriveEdit("replace", "f.txt", "old", "a" * 10 + "b" * 10 + "EVIL"))
    asked = sorted((call["state"]["new_text"]["part"], tuple(sorted(call["questions"]))) for call in stub_sdk.calls)
    assert asked == [
        ("1 of 3", ("malicious", "unreasonable")),
        ("2 of 3", ("malicious",)),
        ("3 of 3", ("malicious",)),
    ]
    assert verdict.malicious == 0.95 and verdict.refused  # a malicious LATER chunk still refuses


def test_noop_screen_refuses_nothing():
    verdict = NoOpDriveEditScreen().screen_edit(DriveEdit("replace", "f.txt", "old", ""))
    assert not verdict.refused and verdict.status == "disabled"


# ── pipeline: the guard ─────────────────────────────────────────────────


def _run(text: str, audit_log, screen, drive=None):
    body = make_body(text=text)
    svix_id, ts, sig = sign(body)
    drive = drive or FakeDriveClient()
    agentmail = FakeAgentMailClient()
    handle_webhook(
        body, svix_id=svix_id, svix_timestamp=ts, svix_signature=sig,
        state_store=InMemoryStateStore(), reader_llm=FakeReaderLLM(), injection_screen=FakeInjectionScreen(),
        gmail_client_factory=FakeGmailClient, calendar_client_factory=FakeCalendarClient,
        drive_client_factory=lambda: drive, agentmail_client=agentmail, audit_log=audit_log,
        drive_edit_screen=screen,
    )
    return drive, agentmail


def _block(request_id: str, verb: str, params: str) -> str:
    return f"---GATEKEEPER-REQUEST---\nrequest_id: {request_id}\nverb: {verb}\nparams:\n{params}---END---\n"


def test_an_allowed_edit_is_written_and_its_scores_audited(configured_env, audit_log):
    screen = FakeDriveEditScreen(malicious=0.03, unreasonable=0.12)
    drive, agentmail = _run(_block("req_g1", "drive.update_file", "  file_id: file_7\n  content: v2\n"), audit_log, screen)

    assert screen.edits == [DriveEdit("replace", "known.txt", "existing notes", "v2")]
    assert [c["op"] for c in drive.calls] == ["update_file"]
    assert "status: completed" in agentmail.calls[0]["text"]
    record = audit_log.all_entries()[0]["record"]
    assert (record["drive_edit_malicious"], record["drive_edit_unreasonable"], record["drive_edit_screen_status"]) == (
        0.03, 0.12, "ok",
    )


@pytest.mark.parametrize(
    "screen",
    [FakeDriveEditScreen(malicious=0.97), FakeDriveEditScreen(unreasonable=0.88), FakeDriveEditScreen(status="degraded")],
    ids=["malicious", "unreasonable", "unscreenable"],
)
def test_a_flagged_or_unscreenable_edit_is_refused_and_nothing_written(configured_env, audit_log, screen):
    drive, agentmail = _run(
        _block("req_g2", "drive.append_file", "  name: known.txt\n  content: more\n"), audit_log, screen
    )

    assert [c["op"] for c in drive.calls] == ["resolve_file_id"]  # no append happened
    text = agentmail.calls[0]["text"]
    assert "status: denied" in text and "error_code: edit_refused" in text
    assert "flagged as possibly malicious or unreasonable" in text
    assert "Detail:" not in text  # a security refusal stays generic
    record = audit_log.all_entries()[0]["record"]
    assert record["reply_error_code"] == "edit_refused"
    assert record["drive_edit_screen_status"] == screen.status


def test_a_refused_batch_item_leaves_the_others_alone(configured_env, audit_log):
    text = (
        "---GATEKEEPER-REQUEST---\nrequest_id: req_gb\nverb: batch\nparams:\n  requests:\n"
        "    - request_id: req_gb_create\n      verb: drive.create_file\n"
        "      params:\n        name: new.txt\n        content: hello\n"
        "    - request_id: req_gb_update\n      verb: drive.update_file\n"
        "      params:\n        file_id: file_7\n        content: wiped\n"
        "---END---\n"
    )
    drive, agentmail = _run(text, audit_log, FakeDriveEditScreen(unreasonable=0.9))

    assert [c["op"] for c in drive.calls] == ["create_file"]
    reply = agentmail.calls[0]["text"]
    assert "error_code: edit_refused" in reply
    assert "Created Drive file 'new.txt'" in reply
    by_id = {e["record"]["parsed_request_id"]: e["record"] for e in audit_log.all_entries()}
    assert by_id["req_gb_update"]["drive_edit_unreasonable"] == 0.9
    assert by_id["req_gb_create"]["drive_edit_screen_status"] is None  # creates aren't screened


def test_create_file_is_not_screened(configured_env, audit_log):
    screen = FakeDriveEditScreen(malicious=0.99)
    drive, agentmail = _run(_block("req_g3", "drive.create_file", "  name: n.txt\n  content: hi\n"), audit_log, screen)

    assert screen.edits == []
    assert "status: completed" in agentmail.calls[0]["text"]
