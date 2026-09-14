"""
conftest.py — shared pytest fixtures.

Patches the small set of module-level config constants app/ingress.py
and app/pipeline.py read from app/config.py at import time, so every
test runs against known, fixed values instead of depending on real
environment variables or a local .env file.

IMPORTANT: each fixture patches the name bound INSIDE THE CONSUMING
MODULE (e.g. `app.ingress.ALLOWED_SENDERS`), not `app.config` itself.
Both modules do `from app.config import X`, which binds a fresh name in
their own namespace at import time -- patching app.config afterwards
would not be seen by code that already captured the old value.
"""
from __future__ import annotations

import pytest

import app.ingress as ingress
import app.pipeline as pipeline
from app.audit_log import JSONLAuditLog
from app.state_store import InMemoryStateStore
from tests.webhook_helpers import TEST_WEBHOOK_SECRET

TEST_INBOX_ID = "inbox_1"
TEST_ALLOWED_SENDER = "instinct@example.com"
TEST_GATEKEEPER_ADDRESS = "gatekeeper@example.com"
TEST_OWNER_EMAIL = "owner@example.com"


@pytest.fixture()
def configured_env(monkeypatch):
    monkeypatch.setattr(ingress, "AGENTMAIL_INBOX_ID", TEST_INBOX_ID)
    monkeypatch.setattr(ingress, "ALLOWED_SENDERS", (TEST_ALLOWED_SENDER,))
    monkeypatch.setattr(ingress, "GATEKEEPER_INBOX_ADDRESS", TEST_GATEKEEPER_ADDRESS)
    monkeypatch.setattr(ingress, "AGENTMAIL_WEBHOOK_SECRET", TEST_WEBHOOK_SECRET)
    monkeypatch.setattr(ingress, "WEBHOOK_TOLERANCE_SECONDS", 300)
    monkeypatch.setattr(pipeline, "AGENTMAIL_INBOX_ID", TEST_INBOX_ID)
    monkeypatch.setattr(pipeline, "MAX_REQUESTS_PER_DAY", 20)
    monkeypatch.setattr(pipeline, "OWNER_EMAIL", TEST_OWNER_EMAIL)
    return {
        "inbox_id": TEST_INBOX_ID,
        "sender": TEST_ALLOWED_SENDER,
        "gatekeeper_address": TEST_GATEKEEPER_ADDRESS,
        "owner_email": TEST_OWNER_EMAIL,
        "secret": TEST_WEBHOOK_SECRET,
    }


@pytest.fixture()
def audit_log(tmp_path):
    return JSONLAuditLog(tmp_path / "audit_log.jsonl")


@pytest.fixture()
def state_store():
    return InMemoryStateStore()
