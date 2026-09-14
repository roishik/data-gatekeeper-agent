"""Audit log tests: hash-chain construction and the property that
matters most -- verify_chain() actually detects tampering, not just
that append() runs without error."""
from __future__ import annotations

import copy

from app.audit_log import AuditRecord, GENESIS_HASH, JSONLAuditLog, compute_entry_hash, verify_chain


def _record(**overrides) -> AuditRecord:
    defaults = dict(agentmail_message_id="msg_1", sender="a@example.com", layer0_verdict="ok", layer1_verdict="ok")
    defaults.update(overrides)
    return AuditRecord(**defaults)


def test_first_entry_chains_from_genesis(tmp_path):
    log = JSONLAuditLog(tmp_path / "log.jsonl")
    entry = log.append(_record())
    assert entry["prev_hash"] == GENESIS_HASH
    assert entry["hash"] == compute_entry_hash(entry["record"], GENESIS_HASH)


def test_entries_link_to_previous_hash(tmp_path):
    log = JSONLAuditLog(tmp_path / "log.jsonl")
    first = log.append(_record(agentmail_message_id="msg_1"))
    second = log.append(_record(agentmail_message_id="msg_2"))
    assert second["prev_hash"] == first["hash"]


def test_chain_survives_reload_from_disk(tmp_path):
    path = tmp_path / "log.jsonl"
    log1 = JSONLAuditLog(path)
    log1.append(_record(agentmail_message_id="msg_1"))
    log1.append(_record(agentmail_message_id="msg_2"))

    log2 = JSONLAuditLog(path)  # simulates a process restart
    third = log2.append(_record(agentmail_message_id="msg_3"))

    entries = log2.all_entries()
    assert len(entries) == 3
    assert third["prev_hash"] == entries[1]["hash"]
    assert verify_chain(entries)


def test_verify_chain_accepts_untampered_chain(tmp_path):
    log = JSONLAuditLog(tmp_path / "log.jsonl")
    for i in range(5):
        log.append(_record(agentmail_message_id=f"msg_{i}"))
    assert verify_chain(log.all_entries())


def test_verify_chain_detects_content_tampering(tmp_path):
    log = JSONLAuditLog(tmp_path / "log.jsonl")
    for i in range(3):
        log.append(_record(agentmail_message_id=f"msg_{i}"))

    entries = copy.deepcopy(log.all_entries())
    entries[1]["record"]["sender"] = "attacker@evil.com"  # tamper with a past record's content

    assert not verify_chain(entries)


def test_verify_chain_detects_hash_tampering(tmp_path):
    log = JSONLAuditLog(tmp_path / "log.jsonl")
    for i in range(3):
        log.append(_record(agentmail_message_id=f"msg_{i}"))

    entries = copy.deepcopy(log.all_entries())
    entries[2]["hash"] = "0" * 64  # forge a hash to match nothing

    assert not verify_chain(entries)


def test_verify_chain_detects_reordering(tmp_path):
    log = JSONLAuditLog(tmp_path / "log.jsonl")
    for i in range(3):
        log.append(_record(agentmail_message_id=f"msg_{i}"))

    entries = copy.deepcopy(log.all_entries())
    entries[0], entries[1] = entries[1], entries[0]  # swap two entries

    assert not verify_chain(entries)


def test_verify_chain_detects_deleted_entry(tmp_path):
    log = JSONLAuditLog(tmp_path / "log.jsonl")
    for i in range(3):
        log.append(_record(agentmail_message_id=f"msg_{i}"))

    entries = copy.deepcopy(log.all_entries())
    del entries[1]  # a compromised process erasing its own tracks

    assert not verify_chain(entries)


def test_audit_record_never_carries_a_snippet_or_body_field():
    """Data-minimization guarantee, checked structurally: AuditRecord
    has no field that could hold email body/snippet text, so it cannot
    leak into the log no matter what a caller passes."""
    import dataclasses

    field_names = {f.name for f in dataclasses.fields(AuditRecord)}
    assert "snippet" not in field_names
    assert "body" not in field_names
    assert "text" not in field_names
