"""
request_parser.py — Layer 2: parse the inbound email into a
machine-checkable request.

Two paths, tried strictly in this order, never mixed:

  1. Deterministic block parsing. If the email body contains a
     well-formed ---GATEKEEPER-REQUEST--- ... ---END--- YAML block
     (research/05 section 2's "Design C" hybrid protocol), parse it with
     plain code (yaml.safe_load + explicit field checks). No LLM is
     involved on this path at all.
  2. QUARANTINED LLM fallback (app/reader_llm.py). Only reached when (1)
     finds no valid block. A separate, tool-less model reads the ENTIRE
     email body -- untrusted, attacker-reachable text -- and may only
     return JSON matching a small, closed schema.

There is no third path. Unparseable or invalid input on EITHER path
becomes verb="unsupported", never a best-effort guess -- this is the
"never coerce" rule from the brief, and it's also what research/03
section 2.5 calls the "structured-output-only extraction" baseline: a
schema violation is a parse failure, full stop.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

import yaml

from app.reader_llm import ReaderLLM

_BLOCK_RE = re.compile(r"---GATEKEEPER-REQUEST---\s*\n(.*?)\n---END---", re.S)

REQUEST_ID_MAX_CHARS = 128


@dataclass(frozen=True)
class ParsedRequest:
    request_id: str
    verb: str
    params: dict[str, Any] = field(default_factory=dict)
    source: str = "block"  # "block" | "llm"


def parse_request(email_text: str, agentmail_message_id: str, reader_llm: ReaderLLM) -> ParsedRequest:
    block_result = _parse_fenced_block(email_text)
    if block_result is not None:
        return block_result
    return _parse_via_llm(email_text, agentmail_message_id, reader_llm)


def _parse_fenced_block(email_text: str) -> ParsedRequest | None:
    match = _BLOCK_RE.search(email_text)
    if not match:
        return None

    try:
        data = yaml.safe_load(match.group(1))
    except yaml.YAMLError:
        return None
    if not isinstance(data, dict):
        return None

    request_id = data.get("request_id")
    verb = data.get("verb")
    params = data.get("params", {})

    if not isinstance(request_id, str) or not request_id.strip() or len(request_id) > REQUEST_ID_MAX_CHARS:
        return None
    if not isinstance(verb, str) or not verb.strip():
        return None
    if params is None:
        params = {}
    if not isinstance(params, dict):
        return None

    return ParsedRequest(request_id=request_id.strip(), verb=verb.strip(), params=params, source="block")


def fallback_request_id_for(agentmail_message_id: str) -> str:
    """A short, stable id for requests that didn't state one. Derived from the
    AgentMail message id so a redelivered message still dedupes, but readable
    in the reply (raw Message-IDs look like `<CAHy...@mail.gmail.com>`)."""
    import hashlib

    return "req-" + hashlib.sha256(agentmail_message_id.encode()).hexdigest()[:12]


def _parse_via_llm(email_text: str, agentmail_message_id: str, reader_llm: ReaderLLM) -> ParsedRequest:
    fallback_request_id = fallback_request_id_for(agentmail_message_id)
    extraction = reader_llm.extract(email_text)
    if extraction is None:
        return ParsedRequest(request_id=fallback_request_id, verb="unsupported", params={}, source="llm")

    params: dict[str, Any] = {}
    if extraction.query is not None:
        params["query"] = extraction.query
    if extraction.max_results is not None:
        params["max_results"] = extraction.max_results
    if extraction.newer_than_days is not None:
        params["newer_than_days"] = extraction.newer_than_days
    if extraction.day_offset is not None:
        params["day_offset"] = extraction.day_offset
    if extraction.days is not None:
        params["days"] = extraction.days

    request_id = (
        extraction.request_id.strip()
        if extraction.request_id and extraction.request_id.strip()
        else fallback_request_id
    )
    return ParsedRequest(
        request_id=request_id[:REQUEST_ID_MAX_CHARS], verb=extraction.verb, params=params, source="llm"
    )
