"""
request_parser.py — Layer 2: parse the inbound email into a
machine-checkable request.

Two paths, tried strictly in this order, never mixed:

  1. Deterministic block parsing. If the email contains a
     ---GATEKEEPER-REQUEST--- ... ---END--- YAML block (research/05 section
     2's "Design C" hybrid protocol), parse it with plain code
     (yaml.safe_load + explicit field checks). No LLM is involved on this
     path at all -- and since 2026-09-22 a block that is PRESENT but broken
     is an explicit error (`invalid_request_block`), never a silent
     fallthrough to the LLM. A broken block is the requester's structured
     intent gone wrong; having an LLM guess at it would be coercion, and it
     would spend Anthropic tokens to do it.
  2. QUARANTINED LLM fallback (app/reader_llm.py). Only reached when there
     is no block at all. A separate, tool-less model reads the ENTIRE email
     body -- untrusted, attacker-reachable text -- and may only return JSON
     matching a small, closed schema.

There is no third path. Unparseable input on either path becomes
verb="unsupported" or a named parse error, never a best-effort guess --
the "never coerce" rule from the brief, and research/03 section 2.5's
"structured-output-only extraction" baseline.

Payload rail (added 2026-09-22)
-------------------------------
Long text (a draft body, a Drive file's content) travels VERBATIM in its
own section, outside the YAML, so neither YAML indentation rules nor the
reader LLM ever touch it:

    ---GATEKEEPER-REQUEST---
    request_id: req-2026-09-22-a
    verb: gmail.create_draft
    params:
      to: someone@example.com
      subject: "Re: the long one"
      body: ---PAYLOAD-1---
    ---END---

    ---GATEKEEPER-PAYLOAD-1---
    Any text at all, any indentation, blank lines, "quotes", colons.
    ---END-PAYLOAD-1---

`split_email()` extracts every payload section FIRST and removes it from
the text before looking for a request block, so nothing inside a payload
can ever be parsed as (or shadow) a request. A param whose value is exactly
`---PAYLOAD-<name>---` is replaced with that payload's text -- and only
`body` (gmail.create_draft) and `content` (drive.create_file) may reference
one. Everything else about a payload -- a missing reference target, a
duplicate name, an unreferenced payload, a reference from any other field
-- is `invalid_payload`. Layer 3 then validates the substituted text like
any other value. This moves FEWER bytes through an LLM than before, so it
only narrows the attack surface.

Other framing rules (ported 2026-09-22 from the fix/durable-agentmail-webhook
branch): markers must start a line (so a `> `-quoted block in a reply chain
is inert text, not a request), more than one request block is
`ambiguous_request` rather than "first one wins", and a request_id must be
a plain token that can't break the reply's line protocol.

Injection pre-filter (added 2026-09-17)
----------------------------------------
`parse_request` optionally takes a score from app/injection_screen.py's
TypeSafe/Jev tripwire, already computed by app/pipeline.py. It is used ONLY
to short-circuit path (2): when there's no block AND the score is at or
above the configured threshold, the (paid, slower) reader LLM call is
skipped and the request resolves to verb="unsupported" -- the same outcome
a genuine extraction failure produces, so a would-be attacker learns
nothing about having been flagged. The block path is gated separately, in
Layer 3 (app/policy.py's apply_screen_gate), and only for write verbs.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any

import yaml

from app.config import READER_LLM_MAX_INPUT_CHARS
from app.policy import BATCH_MAX_ITEMS
from app.reader_llm import ReaderLLM
from app.yaml_safe import safe_load_no_coerce

_BLOCK_RE = re.compile(r"^---GATEKEEPER-REQUEST---[ \t]*\n(.*?)\n---END---[ \t]*$", re.S | re.M)
_PAYLOAD_RE = re.compile(
    r"^---GATEKEEPER-PAYLOAD-(?P<name>[A-Za-z0-9_-]{1,32})---[ \t]*\n(?P<body>.*?)^---END-PAYLOAD-(?P=name)---[ \t]*$",
    re.S | re.M,
)
_PAYLOAD_REF_RE = re.compile(r"^---PAYLOAD-(?P<name>[A-Za-z0-9_-]{1,32})---$")

REQUEST_ID_MAX_CHARS = 128
_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")

# The only (verb, param) pairs a payload may fill -- the long free-text
# fields. Anything else (a recipient, a title, an event id) stays short
# and inline where it's visible in the request block itself.
PAYLOAD_PARAMS: dict[str, frozenset[str]] = {
    "gmail.create_draft": frozenset({"body"}),
    "drive.create_file": frozenset({"content"}),
}
# Upper bound on one payload before Layer 3's per-field caps even apply --
# keeps a pathological email from being chunked through the injection
# screen at great length.
PAYLOAD_MAX_CHARS = 200_000


@dataclass(frozen=True)
class EmailParts:
    """An email split deterministically, before any parsing or screening.
    app/pipeline.py screens these parts individually (app/injection_screen.py)."""

    remainder: str  # the text with every payload section removed
    block_texts: tuple[str, ...]  # raw YAML of each request block found in `remainder`
    payloads: dict[str, str] = field(default_factory=dict)  # name -> verbatim text
    payload_error: str | None = None  # a structural payload problem found while splitting


@dataclass(frozen=True)
class ParsedRequest:
    request_id: str
    verb: str
    params: dict[str, Any] = field(default_factory=dict)
    # "block" | "llm" | "screened" (LLM skipped: injection score) |
    # "llm_skipped" (LLM skipped: too long)
    source: str = "block"
    # Set when the request could not be turned into a verb + params at all;
    # app/pipeline.py denies it with this code, without reaching Layer 3.
    # invalid_request_block | ambiguous_request | invalid_payload | too_long_for_freeform
    parse_error: str | None = None
    parse_error_detail: str | None = None  # our own words, never echoed input
    payload_count: int = 0
    payload_chars: int = 0
    # Populated only when verb == "batch" (block path only -- "batch" is
    # resolved here, in Layer 2, into N ordinary ParsedRequests, never a
    # real Verb the policy engine knows about; see app/pipeline.py's batch
    # handling). Each item may carry its own parse_error independently --
    # one malformed item denies only that item, not the whole batch.
    batch_items: tuple[ParsedRequest, ...] = ()


def normalize_newlines(text: str) -> str:
    return text.replace("\r\n", "\n").replace("\r", "\n")


def split_email(email_text: str) -> EmailParts:
    text = normalize_newlines(email_text)
    payloads: dict[str, str] = {}
    payload_error: str | None = None
    spans: list[tuple[int, int]] = []
    for match in _PAYLOAD_RE.finditer(text):
        name = match.group("name")
        body = match.group("body")
        # The regex consumed the newline after the start marker; the one
        # before the end marker is framing too. Nothing else is touched.
        if body.endswith("\n"):
            body = body[:-1]
        if name in payloads:
            payload_error = f"payload '{name}' appears more than once"
        elif len(body) > PAYLOAD_MAX_CHARS:
            payload_error = f"payload '{name}' exceeds {PAYLOAD_MAX_CHARS} characters"
        payloads[name] = body
        spans.append(match.span())

    remainder_parts: list[str] = []
    cursor = 0
    for start, end in spans:
        remainder_parts.append(text[cursor:start])
        cursor = end
    remainder_parts.append(text[cursor:])
    remainder = "\n".join(remainder_parts)

    block_texts = tuple(m.group(1) for m in _BLOCK_RE.finditer(remainder))
    return EmailParts(remainder=remainder, block_texts=block_texts, payloads=payloads, payload_error=payload_error)


def fallback_request_id_for(agentmail_message_id: str) -> str:
    """A short, stable id for requests that didn't state one. Derived from the
    AgentMail message id so a redelivered message still dedupes, but readable
    in the reply (raw Message-IDs look like `<CAHy...@mail.gmail.com>`)."""
    return "req-" + hashlib.sha256(agentmail_message_id.encode()).hexdigest()[:12]


def parse_request(
    email_text: str,
    agentmail_message_id: str,
    reader_llm: ReaderLLM,
    *,
    injection_score: float | None = None,
    injection_deny_threshold: float | None = None,
    parts: EmailParts | None = None,
) -> ParsedRequest:
    """`parts` lets app/pipeline.py pass the split it already made (and
    screened); tests may omit it."""
    parts = parts if parts is not None else split_email(email_text)
    fallback_id = fallback_request_id_for(agentmail_message_id)

    if parts.block_texts or parts.payloads:
        return _parse_block(parts, fallback_id)

    # Freeform path only, below this point. `source` records why the reader
    # LLM was skipped when it was, so the audit log shows it was never called.
    if (
        injection_score is not None
        and injection_deny_threshold is not None
        and injection_score >= injection_deny_threshold
    ):
        return ParsedRequest(request_id=fallback_id, verb="unsupported", params={}, source="screened")

    if len(parts.remainder) > READER_LLM_MAX_INPUT_CHARS:
        return ParsedRequest(
            request_id=fallback_id, verb="unsupported", params={}, source="llm_skipped",
            parse_error="too_long_for_freeform",
            parse_error_detail=f"a plain-text request may be at most {READER_LLM_MAX_INPUT_CHARS} characters",
        )

    return _parse_via_llm(parts.remainder, fallback_id, reader_llm)


def _block_error(fallback_id: str, code: str, detail: str, parts: EmailParts, request_id: str | None = None, verb: str = "unsupported") -> ParsedRequest:
    return ParsedRequest(
        request_id=request_id or fallback_id, verb=verb, params={}, source="block",
        parse_error=code, parse_error_detail=detail,
        payload_count=len(parts.payloads), payload_chars=sum(len(p) for p in parts.payloads.values()),
    )


def _validate_request_shape(data: Any) -> tuple[str | None, str | None, dict[str, Any] | None, str | None]:
    """(request_id, verb, params, error) from one parsed YAML mapping --
    shared between the top-level block and each batch sub-item (see
    _parse_batch), so both validate request_id/verb/params identically."""
    if not isinstance(data, dict):
        return None, None, None, "must be a YAML mapping"

    request_id = data.get("request_id")
    if not isinstance(request_id, str) or not _REQUEST_ID_RE.fullmatch(request_id.strip()):
        return (
            None, None, None,
            "request_id is required: 1-128 characters of letters, digits and . _ : - (starting with a letter or digit)",
        )
    request_id = request_id.strip()

    verb = data.get("verb")
    if not isinstance(verb, str) or not verb.strip():
        return request_id, None, None, "verb is required"
    verb = verb.strip()

    params = data.get("params", {})
    if params is None:
        params = {}
    if not isinstance(params, dict):
        return request_id, verb, None, "params must be a mapping"

    return request_id, verb, params, None


def _parse_block(parts: EmailParts, fallback_id: str) -> ParsedRequest:
    if len(parts.block_texts) > 1:
        return _block_error(fallback_id, "ambiguous_request", "the email contains more than one GATEKEEPER-REQUEST block", parts)
    if not parts.block_texts:
        return _block_error(fallback_id, "invalid_payload", "payload sections were sent without a GATEKEEPER-REQUEST block", parts)

    try:
        data = safe_load_no_coerce(parts.block_texts[0])
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        where = f" (block line {mark.line + 1}, column {mark.column + 1})" if mark is not None else ""
        return _block_error(fallback_id, "invalid_request_block", f"the block is not valid YAML{where}", parts)

    request_id, verb, params, err = _validate_request_shape(data)
    if err:
        return _block_error(fallback_id, "invalid_request_block", err, parts, request_id=request_id, verb=verb or "unsupported")
    # _validate_request_shape's contract guarantees these are not None
    # here; checked explicitly rather than with `assert`, which `python
    # -O` strips (same discipline as app/policy.py's evaluators).
    if request_id is None or verb is None or params is None:
        return _block_error(fallback_id, "invalid_request_block", "validated request shape missing", parts)

    if parts.payload_error:
        return _block_error(fallback_id, "invalid_payload", parts.payload_error, parts, request_id=request_id, verb=verb)

    if verb == "batch":
        return _parse_batch(request_id, params, parts, fallback_id)

    params, payload_problem = _substitute_payloads(verb, params, parts.payloads)
    if payload_problem:
        return _block_error(fallback_id, "invalid_payload", payload_problem, parts, request_id=request_id, verb=verb)

    return ParsedRequest(
        request_id=request_id, verb=verb, params=params, source="block",
        payload_count=len(parts.payloads), payload_chars=sum(len(p) for p in parts.payloads.values()),
    )


def _parse_batch(batch_request_id: str, params: dict[str, Any], parts: EmailParts, fallback_id: str) -> ParsedRequest:
    """`verb: batch` is resolved entirely here: `params.requests` (a list
    of {request_id, verb, params} mappings, identical in shape to a
    top-level block) becomes N ordinary ParsedRequests, run independently
    by app/pipeline.py -- each with its own dedupe/policy/execution/audit
    record. A malformed or duplicate-id ITEM denies only that item; a
    problem with the batch envelope itself (missing/oversized `requests`,
    a payload no item referenced) denies the whole batch, since there's
    nothing else to run in that case."""
    items_raw = params.get("requests")
    if not isinstance(items_raw, list) or not items_raw:
        return _block_error(
            fallback_id, "invalid_request_block", "batch requires a non-empty 'requests' list",
            parts, request_id=batch_request_id, verb="batch",
        )
    if len(items_raw) > BATCH_MAX_ITEMS:
        return _block_error(
            fallback_id, "invalid_request_block", f"batch accepts at most {BATCH_MAX_ITEMS} items",
            parts, request_id=batch_request_id, verb="batch",
        )

    seen_ids: set[str] = set()
    all_used_payloads: set[str] = set()
    items: list[ParsedRequest] = []
    for i, item_raw in enumerate(items_raw):
        item_id, item_verb, item_params, err = _validate_request_shape(item_raw)
        placeholder_id = item_id or f"{batch_request_id}-item{i}"
        if err:
            items.append(ParsedRequest(
                request_id=placeholder_id, verb=item_verb or "unsupported", params={}, source="block",
                parse_error="invalid_request_block", parse_error_detail=f"batch item {i}: {err}",
            ))
            continue
        # _validate_request_shape's contract guarantees these three are not
        # None when err is None -- checked explicitly, not with `assert`.
        if item_id is None or item_verb is None or item_params is None:
            items.append(ParsedRequest(
                request_id=placeholder_id, verb="unsupported", params={}, source="block",
                parse_error="invalid_request_block", parse_error_detail=f"batch item {i}: validated request shape missing",
            ))
            continue
        if item_verb == "batch":
            items.append(ParsedRequest(
                request_id=item_id, verb="unsupported", params={}, source="block",
                parse_error="invalid_request_block", parse_error_detail=f"batch item {i}: a batch cannot contain another batch",
            ))
            continue
        if item_id == batch_request_id:
            # The outer request_id is recorded as `processing` before any
            # item runs, so an item sharing it would always be answered
            # `duplicate` (falsely claiming an earlier reply) and its final
            # status row would overwrite the batch's own. Denied under a
            # placeholder id so it can't touch the batch's status row.
            items.append(ParsedRequest(
                request_id=f"{batch_request_id}-item{i}",
                verb=item_verb, params={}, source="block",
                parse_error="invalid_request_block",
                parse_error_detail=f"batch item {i}: request_id must differ from the batch's own request_id",
            ))
            continue
        if item_id in seen_ids:
            items.append(ParsedRequest(
                request_id=item_id, verb=item_verb, params={}, source="block",
                parse_error="invalid_request_block", parse_error_detail=f"batch item {i}: duplicate request_id within this batch",
            ))
            continue
        seen_ids.add(item_id)
        item_params, used, payload_problem = _substitute_payloads_for_item(item_verb, item_params or {}, parts.payloads)
        if payload_problem:
            items.append(ParsedRequest(
                request_id=item_id, verb=item_verb, params={}, source="block",
                parse_error="invalid_payload", parse_error_detail=f"batch item {i}: {payload_problem}",
            ))
            continue
        all_used_payloads |= used
        items.append(ParsedRequest(request_id=item_id, verb=item_verb, params=item_params, source="block"))

    unused = sorted(set(parts.payloads) - all_used_payloads)
    if unused:
        return _block_error(
            fallback_id, "invalid_payload",
            f"payload section(s) not referenced by any batch item: {', '.join(unused)}",
            parts, request_id=batch_request_id, verb="batch",
        )

    return ParsedRequest(
        request_id=batch_request_id, verb="batch", params={}, source="block", batch_items=tuple(items),
        payload_count=len(parts.payloads), payload_chars=sum(len(p) for p in parts.payloads.values()),
    )


def _payload_ref(value: Any) -> str | None:
    if isinstance(value, str):
        match = _PAYLOAD_REF_RE.fullmatch(value.strip())
        if match:
            return match.group("name")
    return None


def _substitute_payloads_for_item(
    verb: str, params: dict[str, Any], payloads: dict[str, str]
) -> tuple[dict[str, Any], set[str], str | None]:
    """Substitutes payload references for ONE request; returns
    (new_params, used_payload_names, error). Does not check whether every
    payload in the email was used -- a single request checks that itself
    (_substitute_payloads, below); a batch checks it once, collectively,
    across every item (_parse_batch), since different items may
    legitimately use different payloads."""
    allowed = PAYLOAD_PARAMS.get(verb, frozenset())
    out: dict[str, Any] = {}
    used: set[str] = set()
    for key, value in params.items():
        values = value if isinstance(value, list) else [value]
        refs = [name for name in (_payload_ref(v) for v in values) if name]
        if not refs:
            out[key] = value
            continue
        if key not in allowed or isinstance(value, list):
            return params, used, f"'{key}' cannot take a payload (only {', '.join(sorted(allowed)) or 'no field'} can, for {verb})"
        name = refs[0]
        if name not in payloads:
            return params, used, f"'{key}' references payload '{name}', which is not in the email"
        out[key] = payloads[name]
        used.add(name)
    return out, used, None


def _substitute_payloads(verb: str, params: dict[str, Any], payloads: dict[str, str]) -> tuple[dict[str, Any], str | None]:
    out, used, error = _substitute_payloads_for_item(verb, params, payloads)
    if error:
        return params, error
    unused = sorted(set(payloads) - used)
    if unused:
        return params, f"payload section(s) not referenced by any param: {', '.join(unused)}"
    return out, None


def _parse_via_llm(email_text: str, fallback_request_id: str, reader_llm: ReaderLLM) -> ParsedRequest:
    extraction = reader_llm.extract(email_text)
    if extraction is None:
        if getattr(reader_llm, "last_failure", None) == "truncated":
            # The model ran out of output budget mid-answer: most likely a
            # long draft/file it was asked to reproduce. Say so, instead of
            # the misleading "could not be understood".
            return ParsedRequest(
                request_id=fallback_request_id, verb="unsupported", params={}, source="llm",
                parse_error="too_long_for_freeform",
                parse_error_detail="the request was too long to extract from plain text",
            )
        return ParsedRequest(request_id=fallback_request_id, verb="unsupported", params={}, source="llm")

    params: dict[str, Any] = {}
    for name in (
        "query", "max_results", "newer_than_days", "day_offset", "days", "to", "subject", "body", "thread_id",
        "title", "start_time", "duration_minutes", "attendees", "add_attendees", "remove_attendees", "event_id",
        "name", "content", "location",
    ):
        value = getattr(extraction, name, None)
        if value is not None:
            params[name] = value

    request_id = (
        extraction.request_id.strip()
        if extraction.request_id and extraction.request_id.strip()
        else fallback_request_id
    )
    if not _REQUEST_ID_RE.fullmatch(request_id[:REQUEST_ID_MAX_CHARS]):
        request_id = fallback_request_id  # an LLM-copied id that can't be a request_id is simply not used
    return ParsedRequest(request_id=request_id[:REQUEST_ID_MAX_CHARS], verb=extraction.verb, params=params, source="llm")
