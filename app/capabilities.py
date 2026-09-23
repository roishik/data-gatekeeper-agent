"""
capabilities.py — builds the response for the `capabilities` verb.

Not a Layer 4 executor in the usual sense: it never touches a Google
API, never needs credentials, and returns nothing derived from the
owner's data -- only static facts about this service itself (which
verbs exist, their param bounds, the current protocol version and
quota). That's also why its response skips app/output_screen.py's Jev
screen (app/pipeline.py's _output_items): there is no Google- or
attacker-derived content here to screen.

Added 2026-09-23 at Instinct's request (its review noted trying the
nonexistent verb `drive.capabilities`, and separately asked for a
systematic fix to "which protocol am I talking to" and "what does this
service support" instead of depending on a hand-pasted standing rule
staying in sync -- M1/M2/M7). Every value here is read from the same
source of truth policy.py and config.py already use for validation and
the reply's status block, so this can't drift from what the service
actually enforces the way a separately hand-written description could.
"""
from __future__ import annotations

from dataclasses import dataclass

from app.config import GIT_SHA, MAX_REQUESTS_PER_DAY
from app.policy import BATCH_MAX_ITEMS, VERB_SPECS


@dataclass(frozen=True)
class VerbCapability:
    verb: str
    is_write: bool
    param_bounds: tuple[str, ...]


@dataclass(frozen=True)
class CapabilitiesInfo:
    protocol_version: str
    max_requests_per_day: int
    batch_max_items: int
    verbs: tuple[VerbCapability, ...]


def build_capabilities_info() -> CapabilitiesInfo:
    verbs = tuple(
        VerbCapability(verb=spec.verb.value, is_write=spec.is_write, param_bounds=spec.param_bounds)
        for spec in VERB_SPECS.values()
    )
    return CapabilitiesInfo(
        protocol_version=GIT_SHA,
        max_requests_per_day=MAX_REQUESTS_PER_DAY,
        batch_max_items=BATCH_MAX_ITEMS,
        verbs=verbs,
    )
