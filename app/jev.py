"""
jev.py — shared plumbing for every TypeSafe/Jev call: the inbound
injection screen (app/injection_screen.py) and the outbound sensitive-
material screen (app/output_screen.py).

Jev is a "System One" classifier: it answers typed questions about a piece
of state with probabilities and labels. It generates no text and has no
tools, so the most any Jev answer can do in this service is make a screen
deny or withhold something -- never add, change, or route anything.

Owner's cost principle (2026-09-22): Jev tokens are cheap, Anthropic tokens
are not. So nothing here economizes on Jev calls -- every part of every
email and every item of every reply is screened, long text is chunked
(with overlap, so a phrase can't hide across a chunk boundary) rather than
truncated, and a part's score is the MAX over its chunks. What this module
does bound is latency: chunks run concurrently, and every call has a hard
timeout and at most one retry, so a slow TypeSafe can't stall a request
into Cloud Run's own request timeout.

Each worker builds its own client: simple, and nothing about thread safety
of a shared HTTP client has to be assumed.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable, TypeVar

from app.config import JEV_CHUNK_CHARS, JEV_CHUNK_OVERLAP, JEV_MAX_WORKERS, JEV_TIMEOUT_SECONDS

T = TypeVar("T")
R = TypeVar("R")


def new_client(api_key: str, model: str):
    """A TypeSafeClient with this service's timeout and retry policy.
    Lazy import: tests never need the package to reach the fakes."""
    from typesafe_sdk import RetryPolicy, TypeSafeClient

    return TypeSafeClient(
        api_key=api_key,
        model=model,
        timeout=JEV_TIMEOUT_SECONDS,
        retry=RetryPolicy(max_retries=1, timeout=JEV_TIMEOUT_SECONDS),
    )


def chunk_text(text: str, size: int | None = None, overlap: int | None = None) -> list[str]:
    """Splits `text` into windows of at most `size` characters, each
    overlapping the previous by `overlap`. Empty text -> no chunks (nothing
    to screen); short text -> one chunk, unchanged."""
    size = size or JEV_CHUNK_CHARS
    overlap = JEV_CHUNK_OVERLAP if overlap is None else overlap
    if not text:
        return []
    if len(text) <= size:
        return [text]
    step = max(1, size - overlap)
    return [text[start:start + size] for start in range(0, len(text) - overlap, step)]


def run_parallel(fn: Callable[[T], R], items: list[T]) -> list[R]:
    """`fn` over `items` concurrently, results in input order. `fn` is
    expected to catch its own exceptions (every caller here turns a failed
    Jev call into "no signal" rather than an error)."""
    if not items:
        return []
    if len(items) == 1:
        return [fn(items[0])]
    with ThreadPoolExecutor(max_workers=min(JEV_MAX_WORKERS, len(items))) as pool:
        return list(pool.map(fn, items))


def max_score(values: list[Any]) -> float | None:
    """Max over the non-None scores, or None if there are none -- "no
    signal" must never be mistaken for a score of 0."""
    present = [v for v in values if v is not None]
    return max(present) if present else None
