"""
failures.py — turns an exception raised while handling a request into a
small, reply-safe error code.

Before this existed (until 2026-09-22), any exception after Layer 1 marked
a message as seen escaped app/pipeline.py entirely: the message was never
retried (it was already marked seen), the requester got no reply, and no
audit record was written -- a write verb could even complete and then go
unaudited if the reply step failed. app/pipeline.py now catches every
exception past that point and maps it here, so each request gets exactly
one reply and exactly one audit record no matter where it failed.

What crosses into the reply and the audit log is ONLY the code, whether a
resend could help, and the exception's class name -- never the exception
message. A Google API error message can echo request content (e.g. a Gmail
search query in a URL), and the audit log's data-minimization rule
(app/audit_log.py) applies to failures exactly as it does to successes.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Failure:
    code: str  # machine-readable, appears in the reply's status block
    retryable: bool  # whether resending the same request could plausibly succeed
    type_name: str  # exception class name, for the audit log -- never its message


class GatekeeperDenied(Exception):
    """A request that was valid on its face but is refused at execution
    time -- e.g. an update/delete aimed at a calendar event the gatekeeper
    didn't create. Becomes reply status `denied` (same as a Layer 3
    denial), not `error`: nothing broke, the answer is just no."""

    def __init__(self, error_code: str, reason: str = ""):
        super().__init__(error_code)
        self.error_code = error_code
        self.reason = reason


def _http_status(exc: BaseException) -> int | None:
    """Status code of a googleapiclient HttpError, without importing
    googleapiclient (keeps this module importable without the package)."""
    status = getattr(exc, "status_code", None)
    if status is None:
        status = getattr(getattr(exc, "resp", None), "status", None)
    try:
        return int(status) if status is not None else None
    except (TypeError, ValueError):
        return None


def classify_failure(exc: BaseException) -> Failure:
    type_name = type(exc).__name__

    if type_name == "HttpError":
        status = _http_status(exc)
        if status == 404 or status == 410:
            return Failure("not_found", False, type_name)
        if status == 409:
            return Failure("conflict", False, type_name)
        if status == 429 or (status is not None and status >= 500):
            return Failure("upstream_unavailable", True, type_name)
        return Failure("upstream_rejected", False, type_name)

    # Network-level failures: timeouts, refused/reset connections, DNS.
    # TimeoutError and ConnectionError are both OSError subclasses; httpx
    # and httplib2 raise their own hierarchies for the same conditions.
    module = type(exc).__module__ or ""
    if isinstance(exc, OSError) or module.startswith(("httpx", "httplib2")):
        return Failure("upstream_unavailable", True, type_name)

    return Failure("internal_error", False, type_name)
