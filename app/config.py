"""
Config / env loading.

Every value comes from an environment variable with a sane default (or,
for genuinely required secrets, no default and a loud failure at the
point of use). On Cloud Run, Secret Manager values are mapped straight
into the process environment — this module never reads a file, never
calls Secret Manager itself, and never guesses a fallback path. That's
the whole design: the same code runs locally (via a `.env` you source
yourself, or plain exported env vars) and in prod with zero branching.

Two conventions carried over from an earlier no-framework agent build
(apartments-agent-from-scratch/app/config.py), because they earned their
keep there:
  1. A minimal, dependency-free `.env` loader for local dev only — it
     never overwrites a var that's already set (so real env vars / Cloud
     Run's injected secrets always win over a stray local `.env`).
  2. Secrets are read once, here, into module constants — never re-read
     ad hoc elsewhere — so there is exactly one place that touches
     `os.environ` for a credential.

IMPORTANT: this module must never print, log, or repr() a secret value.
"""
from __future__ import annotations

import logging
import os
from pathlib import Path

# Never log auth headers, and keep per-request HTTP chatter out of Cloud
# Logging. "httpx2" is the fork the anthropic/typesafe SDKs log through.
for _noisy in ("httpx", "httpx2"):
    logging.getLogger(_noisy).setLevel(logging.WARNING)

logger = logging.getLogger("gatekeeper.config")

APP_DIR = Path(__file__).resolve().parent
PROJECT_DIR = APP_DIR.parent


def _load_dotenv(path: Path) -> None:
    """Minimal .env parser (no external dependency). Never overwrites a
    var that's already set in the real environment — Cloud Run's
    Secret-Manager-backed env vars always win over a local file."""
    if not path.exists():
        return
    for raw_line in path.read_text().splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


_load_dotenv(PROJECT_DIR / ".env")


def _env(name: str, default: str | None = None) -> str | None:
    val = os.environ.get(name)
    return val if val else default


def _env_int(name: str, default: int) -> int:
    val = os.environ.get(name)
    return int(val) if val else default


def _env_float(name: str, default: float) -> float:
    val = os.environ.get(name)
    return float(val) if val else default


def _env_str(name: str, default: str) -> str:
    val = os.environ.get(name)
    return val if val else default


def _env_list(name: str, default: str = "") -> list[str]:
    """Comma-separated env var -> list of trimmed, non-empty strings."""
    raw = os.environ.get(name, default)
    return [item.strip() for item in raw.split(",") if item.strip()]


# ── AgentMail (inbound webhook + outbound reply) ────────────────────────────
AGENTMAIL_API_KEY = _env("AGENTMAIL_API_KEY")
AGENTMAIL_WEBHOOK_SECRET = _env("AGENTMAIL_WEBHOOK_SECRET")  # whsec_... , Layer 0
AGENTMAIL_INBOX_ID = _env("AGENTMAIL_INBOX_ID")
# The gatekeeper's own inbox address. Used to reject inbound mail that
# claims to be FROM our own inbox (a loop / spoof), never to authenticate
# anything by itself.
GATEKEEPER_INBOX_ADDRESS = _env("GATEKEEPER_INBOX_ADDRESS")

# Exact-match sender allowlist, display names ignored (see app/ingress.py).
ALLOWED_SENDERS = _env_list("ALLOWED_SENDERS")

# Who gets BCC'd on every outbound reply — the human audit-log copy.
OWNER_EMAIL = _env("OWNER_EMAIL")

# Webhook timestamp tolerance, seconds. 300s matches the Standard
# Webhooks spec's own recommended default.
WEBHOOK_TOLERANCE_SECONDS = _env_int("WEBHOOK_TOLERANCE_SECONDS", 300)

# ── Rate limiting (Layer 1) ─────────────────────────────────────────────────
MAX_REQUESTS_PER_DAY = _env_int("MAX_REQUESTS_PER_DAY", 20)

# ── Anthropic (Layer 2, quarantined reader LLM only) ────────────────────────
ANTHROPIC_API_KEY = _env("ANTHROPIC_API_KEY")
# Pinned, dated snapshot on purpose — see research/03 and research/05: a
# model swap should be a deliberate, tested change, never a silent float.
ANTHROPIC_MODEL = _env("ANTHROPIC_MODEL", "claude-haiku-4-5-20251001")
# A plain-text (no GATEKEEPER-REQUEST block) email longer than this skips
# the reader LLM entirely and is answered with `too_long_for_freeform`,
# pointing at the payload rail (docs/PROTOCOL.md). Anthropic tokens are the
# ones worth saving; long content belongs in a payload section, which no
# LLM ever reads. Added 2026-09-22.
READER_LLM_MAX_INPUT_CHARS = _env_int("READER_LLM_MAX_INPUT_CHARS", 20000)

# ── TypeSafe (additive injection-screening tripwire, between Layers 1/2) ───
# Added 2026-09-17. NOT the security boundary -- see app/injection_screen.py's
# module docstring. Left unset, TypeSafeInjectionScreen simply isn't
# constructed (app/main.py falls back to NoOpInjectionScreen) and the
# pipeline behaves exactly as it did before this feature existed.
TYPESAFE_API_KEY = _env("TYPESAFE_API_KEY")
# Pinned, versioned snapshot on purpose -- same reasoning as ANTHROPIC_MODEL
# above: a model swap should be a deliberate, tested change, never a silent
# float via the "jev-latest" alias.
TYPESAFE_MODEL = _env_str("TYPESAFE_MODEL", "jev-1.13.0")
# Noul probability at/above which the freeform (LLM-fallback) parse path is
# denied BEFORE the Anthropic reader LLM is ever called (app/request_parser.py).
# Deliberately high: this is an additive tripwire on top of the quarantined
# reader LLM + Layer 3 revalidation, not a replacement for them (research/03
# section 5: classifiers are "one layer, never the only layer"), so a false
# positive here should be rare, not merely unlikely.
INJECTION_DENY_THRESHOLD = _env_float("INJECTION_DENY_THRESHOLD", 0.85)

# Shared Jev call plumbing (app/jev.py, added 2026-09-22). Long text is
# chunked with overlap rather than truncated (Jev calls are cheap; see the
# owner's cost principle in app/jev.py), chunks run concurrently, and every
# call has a hard timeout.
JEV_CHUNK_CHARS = _env_int("JEV_CHUNK_CHARS", 4000)
JEV_CHUNK_OVERLAP = _env_int("JEV_CHUNK_OVERLAP", 200)
JEV_MAX_WORKERS = _env_int("JEV_MAX_WORKERS", 8)
JEV_TIMEOUT_SECONDS = _env_float("JEV_TIMEOUT_SECONDS", 10.0)

# Outbound screen (app/output_screen.py, added 2026-09-22): an item going
# back to Instinct has its text withheld when Jev scores it at/above either
# threshold. Deliberately lower than the inbound deny threshold: a false
# positive here only hides one item's text (its ids stay), while a false
# negative forwards sensitive material. Calibrate against the live suite.
OUTPUT_SENSITIVE_THRESHOLD = _env_float("OUTPUT_SENSITIVE_THRESHOLD", 0.5)
OUTPUT_INJECTION_THRESHOLD = _env_float("OUTPUT_INJECTION_THRESHOLD", 0.7)
# "closed" (default): an item that can't be screened is withheld. "open":
# it's sent as-is. See app/output_screen.py for why outbound fails closed.
OUTPUT_SCREEN_FAIL_MODE = _env_str("OUTPUT_SCREEN_FAIL_MODE", "closed")
if OUTPUT_SCREEN_FAIL_MODE not in {"closed", "open"}:
    raise RuntimeError("OUTPUT_SCREEN_FAIL_MODE must be 'closed' or 'open'")

# ── Policy (Layer 3) ─────────────────────────────────────────────────────
# Query terms that make a gmail.search request refuse to run, regardless
# of who's asking or how politely. Configurable, not hardcoded, per the
# brief. Defaults cover the brief's own example threat.
SENSITIVE_QUERY_TERMS = _env_list(
    "SENSITIVE_QUERY_TERMS",
    "otp,one-time code,one time code,verification code,password reset,"
    "reset your password,2fa,two-factor,two factor,security alert,"
    "bank account,credit card,routing number,account number,wire transfer",
)

# ── Calendar window resolution (Layer 3/4/5, calendar.list_events) ─────────
# IANA timezone name. Used by app/calendar_window.py to turn day_offset/
# days into a concrete midnight-to-midnight window and to format event
# times for the reply -- never by the LLM, which only ever sees/produces
# the small bounded integers (see policy.py's CAL_* constants).
OWNER_TIMEZONE = _env_str("OWNER_TIMEZONE", "Asia/Jerusalem")

# ── Google (Layer 4, executor) ──────────────────────────────────────────────
GOOGLE_CLIENT_ID = _env("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = _env("GOOGLE_CLIENT_SECRET")
GOOGLE_REFRESH_TOKEN = _env("GOOGLE_REFRESH_TOKEN")
# The Gmail account the gatekeeper reads on the user's behalf. "me" is
# valid for the Gmail API but an explicit address makes the audit log and
# any error message readable without cross-referencing the OAuth grant.
GOOGLE_GMAIL_USER = _env("GOOGLE_GMAIL_USER", "me")

# Fixed parent folder for drive.create_file (Layer 4, app/drive_executor.py)
# -- the gatekeeper only ever writes inside this one folder, never
# anywhere else in Drive. Left unset, the folder is created on first use
# and its id logged loudly so the operator can pin it here, same
# convention as GOOGLE_SHEETS_LOG_SPREADSHEET_ID / _STATE_SPREADSHEET_ID.
GOOGLE_DRIVE_FOLDER_ID = _env("GOOGLE_DRIVE_FOLDER_ID")

# ── Reply guard (Layer 5) ────────────────────────────────────────────────
# The cap always still exists (app/reply_guard.py truncates the prose,
# never the machine-readable status block, past this point) -- raised
# from the original 4000 to 25000 (2026-09-17, owner request, after
# raising gmail.search's own max_results made 4000 too tight for a full
# 30-result reply). Not the same limit as AgentMail's own message size
# cap, if it has one -- unverified either way (see agentmail_client.py's
# "NOT exercised against a live AgentMail API call" caveat).
REPLY_MAX_CHARS = _env_int("REPLY_MAX_CHARS", 25000)

# ── Audit log ─────────────────────────────────────────────────────────────
# "jsonl" for local/dev/tests, "sheets" for prod (see app/audit_log.py).
AUDIT_LOG_BACKEND = _env("AUDIT_LOG_BACKEND", "jsonl")
AUDIT_LOG_PATH = _env("AUDIT_LOG_PATH", str(PROJECT_DIR / "data" / "audit_log.jsonl"))
# Set after the first prod run creates its own log spreadsheet (see
# app/audit_log.py SheetsAuditLog and docs/RUNBOOK.md) — left unset, a
# fresh spreadsheet is created on first use and its id is logged loudly
# so the operator can pin it here for every future run.
GOOGLE_SHEETS_LOG_SPREADSHEET_ID = _env("GOOGLE_SHEETS_LOG_SPREADSHEET_ID")

# Same idea for the Sheets-backed StateStore (Layer 1 idempotency / daily
# cap) used in prod — see app/state_store.py.
GOOGLE_SHEETS_STATE_SPREADSHEET_ID = _env("GOOGLE_SHEETS_STATE_SPREADSHEET_ID")

STATE_STORE_BACKEND = _env("STATE_STORE_BACKEND", "memory")  # memory | sheets

HOST = _env("HOST", "0.0.0.0")
PORT = _env_int("PORT", 8080)  # Cloud Run injects PORT; 8080 is its own default


def have_anthropic_key() -> bool:
    return bool(ANTHROPIC_API_KEY)


def have_typesafe_key() -> bool:
    return bool(TYPESAFE_API_KEY)


def have_google_credentials() -> bool:
    return bool(GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET and GOOGLE_REFRESH_TOKEN)


def have_agentmail_key() -> bool:
    return bool(AGENTMAIL_API_KEY)
