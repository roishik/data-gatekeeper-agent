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

logging.getLogger("httpx").setLevel(logging.WARNING)  # never log auth headers

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
OWNER_TIMEZONE = _env("OWNER_TIMEZONE", "Asia/Jerusalem")

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
REPLY_MAX_CHARS = _env_int("REPLY_MAX_CHARS", 4000)

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


def have_google_credentials() -> bool:
    return bool(GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET and GOOGLE_REFRESH_TOKEN)


def have_agentmail_key() -> bool:
    return bool(AGENTMAIL_API_KEY)
