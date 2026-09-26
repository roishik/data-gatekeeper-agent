# RUNBOOK

Local run, tests, the Cloud Run deploy sequence, post-deploy checks, and
the kill switch. For the request/response format see
[PROTOCOL.md](PROTOCOL.md); for the design and the layer-by-layer
walkthrough, the repo [README](../README.md) and `research/*.md`.

## Local run

```bash
cd data-gatekeeper-agent
uv sync            # installs the dev group (pytest) too
cp .env.example .env
```

Fill in `.env`. At minimum, to actually process a request end to end
you need `AGENTMAIL_API_KEY`, `AGENTMAIL_WEBHOOK_SECRET`,
`AGENTMAIL_INBOX_ID`, `GATEKEEPER_INBOX_ADDRESS`, `ALLOWED_SENDERS`,
`ANTHROPIC_API_KEY`, and the three `GOOGLE_*` credentials (minted once via
`scripts/google_auth.py`, below). `OWNER_EMAIL` is only used by the live
e2e tests now: replies are no longer BCC'd to the owner (2026-09-22). With
nothing filled in, the app still **imports** and the **test suite still
runs** (everything below the app layer is tested against fakes, not real
credentials) — only actually starting the server and hitting the real
webhook route needs real values.

**`TYPESAFE_API_KEY` (TypeSafe/Jev screening).** Set in prod. Two screens
use it:
- **Inbound** (`app/injection_screen.py`) scores every part of every
  email: subject, body, request block, and each payload.
  - At/above `INJECTION_DENY_THRESHOLD` (0.85), the subject+block "request
    score" denies block-path **write** verbs and skips the reader LLM on the
    freeform path.
  - Fails **open**: an unreachable screen means no signal.
- **Outbound** (`app/output_screen.py`) screens every item a reply carries
  and withholds the text of flagged items (ids kept).
  - Thresholds: `OUTPUT_SENSITIVE_THRESHOLD` 0.5 and
    `OUTPUT_INJECTION_THRESHOLD` 0.7.
  - Fails **closed** (`OUTPUT_SCREEN_FAIL_MODE=closed`): an unscreenable
    item's text is withheld.

Tuning: `JEV_CHUNK_CHARS` 4000, `JEV_CHUNK_OVERLAP` 200,
`JEV_MAX_WORKERS` 8, `JEV_TIMEOUT_SECONDS` 10. Left unset locally, both
screens are no-ops and behave as if the feature didn't exist.

**Reader LLM limits.** Plain-text requests longer than
`READER_LLM_MAX_INPUT_CHARS` (20,000) skip the LLM and are answered
`too_long_for_freeform`, pointing at the payload rail
([PROTOCOL.md](PROTOCOL.md)).

Implemented verbs: `gmail.search`, `gmail.create_draft`,
`calendar.list_calendars`, `calendar.list_events`, `calendar.create_event`,
`calendar.update_event`, `calendar.delete_event`, `drive.create_file`.
`calendar.list_events` resolves relative day language
("today"/"tomorrow"/"this week"/"last week") to a `day_offset`/`days` pair
purely in Python, in the timezone set by `OWNER_TIMEZONE` (default
`Asia/Jerusalem`) — see `app/calendar_window.py`. Calendar verbs take an
optional `calendar_id`; anything but `primary` must be in the account's own
calendar list with enough access (no new OAuth scope: `calendar.readonly`
does the lookup, `calendar.events` the write). `drive.search` and `contacts.search` still
return `not_implemented`.

**Write verbs, by owner's explicit choice (see CLAUDE.md):**
- `gmail.create_draft` only ever creates a Gmail DRAFT. The code never
  calls a send endpoint (see `app/gmail_executor.py`'s docstring), so the
  owner reviewing and manually sending it in Gmail is the approval step.
- The calendar write verbs and `drive.create_file` run autonomously, with
  no recipient/attendee allowlist and no human-approval step. Since
  2026-09-22:
  - `update_event`/`delete_event` only touch events the gatekeeper created
    itself (a private extended property set at creation).
  - Guests are added/removed, never replaced wholesale.
  - An event with attendees has its title screened by Jev before any
    invite goes out.

**A note on the AgentMail key's name.** This project's code always reads
`AGENTMAIL_API_KEY` (see `app/config.py`) — not `agent_mail_api_key`,
`AGENT_MAIL_API_KEY`, or any other spelling. If your own `.env` already
has the key saved under a different name from an earlier note or script,
add a second line with the exact name `AGENTMAIL_API_KEY=...` (or rename
the existing one) — `app/config.py` does not fall back to alternate
spellings for this one key.

```bash
uv run uvicorn app.main:app --reload --port 8080
```

`AUDIT_LOG_BACKEND` and `STATE_STORE_BACKEND` both default to the
zero-credential local backends (`jsonl` / `memory`), so a local run
never needs the Sheets-backed prod path just to come up.

To actually receive AgentMail's webhook locally, put a tunnel (e.g.
`cloudflared tunnel --url http://localhost:8080`) in front of it and
register that public URL as the webhook endpoint in the AgentMail
console (or via `client.webhooks.create(...)`), with event type
`message.received`.

## Tests

```bash
uv run pytest -q
```

The default suite is fully offline — no network calls, no credentials, no
`.env` required — and runs in CI on every push and PR
(`.github/workflows/ci.yml`). Every provider boundary is a `Protocol`
with a real implementation (gated behind real credentials, never
constructed by a test) and a fake (`tests/fakes.py`).

Three **live** suites skip themselves unless `RUN_E2E=1`. They send real
traffic, so run them deliberately:

```bash
RUN_E2E=1 uv run pytest tests/test_sheets_live.py -v            # real Sheets API, scratch spreadsheets (trashed after)
RUN_E2E=1 uv run pytest tests/test_injection_screen_live.py -v  # real TypeSafe API calls
RUN_E2E=1 uv run pytest tests/test_e2e_live.py -v               # real email through the deployed service
```

`test_sheets_live.py` exists because the fakes store rows exactly where
they're told to, and the real `values.append` doesn't always. See the
"State sheet" section below.

## Google OAuth: minting the refresh token

Once, by hand, on your own machine — never inside the deployed service:

1. Google Cloud Console → project `data-gatekeeper-roishik` → APIs &
   Services → Credentials → Create Credentials → OAuth client ID →
   Application type **Desktop app**. Download the `client_secret.json`.
2. Make sure the OAuth consent screen is **In production** (not
   Testing) — an app left in Testing has its refresh tokens killed every
   7 days. Personal, single-user, unverified was fine for the original
   read-only scope set (`gmail.readonly`, `calendar.readonly`,
   `drive.readonly`, `contacts.readonly`, `drive.file`); `gmail.compose`
   and `calendar.events` were added for write access (`scripts/google_auth.py`'s
   `SCOPES`) — **not independently re-verified against Google's current
   sensitive/restricted-scope tiers**, so if the consent screen starts
   asking for a verification review, that's expected to investigate, not
   a bug in this doc.
3. Run:
   ```bash
   uv run python scripts/google_auth.py --client-secret path/to/client_secret.json
   ```
   This opens a browser for consent, then writes the resulting
   credentials to `~/.config/data-gatekeeper/token.json` (0600,
   never inside this repo) and prints the `gcloud secrets create`
   commands to load `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` /
   `GOOGLE_REFRESH_TOKEN` into Secret Manager, reading the values
   straight out of that file (never printing them to the terminal).
   **If `GOOGLE_REFRESH_TOKEN` was already minted under the OLDER,
   narrower scope set** (before `gmail.compose`/`calendar.events`
   existed), it must be re-minted by re-running this script — write
   calls will fail with an insufficient-scope error against an old
   token, not silently fall back to read-only behavior.
4. Delete `client_secret.json` from wherever you downloaded it once
   step 3 has run — it isn't needed again.

## Cloud Run deploy

Service `data-gatekeeper`, project `data-gatekeeper-roishik`, region
`europe-west1`. Secrets are mounted from Secret Manager, never baked into
the image or passed as plain `--set-env-vars`. Env vars and secrets
persist across source deploys, so a routine deploy is one command.

**Deploy only a clean, pushed commit.** `gcloud run deploy --source=.`
uploads the *working tree* (filtered by `.gcloudignore`), not a commit.
On 2026-09-19 the live revision turned out to be a local commit that had
never been pushed, so GitHub and the deploy disagreed. So:

```bash
git status --porcelain            # must print nothing
git push                          # the commit being deployed must be on GitHub
SHA=$(git rev-parse --short HEAD)
gcloud run deploy data-gatekeeper --project=data-gatekeeper-roishik --region=europe-west1 \
  --source=. --labels=commit=$SHA --timeout=120 --max-instances=1 \
  --update-env-vars=GIT_SHA=$SHA,MAX_REQUESTS_PER_DAY=100 --quiet
```

- `--labels=commit=$SHA` makes "which commit is live?" answerable with
  `gcloud run services describe ... --format='value(metadata.labels.commit)'`.
- `--timeout=120` (raised from 60 on 2026-09-22): a request that runs
  Gmail, Jev and the reply in sequence must never be killed mid-write.
- `--max-instances=1` is part of the audit chain's single-writer guarantee
  (see `app/main.py`).
- `GIT_SHA=$SHA` (new, 2026-09-23): every reply's `protocol_version` field
  reads this env var, falling back to `"dev"` if it's never set. Without
  it, Instinct can't tell a deploy happened from the reply alone.
- `MAX_REQUESTS_PER_DAY=100` (raised from 50, 2026-09-23, owner's decision):
  the code default changed too, but a live env var always wins over the
  code default on redeploy, so this must be set explicitly at least once
  or the live service stays at 50.

To change the allowlist (values contain commas, so use gcloud's custom
delimiter). This widens who can reach the owner's data, so it's the
owner's call:
```bash
gcloud run services update data-gatekeeper --project=data-gatekeeper-roishik --region=europe-west1 --update-env-vars="^;^ALLOWED_SENDERS=roishikler@mail.instinct.com"
```

Initial setup (done once, 2026-09-14/15; kept for rebuilding from scratch):
- `gcloud services enable run.googleapis.com secretmanager.googleapis.com artifactregistry.googleapis.com cloudbuild.googleapis.com`
- Create each secret with `--data-file=-`, reading values from files or
  Python, never pasting them into a shell: `AGENTMAIL_API_KEY`,
  `AGENTMAIL_WEBHOOK_SECRET`, `ANTHROPIC_API_KEY`, `TYPESAFE_API_KEY`, and
  the three `GOOGLE_*` (see `scripts/google_auth.py`'s printed commands).
  Grant `gatekeeper-run@data-gatekeeper-roishik.iam.gserviceaccount.com`
  `roles/secretmanager.secretAccessor` on each secret individually.
- First deploy adds `--service-account=gatekeeper-run@...`,
  `--allow-unauthenticated` (AgentMail must be able to POST from the
  open internet; Layer 0's signature check stands in for network auth),
  `--set-secrets` for every secret above, and the non-secret env vars
  listed in CLAUDE.md's infrastructure table.
- The first run with `AUDIT_LOG_BACKEND=sheets` / `STATE_STORE_BACKEND=sheets`
  and no spreadsheet ids creates the spreadsheets and logs their ids at
  WARNING. Pin them into `GOOGLE_SHEETS_LOG_SPREADSHEET_ID` /
  `GOOGLE_SHEETS_STATE_SPREADSHEET_ID`, or every cold start creates new ones.
- Same for `drive.create_file`: its first live call with
  `GOOGLE_DRIVE_FOLDER_ID` unset creates a folder and logs its id at
  WARNING. Pin it.
- Register `<service URL>/webhooks/agentmail` as the AgentMail webhook
  (event type `message.received`) and store its signing secret as
  `AGENTMAIL_WEBHOOK_SECRET`.

## After every deploy

```bash
uv run python scripts/verify_audit_chain.py --recent 5
```

Read-only. It recomputes the prod audit log's hash chain, says where it
broke if it did (a revision-rollout overlap is the one way the service can
fork its own chain), and summarizes verdicts. It prints no ids and no
content. Then send one real request (or run the live e2e suite) and check
its reply.

## State sheet

`GOOGLE_SHEETS_STATE_SPREADSHEET_ID` holds Layer 1's state, one tab per
record kind. **Column A is always a non-empty key**, enforced in
`SheetsStateStore._append`:

| tab | columns |
|---|---|
| `messages` | message_id, first_seen_at |
| `request_status` | request_id, status, updated_at, sender (append-only, last row wins) |
| `daily_counts` | date (owner's timezone), sender, request_id |

The legacy `requests` tab is dead history. Its rows start with a blank
cell, which made `values.append` shift every later row one column right,
so request dedupe and the daily cap never matched anything from launch
until 2026-09-22. Leave it in place; nothing reads it.

## Kill switch

Three independent actions, any ONE of which stops the pipeline —
practiced here, not just theorized, per research/03 §7's requirement
that a kill switch be a tested operation:

1. **Disable the webhook.** In the AgentMail console (or
   `client.webhooks.delete(webhook_id=...)` / `agentmail webhooks delete`),
   delete or disable the endpoint. AgentMail stops POSTing to this
   service immediately; no code change or redeploy needed.
2. **Revoke Google access.** Go to
   [myaccount.google.com/connections](https://myaccount.google.com/connections),
   find the OAuth client this project registered, and remove its
   access. The refresh token in Secret Manager becomes worthless
   instantly — every subsequent Gmail/Sheets call fails at the token
   -refresh step, before any API call is even attempted.
3. **Delete the Cloud Run service.**
   ```bash
   gcloud run services delete data-gatekeeper --project data-gatekeeper-roishik --region europe-west1
   ```
   Removes the running service entirely; AgentMail's webhook then just
   fails to connect (and should be disabled too, per step 1, so it stops
   retrying against a dead endpoint rather than retrying forever).

Any single one of these is sufficient on its own. All three together is
the "actually gone" state: no listener, no valid Google credential, no
running service.

## Log retention

Not automated in this MVP. `AuditLog`'s two backends (`JSONLAuditLog`,
`SheetsAuditLog`) are both simple appends with no built-in expiry. A real
retention job would have to respect the hash chain: deleting an entry in
the middle is detectable as tampering by design, so a retention job can
only truncate from the START of the chain and record where it cut, never
delete arbitrary rows.
