# RUNBOOK

Local run, tests, the Cloud Run deploy sequence, and the kill switch.
For the design and the layer-by-layer walkthrough, see the repo
[README](../README.md) and `research/*.md`.

## Local run

```bash
cd data-gatekeeper-agent
uv sync --extra dev
cp .env.example .env
```

Fill in `.env`. At minimum, to actually process a request end to end
you need `AGENTMAIL_API_KEY`, `AGENTMAIL_WEBHOOK_SECRET`,
`AGENTMAIL_INBOX_ID`, `GATEKEEPER_INBOX_ADDRESS`, `ALLOWED_SENDERS`,
`OWNER_EMAIL`, `ANTHROPIC_API_KEY`, and the three `GOOGLE_*` credentials
(minted once via `scripts/google_auth.py`, below). With nothing filled
in, the app still **imports** and the **test suite still runs**
(everything below the app layer is tested against fakes, not real
credentials) — only actually starting the server and hitting the real
webhook route needs real values.

Implemented verbs as of this build: `gmail.search`, `gmail.create_draft`,
`calendar.list_events`, `calendar.create_event`, `calendar.update_event`,
`calendar.delete_event`, `drive.create_file`. `calendar.list_events`
resolves relative day language ("today"/"tomorrow"/"this week") to a
`day_offset`/`days` pair purely in Python, in the timezone set by
`OWNER_TIMEZONE` (default `Asia/Jerusalem`) — see
`app/calendar_window.py`. `drive.search` and `contacts.search` still
return `not_implemented`.

**Write verbs, by owner's explicit choice (see CLAUDE.md):**
`gmail.create_draft` only ever creates a Gmail DRAFT — the code never
calls a send endpoint (see `app/gmail_executor.py`'s docstring) — so the
owner reviewing and manually sending it in Gmail is the approval step
for that verb. The calendar write verbs and `drive.create_file` run
fully autonomously, with **no recipient/attendee allowlist and no
human-approval step** — `calendar.create_event`/`update_event` send real
Calendar invite/update emails to whatever attendee addresses the request
names, immediately. There is no push-approval channel in this build.

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

Fully offline — no network calls, no credentials, no `.env` required.
Every provider boundary (`app/reader_llm.py`, `app/gmail_executor.py`,
`app/agentmail_client.py`) is a `Protocol` with a real implementation
(gated behind having real credentials, never constructed by a test) and
a fake (`tests/fakes.py`, used by every test). See the final build
report for the exact list of test scenarios covered.

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

Project `data-gatekeeper-roishik`, region `europe-west1` (per the
README's decided architecture). Secrets are mounted from Secret Manager,
never baked into the image or passed as plain `--set-env-vars`.

```bash
PROJECT=data-gatekeeper-roishik
REGION=europe-west1
SERVICE=data-gatekeeper-agent

gcloud config set project "$PROJECT"

# One-time: enable the APIs this deploy needs.
gcloud services enable run.googleapis.com secretmanager.googleapis.com \
  artifactregistry.googleapis.com

# Build and push the image (Cloud Build; or `docker build` + `docker push`
# to Artifact Registry if you prefer building locally).
gcloud builds submit --tag "$REGION-docker.pkg.dev/$PROJECT/gatekeeper/$SERVICE:latest"

# One-time per secret: create it (see scripts/google_auth.py's printed
# commands for the three GOOGLE_* ones). Repeat this shape for
# AGENTMAIL_API_KEY, AGENTMAIL_WEBHOOK_SECRET, ANTHROPIC_API_KEY, etc.
#   gcloud secrets create AGENTMAIL_API_KEY --data-file=-   # then paste + Ctrl-D
#   gcloud secrets create AGENTMAIL_WEBHOOK_SECRET --data-file=-
#   gcloud secrets create ANTHROPIC_API_KEY --data-file=-

gcloud run deploy "$SERVICE" \
  --project "$PROJECT" \
  --region "$REGION" \
  --image "$REGION-docker.pkg.dev/$PROJECT/gatekeeper/$SERVICE:latest" \
  --no-allow-unauthenticated=false \
  --set-env-vars "AGENTMAIL_INBOX_ID=...,GATEKEEPER_INBOX_ADDRESS=roi.shikler@agentmail.to,ALLOWED_SENDERS=...,OWNER_EMAIL=...,MAX_REQUESTS_PER_DAY=20,ANTHROPIC_MODEL=claude-haiku-4-5-20251001,AUDIT_LOG_BACKEND=sheets,STATE_STORE_BACKEND=sheets" \
  --set-secrets "AGENTMAIL_API_KEY=AGENTMAIL_API_KEY:latest,AGENTMAIL_WEBHOOK_SECRET=AGENTMAIL_WEBHOOK_SECRET:latest,ANTHROPIC_API_KEY=ANTHROPIC_API_KEY:latest,GOOGLE_CLIENT_ID=GOOGLE_CLIENT_ID:latest,GOOGLE_CLIENT_SECRET=GOOGLE_CLIENT_SECRET:latest,GOOGLE_REFRESH_TOKEN=GOOGLE_REFRESH_TOKEN:latest" \
  --min-instances 0 \
  --max-instances 2 \
  --memory 256Mi
```

Notes:
- `--no-allow-unauthenticated=false` means the service IS publicly
  reachable (AgentMail's webhook has to be able to POST to it from the
  open internet) — Layer 0's signature verification is what stands in
  for network-level auth here, which is exactly why it runs first and
  rejects loudly on any failure.
- After the first deploy with `AUDIT_LOG_BACKEND=sheets` /
  `STATE_STORE_BACKEND=sheets`, watch the Cloud Run logs for the "created
  a new ... spreadsheet" warning (`app/audit_log.py`, `app/state_store.py`)
  and copy the printed spreadsheet id into
  `GOOGLE_SHEETS_LOG_SPREADSHEET_ID` / `GOOGLE_SHEETS_STATE_SPREADSHEET_ID`
  (as an env var or another Secret Manager entry), then redeploy — otherwise
  a cold start after scale-to-zero creates a fresh spreadsheet every time.
- Same idea for `drive.create_file` (`app/drive_executor.py`): the first
  call with `GOOGLE_DRIVE_FOLDER_ID` unset creates a Drive folder and
  logs its id at WARNING — pin it into `GOOGLE_DRIVE_FOLDER_ID` so every
  later write lands in the same folder instead of a fresh one per cold
  start.
- Register the deployed service's URL + `/webhooks/agentmail` as the
  AgentMail webhook endpoint (event type `message.received`) once it's
  live, and copy the signing secret AgentMail gives you into the
  `AGENTMAIL_WEBHOOK_SECRET` secret above.

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
   gcloud run services delete data-gatekeeper-agent --project data-gatekeeper-roishik --region europe-west1
   ```
   Removes the running service entirely; AgentMail's webhook then just
   fails to connect (and should be disabled too, per step 1, so it stops
   retrying against a dead endpoint rather than retrying forever).

Any single one of these is sufficient on its own. All three together is
the "actually gone" state: no listener, no valid Google credential, no
running service.

## Log retention

Not automated in this MVP. `AuditLog`'s two backends (`JSONLAuditLog`,
`SheetsAuditLog`) are both simple appends with no built-in expiry — see
the final build report's "known gaps" for what a real retention job
would need to do (the hash chain makes deleting an OLD entry in the
middle detectable-as-tampering by design, so a retention job can only
safely truncate from the START of the chain and record where it cut,
not delete arbitrary rows).
