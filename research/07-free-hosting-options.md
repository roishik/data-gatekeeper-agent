# 07 — Free / near-free hosting for the gatekeeper (MVP scope)

> Research date: 2026-09-14. MVP scope per the [README](../README.md): AgentMail inbox, Google
> read-only scopes (gmail/calendar/drive/contacts), Claude (Haiku 4.5 / Sonnet 5) via the
> Anthropic API, ~5-50 requests/day, Python preferred. **No LinkedIn/Playwright in the MVP** —
> that changes the hosting calculus a lot versus report 05, which sized hosting around a
> persistent, logged-in browser profile. Without that requirement, this is just "wake up on an
> inbound email, call two APIs, reply" — a workload almost every serverless free tier can carry
> at zero or near-zero cost.

## Executive summary

- **AgentMail's free tier** (3 inboxes, 3,000 emails/mo, **100 emails/day**, 3 GB storage, no
  credit card) is the binding constraint on the whole system, not compute. At 50 requests/day,
  each round trip (inbound request + outbound reply, ignoring the BCC-to-you copy) is 2 messages
  — **100/day**, sitting right at the free-tier ceiling. At the stated 5-50/day range, budget for
  outgrowing free AgentMail into the **$20/mo Developer tier** before you outgrow any compute
  free tier. ([agentmail.to/pricing](https://www.agentmail.to/pricing))
- AgentMail delivers events by **webhook only** (Svix-based, HMAC-SHA256, `svix-id` /
  `svix-timestamp` / `svix-signature` headers, Standard Webhooks spec) — it needs a **public
  HTTPS endpoint**. No websocket push was found in the docs. **Polling** the unfiltered
  `GET /messages` list endpoint is documented and supported as a fallback (AgentMail's own docs
  suggest ~30s polling), which opens up any host that can run a cron job, not just ones that can
  receive inbound HTTP. ([docs.agentmail.to/webhook-agent](https://docs.agentmail.to/webhook-agent), [docs.agentmail.to/webhook-verification](https://docs.agentmail.to/webhook-verification), [docs.agentmail.to — list messages](https://docs.agentmail.to/api-reference/inboxes/messages/list))
- **Cloudflare Workers Free** is the standout: every Worker gets a public `*.workers.dev` HTTPS
  URL for free, satisfying AgentMail's webhook requirement out of the box, at **$0/mo**, with
  no cold start (V8 isolates) and CPU-time billing that only counts *actual compute*, not time
  spent waiting on the Anthropic/AgentMail API calls. Free plan: 100,000 requests/day, 10ms CPU
  time/invocation, Cron Triggers supported (1-minute minimum interval, up to 5 triggers/account)
  as a polling backup. ([developers.cloudflare.com/workers/platform/pricing](https://developers.cloudflare.com/workers/platform/pricing/), [developers.cloudflare.com/workers/platform/limits](https://developers.cloudflare.com/workers/platform/limits/))
- **Google Apps Script** is uniquely attractive for one reason and disqualifying for another: it
  runs *as your own Google account* with native Gmail/Calendar/Drive/Contacts access (no separate
  OAuth client, so it sidesteps the "unverified app, 7-day token" trap entirely) — but **Apps
  Script's `doPost(e)` cannot read arbitrary HTTP request headers** (Google officially declined
  to add this, citing security, as of a long-standing tracked issue). Since AgentMail's signature
  verification lives in headers (`svix-signature` etc.), Apps Script **cannot cryptographically
  verify that a webhook payload actually came from AgentMail** — a real gap for a
  credential-holding gatekeeper. Polling instead of webhooks sidesteps this but adds latency
  and burns UrlFetch quota. ([Google Groups — HTTP headers will not be supported in doPost()](https://groups.google.com/g/google-apps-script-community/c/bgnzoAUV_No))
- **Bedrock AgentCore** and **Vertex AI Agent Engine / Gemini Enterprise Agent Platform** are
  both real, both have an Identity/token-vault story that can hold Google OAuth tokens (AgentCore
  explicitly documents a Google Drive/Gmail OAuth integration), but **neither is free at any
  durable level** and neither is a natively "always-listening" mail server — both are
  invocation/session-billed agent *runtimes* that something else (EventBridge/Lambda,
  Cloud Scheduler/Cloud Run) has to wake up. For a single user at 5-50 req/day they are
  over-engineered: more moving parts, more IAM/policy surface, and non-trivial idle/session
  billing components (Memory events, Gateway invocations, session vCPU-hours) that don't map to
  a true "$0 when nothing happens" model. Both are worth revisiting only if this project grows
  into a multi-tool, multi-tenant agent.
- **Oracle Cloud Always Free (Ampere A1)** is real free compute (now **2 OCPU / 12 GB RAM**,
  halved from 4/24 in a June 2026 change with no public announcement, and users were warned in
  2026 that over-limit legacy instances would be **terminated** starting August 18, 2026) — still
  the most generous perpetually-free VM on the market, but it's a raw VM you fully operate, it's
  idle-reclaimable (Oracle can stop instances under ~10-20% CPU/network/memory utilization over 7
  days — a mail-triggered gatekeeper at 5-50 req/day looks exactly like "idle" to that heuristic),
  and Oracle's free-tier reliability has a real history of account/resource reclamation stories.
  Treat it as free-but-fragile, not free-and-forgettable.
  ([InfoQ — Oracle quietly halves free tier](https://www.infoq.com/news/2026/07/oracle-cloud-free-tier-limits/), [Oracle Cloud FAQ](https://www.oracle.com/cloud/free/faq/))
- **GCP's `e2-micro` Always Free VM**, **Cloud Run free tier** (2M requests/mo, 180,000
  vCPU-seconds, 360,000 GB-seconds), and **AWS Lambda's Always Free tier** (1M requests + 400,000
  GB-seconds/month, confirmed to remain permanent/unlimited even after AWS's July 2025 shift to a
  credit-based *trial* for genuinely new accounts) are all functionally $0/mo at this volume and
  are the closest things to "boringly reliable, actually free forever" compute on this list.
  ([Google Cloud free tier docs](https://docs.cloud.google.com/free/docs/free-cloud-features), [AWS Free Tier changes, July 2025](https://aws.amazon.com/about-aws/whats-new/2025/07/aws-free-tier-credits-month-free-plan/))
- **GitHub Actions** is a poor fit as the primary transport: 5-minute minimum cron granularity,
  documented real-world delays of 15+ minutes under load, and it's fundamentally a CI/test
  runner, not a service — but it is a fine, free (2,000 private-repo minutes/mo) place to run a
  *secondary* polling safety-net or the injection-test CI suite already planned in report 03.
- Free PaaS app hosts (**Render, Koyeb, Railway, Fly.io, Deno Deploy, Supabase Edge Functions,
  Pipedream**) mostly fail the "always-on or wakes instantly on a webhook" test at $0: Render
  free spins down after 15 min idle (~1 min cold start on next HTTP hit — survivable for a
  webhook, since it does wake on the request itself, just slowly); Koyeb free scales to zero
  after 1 hour idle; Fly.io dropped its free tier to a 2-hour trial in 2026; Railway's free
  credit covers only a few hours of runtime. **Deno Deploy's free plan** (1M requests/mo, no
  credit card, no expiry, commercial use allowed) is the one traditional PaaS-style free tier
  that's actually edge-hosted (always warm, like Workers) rather than container-spin-down based —
  worth a look as a Cloudflare Workers alternative if you prefer Deno/TypeScript.
- **Storage**: logging to the user's own **Google Drive/Sheets** is free, keeps data in Google,
  and is easy for the user to read by hand — but it has a real tamper-evidence weakness the user
  should know about (below), and writing to it needs **`drive.file`**, not `drive.readonly`.
  `drive.file` is confirmed to work for the Sheets API too, and is a **non-sensitive** scope (no
  Google verification review needed) **as long as the gatekeeper creates the log file itself**
  rather than needing standing access to a file it didn't create.

---

## 1. AgentMail — the actual bottleneck

| | Free | Developer ($20/mo) | Startup ($200/mo) |
|---|---|---|---|
| Inboxes | 3 | 10 | 150 |
| Emails/month | 3,000 | 10,000 | custom |
| Daily send cap | **100/day** | none | 15,000/day |
| Storage | 3 GB | 10 GB | custom |
| Webhooks | included | included | 10 endpoints |
| Credit card | **not required** | required | required |

Source: [agentmail.to/pricing](https://www.agentmail.to/pricing).

**Delivery mechanisms** (from [docs.agentmail.to](https://docs.agentmail.to/overview) and the
[webhook-agent example](https://docs.agentmail.to/webhook-agent)):

- **Webhooks (recommended by AgentMail itself):** you register a public HTTPS URL; AgentMail
  (via Svix) POSTs `message.received` (and other lifecycle: `sent`, `delivered`, `bounced`,
  `complained`, `rejected`, plus domain verification) events, JSON, capped at 1 MB (text/html
  fields are dropped if the message is larger). Your endpoint must return `200` fast and process
  async. **Signature verification** uses the Standard Webhooks spec: `svix-id`, `svix-timestamp`,
  `svix-signature` headers, HMAC-SHA256 over `id.timestamp.payload` with the endpoint's signing
  secret (`whsec_...`). This is genuinely good, standard, verifiable security — *if* your host can
  read those headers. ([webhook-verification docs](https://docs.agentmail.to/webhook-verification))
- **Websockets:** not documented anywhere found. Treat as **not supported** — plan around
  webhook or polling only.
- **Polling:** `GET /inboxes/{id}/messages` lists newest-first; AgentMail's own docs recommend
  polling the *unfiltered* list every ~30s and matching in your own code, because filtered
  queries (`from`/`to`/`subject`) are served by a search index that can lag fresh deliveries.
  This is a legitimate, supported fallback for hosts that can't receive inbound HTTP (Apps
  Script, GitHub Actions, a Cloudflare Cron Trigger with no public listener, a home machine
  behind NAT with no tunnel). ([messages/list docs](https://docs.agentmail.to/api-reference/inboxes/messages/list))

**Implication for hosting choice:** if your host has a public HTTPS URL "for free" (Cloudflare
Workers, Render, Fly, a VPS+Tunnel, Cloud Run), take the webhook path — it's lower latency and
AgentMail's own recommended pattern. If it doesn't (Apps Script, GitHub Actions, Lambda without
API Gateway, a plain cron job), polling every 1-5 minutes is fully sufficient for this project's
10-second-to-5-minute latency tolerance (per report 05) and costs nothing extra.

---

## 2. Comparison table

Costs assume the MVP workload only (no Playwright/browser automation) and 5-50 requests/day.
"Wakes instantly" = sub-second to a few seconds from event to handler start.

| Option | Monthly cost (compute) | Free tier expires? | Trigger | Cold start | Exec time limit | Secrets | Persistent state | Isolation | Ops effort | Lock-in | Card required |
|---|---|---|---|---|---|---|---|---|---|---|---|
| **Cloudflare Workers (Free)** | $0 | Never (Always Free) | AgentMail webhook to `*.workers.dev`; Cron Trigger for polling backup | None (V8 isolate) | 10ms CPU/invocation (I/O wait free); paid plan raises to 30s CPU | Workers Secrets / Secrets Store | Durable Objects (SQLite-backed on free), KV, D1, R2 — all have free tiers | Strong: no server, V8 sandbox, zero open ports | Low | Medium (Workers-specific APIs, though mostly standard `fetch`) | No |
| **Deno Deploy (Free)** | $0 | Never stated | Webhook to Deno Deploy URL | None (edge, always warm) | 50ms CPU/request | Env vars (project-level) | 1 GiB KV included | Strong: managed edge runtime | Low | Low-medium (mostly standard JS/TS + Deno KV) | No |
| **GCP Cloud Run (Always Free)** | $0 at this volume (2M req, 180K vCPU-s, 360K GB-s/mo free) | Never (Always Free, not trial) | Webhook (Cloud Run URL) | ~0.3-2s if scaled to zero (min-instances=0); can set min-instances=1 to avoid it but that costs money | 60 min max request (way over-provisioned for this) | Secret Manager (6 active versions + 10K accesses/mo free) | Cloud SQL/Firestore external | Container-level; scoped IAM service account | Low-medium (Docker/Cloud Build) | Low (standard containers) | No |
| **AWS Lambda + EventBridge/API Gateway** | $0 at this volume (1M req + 400K GB-s Lambda free forever; EventBridge Scheduler 14M invocations/mo free forever) | Always-Free tier is permanent for **all** accounts, old and new, post-2025 change | Webhook via Function URL or API Gateway; EventBridge Scheduler for polling | ~100ms-1s (more with a bundled container image) | 15 min max | AWS Secrets Manager (no perpetual free tier — $0.40/secret/mo — or free SSM Parameter Store as a cheaper substitute) | DynamoDB free tier (25GB, 25 WCU/RCU) | IAM-scoped role per function; no open ports if Function URL uses IAM auth | Medium (IAM policies, packaging) | Medium (AWS-specific) | No (card is on file for the account generally, but Always-Free usage itself isn't billed) |
| **Google Apps Script** | $0 | Never (part of consumer Google account) | `doPost` web app (polling recommended instead — see header limitation) | None (Google-managed) | 6 min/execution; 90 min total trigger-runtime/day (consumer); 20,000 UrlFetch calls/day (consumer) | `PropertiesService` (Script/User properties — **not a real secrets vault**, visible to any editor of the script) | Apps Script itself has no DB; write to Sheets/Drive directly (this **is** the "own Google account" story) | **Weak**: runs with your account's own broad implicit scopes granted to the script; **cannot verify AgentMail's webhook signature (no header access)**; no process isolation from your personal Google account at all | Very low to start, but security review is manual | High (Apps Script-specific runtime, quotas, deployment model) | No |
| **Oracle Cloud Always Free (Ampere A1)** | $0 | "Always Free" branding but **not immune to policy changes** — halved June 2026, over-limit legacy instances face termination from Aug 18 2026 | Self-hosted webhook receiver or IMAP/poll | None (real VM) | None (real VM) | Bring your own (SOPS/age, Vault, etc.) | Full local disk / attach a DB | Best of any option here *if you configure it* (Cloudflare Tunnel, no open ports) — but you own all OS patching | Medium-high (you're the sysadmin) | Low (portable Linux VM) | No, but Oracle's own idle-reclamation and 2026 policy churn are real risks |
| **GCP `e2-micro` Always Free VM** | $0 | Always Free (perpetual, but only 1 instance, only 3 US regions) | Self-hosted webhook receiver or poll | None (real VM) | None | Secret Manager or local | Full local disk + optional Firestore free tier | Strong if behind Cloudflare Tunnel; you patch the OS | Medium | Low | No |
| **Amazon Bedrock AgentCore** | Consumption-based, **no free tier of its own**; Runtime $0.0895/vCPU-hr + $0.00945/GB-hr (idle CPU not billed, but session/memory/gateway add up); realistically low but not $0 | New-account $200 AWS credit expires in 6 months (2025+ policy) | Not a native listener — something else (Lambda/EventBridge) must invoke it | Session cold start | Session-based, configurable | **AgentCore Identity Token Vault — explicitly documented to hold Google OAuth tokens** (Gmail/Calendar example in AWS docs) | AgentCore Memory (billed per event/retrieval) | Strong identity/isolation model, but adds AWS's entire IAM surface for one user | High (12 billable sub-components, new/immature docs) | High (AWS + AgentCore-specific abstractions) | No, but non-zero recurring cost even idle |
| **Vertex AI Agent Engine / Gemini Enterprise Agent Platform** | Runtime $0.0864/vCPU-hr + $0.0090/GB-hr + $0.25/1,000 session events; **not free** beyond Express Mode trial | Vertex AI Express Mode: free, but capped at 10 agent engines and **90 days**, no billing enabled (prototyping only); $300 general GCP credit, also expires | Needs an external trigger (Cloud Run/Functions/Scheduler) to wake per email; not itself an always-listening mail server | ~0.4s warm / ~4.7s cold at min-instances=0 in one benchmark | Configurable | Standard GCP: Secret Manager | Session/Memory store (billed) | Managed container isolation, GCP IAM | Medium-high | Medium-high (GCP + ADK-specific) | No |
| **GitHub Actions (scheduled)** | $0 (2,000 private-repo min/mo free) | Never for the free allotment itself | `schedule:` cron (poll AgentMail) | N/A (poll-based) | Job-level (default 6h, way over-provisioned) | GitHub Actions Secrets (adequate for CI, **not designed as a live credential vault for a running service**) | None (stateless; would need external store) | Weak as primary transport: **5-minute minimum interval, documented 15+ min real-world delays**, public-repo schedules disabled after 60 days inactivity | Low | Low | No |
| **Render (Free web service)** | $0, 750 instance-hours/mo | Never advertised as expiring | Webhook (spins down after 15 min idle, ~1 min cold start on next request — it *does* still wake on the incoming webhook, just slowly) | ~1 min | N/A | Env vars / Render secrets | Free Postgres **expires after 30 days** | Container-level | Low | Low (standard Docker/Python) | Not stated explicitly for free tier |
| **Koyeb (Free)** | $0 | Not stated to expire | Webhook (scales to zero after 1h idle) | Several seconds | N/A | Env vars | Limited (2GB SSD) | Container-level | Low | Low | Check at signup |
| **Fly.io** | No real free tier since 2026 (2-hour trial only) | N/A | — | — | — | — | — | — | — | — | Yes |
| **Railway** | Free credit ≈ a few hours/mo runtime only — **not viable for always-on** | N/A | — | — | — | — | — | — | — | — | Not for free credit |
| **Home Mac / Raspberry Pi + Cloudflare Tunnel** | $0 (+ electricity) | N/A | Webhook via Tunnel, or poll | None if machine is on | None | Local secrets manager / age | Full local disk | **Zero open inbound ports** via Tunnel, but the credential-holding process shares a machine with your everyday computer (Mac) or a fragile home SBC (Pi) — physical/OS/network blast radius is real | Medium (you are the sysadmin; laptop sleep/reboots are a real availability risk for "always on") | Low | No |

Sources for this table are cited inline above and consolidated at the end.

---

## 3. Per-option notes

### Amazon Bedrock AgentCore
Runtime, Gateway, Identity, Memory, and Observability are independently billed
([AWS pricing breakdowns](https://cloudburn.io/blog/amazon-bedrock-agentcore-pricing),
[factualminds](https://www.factualminds.com/blog/amazon-bedrock-agentcore-pricing-12-components/)).
The one genuinely compelling piece for this project is **AgentCore Identity's token vault**,
which AWS's own docs walk through explicitly for **Google Drive/Gmail/Calendar OAuth**: it
generates the consent URL, exchanges the code, and stores the resulting Google access token in
the vault keyed by agent+user identity
([AWS docs — Integrate with Google Drive using OAuth2](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/identity-getting-started-google.html)).
That's a real, purpose-built alternative to hand-rolling refresh-token storage in Secrets
Manager/SOPS. But AgentCore Runtime is **not** an always-on listener by itself — it's a managed
sandboxed execution environment invoked per-session; you'd still need Lambda + EventBridge (or
similar) in front of it to react to an inbound AgentMail webhook, which reintroduces the "who's
the listener" question this whole report is about. For a single user at this volume, the value
(a purpose-built OAuth vault) doesn't clearly outweigh the cost (a new, immature, 12-component
billing surface, no perpetual free tier, and AWS's full IAM blast radius). **Verdict: watch, don't
build on, for the MVP.**

### Vertex AI Agent Engine / Gemini Enterprise Agent Platform
Rebranded from Vertex AI Agent Builder at Google Cloud Next 2026
([UI Bakery](https://uibakery.io/blog/vertex-ai-agent-builder),
[Google Cloud product page](https://cloud.google.com/products/gemini-enterprise-agent-platform)).
Claude (Sonnet 5, Opus 5) is available through Vertex AI's Model Garden with global/multi-region/
regional endpoint choices
([Google Cloud blog — multi-region Claude endpoints](https://cloud.google.com/blog/products/ai-machine-learning/multi-region-endpoints-for-claude-available-on-vertex-ai)),
so "Claude via Vertex" is real, not hypothetical. The "same cloud as the data" argument is weaker
than it sounds here, though: Gmail/Calendar/Drive/Contacts are called over the public Google
Workspace APIs regardless of where your compute runs (there's no private-networking shortcut for
a personal @gmail.com account), so co-locating in GCP buys you marginally lower latency, not a
different security posture or materially lower egress cost. **Express Mode** is free but capped
at 10 agent engines and 90 days with no billing enabled — a prototyping sandbox, not a home for a
years-long personal assistant. Outside that, Agent Engine Runtime is billed per vCPU-hour/
GB-hour plus per-1,000 session events, with real cold-start latency when scaled to zero
([oneuptime.com](https://oneuptime.com/blog/post/2026-02-17-how-to-enable-scale-to-zero-for-vertex-ai-prediction-endpoints-to-reduce-costs/view),
[futureagi.com](https://futureagi.com/blog/evaluating-vertex-ai-agent-engine-2026/)). **Verdict:**
reasonable if you're already deep in GCP/ADK, but not free, and not simpler than Cloud Run for
this workload.

### Google Apps Script
The one option that removes an entire category of risk from the README's own decided
architecture: because Apps Script runs as *you*, using the built-in `GmailApp`/`CalendarApp`/
`DriveApp`/`ContactsApp` services, there is **no separate OAuth client to leave in "Testing" mode
and no 7-day refresh-token expiry trap** — that whole failure mode (README §7, "Google is easy,
with one trap") disappears. Quotas are workable: 20,000 `UrlFetchApp` calls/day and 90 minutes of
total trigger runtime/day on a consumer account (6 hours/100,000 calls on Workspace)
([developers.google.com/apps-script/guides/services/quotas](https://developers.google.com/apps-script/guides/services/quotas)),
comfortably enough for 5-50 requests/day even with a polling-every-1-minute trigger. `Utilities.
computeHmacSha256Signature` exists and could verify a *body-embedded* shared secret. But the
project's threat model (report 03) leans on **AgentMail's own Svix-signed webhook headers** as an
authentication layer, and **Apps Script's `doPost(e)` cannot read arbitrary HTTP headers** —
Google's engineering team formally declined to add this
([Google Groups thread](https://groups.google.com/g/google-apps-script-community/c/bgnzoAUV_No)),
so `svix-id`/`svix-timestamp`/`svix-signature` are invisible to the script. Two workarounds: (a)
poll instead of using webhooks (loses the header problem entirely, at the cost of latency, and is
explicitly supported by AgentMail), or (b) put a thin verifier in front (e.g., a $0 Cloudflare
Worker that checks the Svix signature and forwards only a verified, re-signed payload to the
Apps Script web app) — which reintroduces a second host and partly defeats the "just use Apps
Script" simplicity. Secrets live in `PropertiesService`, readable by anyone with edit access to
the script project — fine for a true single-editor personal project, but not a real secrets
vault, and there's zero process isolation between "the LLM's untrusted output" and "the code
holding your Google session," because it's all one script project running under your own account
session. **Verdict:** compelling for the OAuth simplification alone; use the *polling* pattern,
not `doPost`, if you go this route, precisely because of the header gap.

### Oracle Cloud Always Free (Ampere A1)
Still the most raw-compute-for-$0 offer from any major cloud (2 OCPU / 12 GB RAM as of the June
2026 halving, down from 4/24)
([InfoQ](https://www.infoq.com/news/2026/07/oracle-cloud-free-tier-limits/)). Two real risks for
this project specifically: (1) **idle reclamation** — Oracle can stop compute instances it judges
idle (originally <10%, more recent docs cite <20% CPU/network/memory over 7 days); a mailbox
that gets 5-50 requests/day and otherwise sits idle is a textbook match for that heuristic, so
you may need synthetic keep-alive traffic, which is an awkward thing to have to build for a
security-sensitive credential holder; (2) **policy churn** — the June 2026 silent halving and the
August 2026 termination notices for over-limit legacy instances show Oracle's Always Free
program is not a stable target to build long-term infrastructure on, even though it's genuinely
free today. **Verdict:** fine as a *secondary/backup* box, risky as the sole home for the
credential-holding process.

### GCP `e2-micro`, Cloud Run + Cloud Scheduler, Cloud Functions
The most boring and most durable free options among the "real compute" category. `e2-micro` is
explicitly called out by Google as Always Free (not a trial), limited to one instance in
`us-west1`/`us-central1`/`us-east1`, 30 GB persistent disk, 1 GB egress/month
([docs.cloud.google.com/free](https://docs.cloud.google.com/free/docs/free-cloud-features)).
Cloud Run's free tier (2M requests, 360,000 GB-seconds, 180,000 vCPU-seconds/month) comfortably
covers 5-50 requests/day forever, and Cloud Run is a normal HTTP container — AgentMail's webhook
can hit it directly, with cold start in the low single-digit seconds if scaled to zero (set
`min-instances=0`; setting it to 1 to remove cold start entirely costs a small ongoing fee).
**Cloud Scheduler is not in the Always Free list** — it's 3 free jobs per *billing account*
(not per project), then $0.10/job/month, which is trivial at this scale but not literally $0 if
you already use your 3 free jobs elsewhere. Cloud Functions matches Cloud Run's free allotment
(2M invocations, 400,000 GB-seconds). **Verdict:** strong, boring, reliable — a good "graduate
here from Workers" option if you outgrow the edge-isolate model or want real container/Python
runtime parity with local dev.

### Cloudflare Workers Free
Every Worker gets a public HTTPS URL on `*.workers.dev` at zero cost — that alone satisfies
AgentMail's "needs a public HTTPS endpoint" webhook requirement without provisioning anything.
100,000 requests/day, 10ms of *CPU* time per invocation (time spent awaiting the AgentMail/
Anthropic API responses over the network does **not** count against this, only actual JS
execution does), Cron Triggers supported down to 1-minute granularity (max 5 triggers/account on
Free, useful as a polling safety net alongside the webhook), Durable Objects available on Free
with the SQLite storage backend for per-thread state
([developers.cloudflare.com/workers/platform/pricing](https://developers.cloudflare.com/workers/platform/pricing/),
[.../platform/limits](https://developers.cloudflare.com/workers/platform/limits/)). No cold
start in the traditional sense (V8 isolates, not containers). Note report 05 already recommended
Cloudflare for the email-ingestion/orchestration layer even in the VPS-hybrid design — this
report's finding (no LinkedIn in MVP) removes the reason to hybridize at all; Workers alone can
plausibly be the *whole* MVP host. Python isn't natively supported on Workers (Python Workers
exist but are still maturing / more restricted than JS); if Python is a hard requirement, this
becomes the one place TypeScript is the more natural fit despite the stated Python preference —
worth flagging as a real trade-off, not glossing over it.

### Cloudflare D1 / R2 / KV (as app storage, not the "log to Drive" question below)
D1 free: 5M rows read/day, 100K rows written/day, 5GB storage, with **daily-limit enforcement
now actually live** as of a September 2026 changelog entry (previously soft/unenforced)
([Cloudflare changelog](https://developers.cloudflare.com/changelog/post/2026-09-01-d1-free-tier-limit-enforcement/)).
R2 free: 10GB storage, 1M Class A (write) ops/mo, 10M Class B (read) ops/mo, **zero egress fees**
— genuinely useful for a WORM-style audit log bucket, as report 05 already recommended. KV free:
100K reads/day, 1,000 each of writes/lists/deletes/day, 1GB total storage. All comfortably cover
5-50 requests/day for the lifetime of this project.

### AWS Lambda + EventBridge Scheduler
AWS's July 2025 change replaced the *12-months-free* trial for **brand-new accounts** with a
6-month, $200-credit model, but **the Always Free tier itself (1M Lambda requests + 400,000
GB-seconds/month, EventBridge Scheduler's 14M invocations/month) is unaffected and permanent for
all accounts**, old and new
([AWS announcement, July 2025](https://aws.amazon.com/about-aws/whats-new/2025/07/aws-free-tier-credits-month-free-plan/),
[InfraTally summary](https://infratally.com/articles/aws-free-tier-2026.html)). At 5-50
requests/day this is comfortably inside the permanent free allotment forever — the caveat is
operational complexity (IAM roles, Function URLs vs. API Gateway, packaging Python dependencies),
not cost. Secrets Manager itself is **not** in the Always Free list ($0.40/secret/month); use SSM
Parameter Store's free tier (standard parameters) instead if avoiding even that small charge
matters.

### GitHub Actions (scheduled workflows)
Confirmed: **5-minute minimum cron interval**, and GitHub does not guarantee on-time execution —
delays of 15+ minutes under platform load are documented, and schedules on *public* repos are
silently disabled after 60 days of inactivity (private repos aren't documented to have this
specific behavior)
([community discussion](https://github.com/orgs/community/discussions/156282),
[cronuru.com guide](https://cronuru.com/guides/github-actions-scheduled-workflows)). 2,000 free
Linux minutes/month on private repos is far more than a poll-every-few-minutes job needs, but the
delay/reliability profile makes it a poor **primary** transport for a system whose whole value
proposition is a trustworthy audit trail with predictable behavior. It's a reasonable **secondary**
poll-based safety net (e.g., "if no reply went out within 10 minutes, alert me") or the natural
home for the weekly promptfoo/AgentDojo injection-test suite report 03 already planned — not the
main event loop.

### Free app hosts survey
- **Render free**: 750 instance-hours/mo, web service spins down after 15 min idle, ~1 min cold
  start on the next request (it does still wake on an incoming webhook, just slowly — usable, not
  ideal, at 5-50 req/day round trips). Background workers/cron are **not available on the free
  tier at all**
  ([render.com/docs/free](https://render.com/docs/free)). Free Postgres expires after 30 days.
- **Koyeb free**: scales to zero after 1 hour idle, 512MB RAM/0.1 vCPU, cold start of several
  seconds on wake ([srvrlss.io](https://www.srvrlss.io/provider/koyeb/)).
- **Fly.io**: no meaningful free tier remains in 2026 — reduced to a 2-hour trial for new
  accounts, credit card required.
- **Railway**: free credit is small enough (roughly $1/mo-equivalent, a few hours of runtime) that
  it does not cover an always-on process at all.
- **Deno Deploy free**: 1M requests/mo, 100GB egress, 50ms CPU/request, no credit card, **no
  stated expiry**, commercial use explicitly allowed, edge-deployed (always warm, same model as
  Workers) — genuinely the closest thing to "Cloudflare Workers but Deno/TS-flavored" among the
  PaaS options, and a credible alternative if Workers' Python limitations are a blocker
  ([docs.deno.com/deploy/usage](https://docs.deno.com/deploy/usage/)).
- **Supabase Edge Functions free**: 500,000 invocations/mo bundled with the wider Supabase free
  plan (500MB DB, 1GB storage) — usable, but you'd be adopting a full BaaS stack for what this
  project needs only the function-hosting slice of.
- **Pipedream free**: 100 credits/mo, 3 active workflows, HTTP/webhook triggers built in — fine
  for prototyping the AgentMail→Claude→reply flow visually, but the workflow-count and credit
  ceiling make it a poor long-term home for a security-sensitive always-on process (and its
  low-code workflow builder is the wrong shape for "deterministic code in the privileged path,"
  the design principle in the README).
- **Vercel cron**: bundled with Vercel's Hobby plan but the **Hobby plan explicitly bans
  commercial use**, which is a fuzzy fit for "runs your personal AI stack" but should be
  double-checked against Vercel's ToS before relying on it for anything beyond a toy.

### Home machine (Mac or Raspberry Pi) + Cloudflare Tunnel
Free, and Cloudflare Tunnel gives the same "zero open inbound ports" property report 05 already
recommended for the VPS design. The honest trade-offs: a Mac that sleeps, reboots for OS updates,
or gets closed in a bag is not "always on" in the way a managed platform is, and running a
credential-holding, internet-facing process on your **daily-driver laptop** mixes the blast radius
of "gatekeeper gets compromised" with "your personal machine gets compromised" — a meaningfully
worse isolation story than any of the managed options above. A dedicated Raspberry Pi avoids the
daily-driver problem but reintroduces "you are the sysadmin for an always-on device with no
power/network redundancy," which is the same trade-off report 05 flagged for this exact option.
**Verdict:** fine for a prototype/spike, not recommended as the long-term home given equally-free
managed alternatives exist.

---

## 4. Storage sub-question: log to the user's own Google Drive/Sheets?

**Scope needed:** `drive.readonly` (already in the MVP scope for reading files) cannot write.
Writing requires an additional scope. **`drive.file`** is confirmed sufficient and is the right
choice: it is a Google-classified **non-sensitive** scope (no OAuth verification review required,
consistent with the README's "unverified, single-user app needs no Google review" decision), and
it explicitly works for the Sheets API too — `spreadsheets.create` accepts `drive.file`
([Google's Sheets API scopes docs](https://developers.google.com/workspace/sheets/api/scopes),
[Choose Google Drive API scopes](https://developers.google.com/workspace/drive/api/guides/api-specific-auth)).
The catch that matters here: `drive.file` only grants access to files **the app itself created**
(or that the user explicitly picked via the Google Picker UI). That's actually a good fit for an
append-only audit log: have the gatekeeper **create its own log spreadsheet/file on first run**
(covered by `drive.file` from that point on) rather than trying to get standing access to a
pre-existing file — no picker UI, no extra scope, no verification requirement.

**Tamper-evidence weakness (the user's own concern, confirmed real):** if the gatekeeper's own
credential can write the log, a compromised gatekeeper process can edit or delete its own audit
trail — logging to Drive with `drive.file` does not change this; the same credential that appends
new rows can also overwrite or delete old ones (Sheets/Drive APIs don't offer an app-enforced
"append-only, no history rewrite" mode by scope alone; Drive does keep a native version history
for Sheets which provides *some* forensic recovery, but a sufficiently capable attacker who
controls the API credential can also purge revisions via the Drive API). Mitigations, in
increasing order of strength:
1. **Hash-chain each log entry** (each row's hash includes the previous row's hash, per report
   05's existing recommendation) — doesn't stop deletion, but makes any row tampering or
   reordering detectable on inspection.
2. **Mirror the chain to a second place the gatekeeper cannot write to after the fact** — e.g.,
   append-only to Cloudflare R2 with a Bucket Lock (report 05's existing recommendation,
   tamper-evident but not SEC 17a-4 certified), or simply BCC every reply to yourself (the
   email thread itself, sitting in *your* inbox rather than the gatekeeper's writable store, is
   already a second, harder-to-tamper copy — this is already the project's core design).
3. The email thread (already the primary audit log per the README) is arguably **already** the
   "second place" that solves this: the gatekeeper can write to its own Drive log all it wants,
   but it would need to also compromise your personal inbox to erase the BCC'd copies there.

**Comparison to the alternatives the user asked about:**

| | Cost | Data locality | Tamper-evidence | API quota risk |
|---|---|---|---|---|
| **Google Drive/Sheets (`drive.file`)** | Free | Stays in the user's own Google account — the strongest "data sovereignty" answer of any option here | Weak alone (see above); strong when paired with the email-BCC copy that already exists | Sheets API: 300 req/min/project, 60/min/user — far above 5-50/day ([developers.google.com/workspace/sheets/api/limits](https://developers.google.com/workspace/sheets/api/limits)) |
| **Firestore free tier** | Free (1 GiB storage, 50K reads/20K writes/20K deletes per day) | GCP, not Google Workspace — a separate account/project, not "in the user's Drive" | Same weakness as Drive (whoever holds the write credential can rewrite) unless paired with a second sink | Comfortably covers this workload forever |
| **Cloudflare D1/R2** | Free | Cloudflare, not Google | R2 + Bucket Lock is the strongest single-sink option on this list (WORM-style, not deletable within the lock window) | Comfortably covers this workload |
| **SQLite on a VM** | Free (with the VM) | Wherever the VM is | Weakest — a local file an attacker with shell access can edit directly, unless snapshotted/shipped off-box | N/A |
| **Turso free tier** | Free (100 DBs, 5GB storage, 500M rows read/10M rows written per month) | Turso's cloud (libSQL/SQLite-compatible) | Same weakness as Firestore/D1 unless mirrored | Comfortably covers this workload |

**Recommendation:** Google Sheets/Drive via `drive.file` for the human-readable, easy-to-browse
log (this directly serves the "easy for the user to read" goal), **plus** the hash chain from
report 05, **plus** relying on the BCC'd email thread as the actual tamper-resistant copy — don't
introduce a second paid/managed database (Firestore/D1/Turso) purely for tamper-evidence when the
project's own design already produces a second, harder-to-reach copy for free.

---

## 5. Cost estimate at 20 requests/day (including LLM tokens)

Verified model pricing ([claude.com/pricing](https://claude.com/pricing), confirmed by the
project's own README verification pass): **Haiku 4.5 $1/$5 per MTok** (input/output),
**Sonnet 5 $2/$10 per MTok**.

Token sizing is **not yet verified** (no code exists yet — this is an estimate, not a measured
number) — assumed ~3,000 input tokens (system prompt + email body + any Gmail/Calendar API
results pulled into context) and ~800 output tokens (structured schema response) per request,
blended 90% Haiku-only triage / 10% escalated to Sonnet for ambiguous cases, no prompt caching:

- Haiku request: (3,000/1e6 × $1) + (800/1e6 × $5) ≈ **$0.007**
- Sonnet request: (3,000/1e6 × $2) + (800/1e6 × $10) ≈ **$0.014**
- Blended: 0.9 × $0.007 + 0.1 × $0.014 ≈ **$0.0077/request**
- At 20 requests/day × 30 days = 600 requests/month → **≈ $4.60/month in tokens**
  (prompt caching on the stable system/policy prompt, as report 05 recommends, would cut this
  further)

This is *lower* than report 05's blended $0.015/request estimate, most likely because that
estimate folded in occasional Opus escalations and multi-turn tool loops that a pure MVP (no
LinkedIn, simpler verb set) may not need yet — treat both as rough, unverified planning numbers
until real usage data exists.

**Total monthly estimate at 20 req/day:**

| Component | Cost |
|---|---|
| LLM tokens (Haiku/Sonnet blend, estimated) | ~$4.60 |
| AgentMail | $0 (well under the 100/day free cap at 20 req/day ≈ 40 messages/day) |
| Hosting (Cloudflare Workers Free, or Cloud Run/Lambda free tier) | $0 |
| Storage (Drive/Sheets, or R2/Firestore free tier) | $0 |
| Secrets (Workers Secrets, or GCP Secret Manager free tier) | $0 |
| **Total** | **≈ $5/month**, comfortably under the project's <$5/mo hosting target (excluding LLM, which is itself only ~$4.60/mo at this volume) |

At the upper end of the stated range (50 req/day ≈ 100 messages/day), AgentMail's free cap is
hit exactly — budget an extra **$20/mo** for the AgentMail Developer tier at that point, which
would still keep the whole system (hosting $0 + AgentMail $20 + LLM ~$11.50 at 50 req/day) under
**~$35/month**, well inside "small."

---

## 6. Top-3 recommendation for this project

1. **Cloudflare Workers (Free) + AgentMail webhook + Cloudflare R2 (Bucket Lock) for the
   tamper-evident log copy + Google Sheets (`drive.file`) for the human-readable log.**
   Rationale: the only option that gets a public HTTPS webhook endpoint, instant wake-on-event,
   durable per-thread state (Durable Objects), secrets storage, and an R2 audit-log sink all at
   **genuine $0/month**, with no cold start and no idle-reclamation risk (unlike Oracle) and no
   spin-down risk (unlike Render/Koyeb). Main cost: Python isn't the native fit (TypeScript is);
   the README says Python is *preferred*, not required, and TS is explicitly called "OK."
2. **GCP Cloud Run (Always Free) + Cloud Scheduler (or a Worker doing the poll) + Secret Manager
   free tier + Firestore or Drive for logging.**
   Rationale: if Python is a hard requirement, this is the next-best $0 option — a real
   container, near-zero cold start at this request volume, Google's own Secret Manager free tier
   (6 versions/10K accesses, plenty for a handful of long-lived refresh tokens), and it sits in
   the same cloud family as the Google APIs being called (marginal latency benefit, per the
   "same cloud as the data" question — real but small for a personal account). Slightly more ops
   than Workers (Docker/Cloud Build), but still low.
3. **Google Apps Script, polling AgentMail (not `doPost`), for a first spike only.**
   Rationale: fastest possible path to "does this even work end-to-end," and the only option
   that eliminates the OAuth-client/7-day-token-expiry failure mode entirely by running as your
   own account. Not recommended as the long-term home given the header-verification gap and
   `PropertiesService`'s weak secrets story — but genuinely excellent for the README's own
   "Suggested next phase 1: feasibility spike (no code)... send a hand-written structured request
   email to a test inbox" before investing in a real deployment.

**Start-free-on-X, move-to-Y-if-Z path:**
Start on **Apps Script polling** for the feasibility spike (near-zero setup, proves the
Instinct-cooperation and protocol-format questions from the README's blocking decisions #1 and
#4). Once the spike confirms the design, **move to Cloudflare Workers** for the real build (gets
you the webhook path, proper secrets, Durable Object state, and R2 audit logging) — **move again
to GCP Cloud Run only if** you outgrow Workers' Python limitations, need a real Playwright-capable
container later (i.e., LinkedIn gets un-parked), or want tighter integration with GCP-native
Secret Manager/IAM for other reasons.

---

## 7. Security notes per option (summary)

- **Cloudflare Workers**: strongest default isolation of the free options (V8 sandbox, no open
  ports, managed runtime); the meaningful risk is Workers-specific API surface (less battle-tested
  than a plain Python stdlib for security review) and, if Python is used via Python Workers, that
  subsystem is newer and less proven.
- **GCP Cloud Run/Lambda**: standard container/function isolation with mature, well-understood
  IAM models; risk is entirely in how carefully you scope the service account/IAM role — both
  clouds make it easy to over-grant by accident.
- **Google Apps Script**: **weakest isolation of any option evaluated** — the gatekeeper logic,
  your live Google session's implicit grants, and your secrets (`PropertiesService`) all live in
  one script project with no process boundary; anyone who can edit the script can read the
  secrets; the LLM's untrusted output and the privileged code are not meaningfully separated by
  the platform, so all separation has to come from your own code discipline. It's also the one
  option that **cannot verify AgentMail's webhook signature** if used with `doPost`.
- **Oracle/GCP/home VM**: only as secure as your own hardening (behind a Cloudflare Tunnel with
  zero open ports is the right baseline, per report 05); you own OS patching and secrets
  management end to end.
- **Bedrock AgentCore / Vertex AI Agent Engine**: both have mature, purpose-built identity/token
  vault stories (AgentCore Identity explicitly for Google OAuth) that are arguably *more*
  security-engineered than anything you'd hand-roll — but both also mean a second cloud vendor
  holding a piece of your credential lifecycle, and both add substantial platform surface (IAM,
  Gateway, Memory) for a single user, which cuts against the README's "smallest attack surface"
  design principle.
- **Home machine**: the Mac option specifically mixes your daily-driver device's blast radius
  with the gatekeeper's — a strictly worse isolation story than any managed option that costs
  the same ($0).

---

## 8. Open questions for the user

1. **Python vs. TypeScript for the actual build.** Cloudflare Workers (the top recommendation) is
   most natural in TypeScript; is that an acceptable trade against the stated Python preference,
   or does GCP Cloud Run (Python-native, still $0) become the default instead?
2. **AgentMail free tier's 100/day cap** — is 5-50 requests/day a hard ceiling, or should the
   design budget from day one for the $20/mo Developer tier once volume grows? (Also: does a BCC
   copy count as a separate "email" against the daily cap? Not found in AgentMail's docs —
   worth confirming directly with AgentMail before committing to the free tier long-term.)
3. **Is Apps Script's `doPost` header limitation acceptable** if Apps Script is used past the
   spike stage (i.e., accept webhook payloads without cryptographic origin verification, relying
   instead on the existing sender-allowlist/DKIM/request-ID layers from report 03), or does that
   rule out `doPost`-based Apps Script entirely in favor of polling-only?
4. **Is the "same cloud as the data" argument for GCP/Vertex worth anything concrete here**, given
   Gmail/Calendar/Drive/Contacts API calls go over the public internet regardless of where compute
   runs for a personal (non-Workspace) account? If not, this removes one of the stated reasons to
   consider Vertex AI Agent Engine at all.
5. **Is R2 + a Bucket Lock, mirrored against the BCC'd email thread, a strong enough
   tamper-evidence story**, or does the user want a true WORM store (S3 Object Lock in compliance
   mode, which report 05 already flagged as the stronger-but-AWS-specific alternative) despite the
   added vendor?

---

## Sources

- [AgentMail — Pricing](https://www.agentmail.to/pricing)
- [AgentMail — Webhooks Overview](https://docs.agentmail.to/overview)
- [AgentMail — Example: Event-Driven Agent](https://docs.agentmail.to/webhook-agent)
- [AgentMail — Verifying Webhooks](https://docs.agentmail.to/webhook-verification)
- [AgentMail — List Messages API](https://docs.agentmail.to/api-reference/inboxes/messages/list)
- [Amazon Bedrock AgentCore Pricing breakdown — CloudBurn](https://cloudburn.io/blog/amazon-bedrock-agentcore-pricing)
- [AWS docs — Integrate with Google Drive using OAuth2 (AgentCore Identity)](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/identity-getting-started-google.html)
- [AWS Bedrock AgentCore Pricing and Alternatives — BetterClaw](https://www.betterclaw.io/blog/aws-bedrock-agentcore-pricing-alternatives)
- [Google Cloud — Gemini Enterprise Agent Platform product page](https://cloud.google.com/products/gemini-enterprise-agent-platform)
- [Google Cloud blog — Multi-region endpoints for Claude on Vertex AI](https://cloud.google.com/blog/products/ai-machine-learning/multi-region-endpoints-for-claude-available-on-vertex-ai)
- [Vertex AI Agent Engine — scale-to-zero / cold start benchmark discussion](https://futureagi.com/blog/evaluating-vertex-ai-agent-engine-2026/)
- [Google Apps Script — Quotas for Google Services](https://developers.google.com/apps-script/guides/services/quotas)
- [Google Groups — HTTP headers will not be supported in doPost() requests](https://groups.google.com/g/google-apps-script-community/c/bgnzoAUV_No)
- [Google — Choose Google Drive API scopes (drive.file)](https://developers.google.com/workspace/drive/api/guides/api-specific-auth)
- [Google — Choose Google Sheets API scopes](https://developers.google.com/workspace/sheets/api/scopes)
- [Google Sheets API — Usage limits](https://developers.google.com/workspace/sheets/api/limits)
- [Oracle Cloud Free Tier FAQ](https://www.oracle.com/cloud/free/faq/)
- [InfoQ — Oracle quietly halves free tier Ampere A1 compute limits](https://www.infoq.com/news/2026/07/oracle-cloud-free-tier-limits/)
- [Google Cloud — Always Free tier features (docs.cloud.google.com)](https://docs.cloud.google.com/free/docs/free-cloud-features)
- [Google Cloud Secret Manager pricing](https://cloud.google.com/secret-manager/pricing)
- [Google Cloud Scheduler pricing](https://cloud.google.com/scheduler/pricing)
- [Cloudflare Workers — Pricing](https://developers.cloudflare.com/workers/platform/pricing/)
- [Cloudflare Workers — Limits](https://developers.cloudflare.com/workers/platform/limits/)
- [Cloudflare — D1 free tier limit enforcement changelog (Sept 2026)](https://developers.cloudflare.com/changelog/post/2026-09-01-d1-free-tier-limit-enforcement/)
- [AWS — Free Tier credits and 6-month free plan announcement (July 2025)](https://aws.amazon.com/about-aws/whats-new/2025/07/aws-free-tier-credits-month-free-plan/)
- [InfraTally — AWS Free Tier in 2026: What Changed](https://infratally.com/articles/aws-free-tier-2026.html)
- [GitHub Actions scheduled workflow delay discussion](https://github.com/orgs/community/discussions/156282)
- [Cronuru — GitHub Actions Scheduled Workflows guide](https://cronuru.com/guides/github-actions-scheduled-workflows)
- [Render — Free tier docs](https://render.com/docs/free)
- [Koyeb Free Tier — srvrlss.io](https://www.srvrlss.io/provider/koyeb/)
- [Deno Deploy — Usage Guidelines](https://docs.deno.com/deploy/usage/)
- [Claude API Pricing — claude.com/pricing](https://claude.com/pricing)
- [Report 05 — Deployment, Protocol, and Observability (this repo)](05-deployment-protocol-and-observability.md)
