# Deployment, Protocol & Observability for a Self-Hosted "Data Gatekeeper" Agent

Research date: 2026-09-14

## Executive summary

- **Why this matters now**: the consumer agent this project is meant to sit in front of, Instinct, is already generating exactly the failure modes a gatekeeper is designed to prevent — a user reported it "sent an email on her behalf without checking with me first," another found it kept summarizing her Gmail hours after she'd disconnected the account ("stored in plain text for later searches"), and a third demonstrated it could be phished into leaking a sign-up code straight out of the inbox ("unsafe to give AI read/write access to your inbox"). Its terms of service also grant Instinct's operator a broad, perpetual license to user data and let it "enter into agreements, commitments, or transactions" on the user's behalf. ([TechCrunch](https://techcrunch.com/2026/08/24/instincts-powerful-ai-assistant-is-raising-privacy-and-security-concerns/)) That is the concrete threat model for this whole project: credential exposure, unapproved actions, and silent data retention/exfiltration via prompt injection.
- **Hosting**: for a single-user, always-on gatekeeper that needs headless-browser support (Playwright for LinkedIn) plus inbound/outbound email, the two strongest options are (1) a small Hetzner/DigitalOcean VPS running Docker (full control, cheap, ~$5-12/mo, trivial Playwright support) reached only via a Cloudflare Tunnel (zero open inbound ports), or (2) Cloudflare Workers + Durable Objects (Agents SDK) + Email Service, which is nearly free at this scale and has genuinely excellent inbound-email-to-durable-state wiring, but its Playwright story (Browser Rendering/"Browser Run") is a metered, time-limited add-on, not a full persistent browser profile — workable for LinkedIn but more fragile than a real VPS with a persistent Chromium profile. A hybrid (Workers for email/orchestration + a small VPS or Modal sandbox for the Playwright leg) is a credible middle path. Render and Fly.io are reasonable single-service alternatives; Railway is pricier for always-on than it looks; AWS Lambda+SES and Cloud Run are overkill for one user; a home Mac mini/Raspberry Pi behind Cloudflare Tunnel is viable and free but adds home-network and power/uptime risk. Anthropic's Managed Agents (launched April 2026) is interesting but is compute+session-hour billed on top of token costs and is designed for sandboxed agent *execution*, not for being the credential-holding, always-listening mail server itself.
- **Protocol**: free-text email between two LLMs is fragile (ambiguous verbs, no machine-checkable success/failure, hard to audit). A **fenced YAML/JSON block inside a normal, human-readable email body** — with a small fixed verb vocabulary, a request ID, and RFC 5322 `Message-ID`/`In-Reply-To` threading — gets you both LLM-writability and audit readability. This report proposes and compares three concrete designs (free text, structured envelope, hybrid) and recommends the hybrid.
- **Human-in-the-loop**: keep the user BCC'd (not CC'd, to avoid Instinct treating the user as another correspondent) on every gatekeeper reply, and use a push channel (ntfy.sh self-hosted, or Pushover) for time-sensitive approvals with signed, single-use, expiring links — not Telegram bot callback data alone, which is forgeable if the bot token or chat ID leaks. A tiny read-only web dashboard is worth building early because email threads become unsearchable past ~50 requests.
- **Audit logging**: log every request as an appended, hash-chained record (each entry's hash includes the previous entry's hash) written to Cloudflare R2 with a bucket lock (retention/WORM-style, though not SEC 17a-4 certified) or S3 Object Lock; mirror traces into Langfuse (self-hosted, MIT-licensed, OTel GenAI-native) for the LLM-specific view (prompts, tool calls, token cost) and keep the R2/S3 hash-chained log as the legally/psychologically "tamper-evident" ground truth. The email thread itself remains the primary human-readable audit log per the project's own design goal.
- **Kill switch**: a single `systemctl stop` / `docker compose down` / Cloudflare Worker route-disable is necessary but not sufficient — pair it with a dead-man's-switch heartbeat (Healthchecks.io, free) that pages you if the gatekeeper goes silent *or* if it goes suspiciously loud (volume spike alert), and short-lived OAuth tokens so a compromised host self-expires within hours/days even if you're unreachable.
- **Cost**: at 20 requests/day the whole system (hosting + LLM) should land under $15-20/month; at 200/day, under $60-120/month if you route most requests through Haiku 4.5 and only escalate ambiguous/sensitive ones to Sonnet 5. Opus 5 should be reserved for rare, high-stakes judgment calls (e.g., "should I approve this LinkedIn connection request from a recruiter") given its 2.5x cost over Sonnet.
- **Latency**: realistic inbound+outbound email round-trip is **10 seconds to a few minutes** end-to-end (SMTP acceptance is usually seconds, but Gmail/inbox delivery and Instinct's own polling cadence add the rest) — acceptable for "send my LinkedIn connection notes" but noticeably worse than WhatsApp's near-instant feel for anything the user is actively waiting on. If Instinct polls its inbox on a fixed interval (e.g., every 1-5 minutes) rather than push (IMAP IDLE/Gmail push notifications), that polling interval — not email transport — will dominate perceived latency. Recommend keeping email as the audit trail but exposing a low-latency **webhook or MCP tool call** as the primary request path for anything the user is waiting on live, with the system auto-generating the matching email record for audit.

---

## 1. Hosting options

### Requirements recap
Always-on (or fast-resume), single user, must hold long-lived credentials (Gmail OAuth, LinkedIn session cookies) securely, must run a headless browser for LinkedIn automation via Playwright, needs inbound email (or webhook) triggering, persistent storage for session state/audit logs, minimal ops burden, cheap, easy to kill.

### Comparison table

| Option | Monthly cost (single user) | Always-on? | Playwright/headless browser | Persistent storage | Inbound email | Isolation / who can reach the box | Ops burden | Data residency |
|---|---|---|---|---|---|---|---|---|
| **Cloudflare Workers + Durable Objects (Agents SDK) + Email Service** | ~$5 (Workers Paid plan minimum; includes 10M req + Durable Objects) ([Cloudflare docs](https://developers.cloudflare.com/workers/platform/pricing/)) | Yes, DO instances wake on event/email | Only via **Browser Rendering / "Browser Run"**: free tier 10 min/day, Paid plan 10 browser-hours/mo then $0.09/hr, $2/extra concurrent browser ([Cloudflare docs](https://developers.cloudflare.com/browser-run/pricing/)); stateless-ish, not a persistent logged-in Chromium profile — workable but fiddly for LinkedIn session persistence | Durable Objects storage + R2 (no egress fees) | Native: `onEmail` hook on the Agent class, HMAC-signed reply routing, per-thread DO instance ([Cloudflare blog](https://blog.cloudflare.com/email-for-agents/)) | No inbound ports; Cloudflare's edge terminates everything; secrets in Workers Secrets/Secrets Store | Low — no server to patch, but you're inside a specific runtime (V8 isolates, no arbitrary Linux binaries) | Choose Cloudflare region/jurisdiction (EU/US) at account level; not full data-residency guarantees for all products |
| **Render (background worker / web service)** | $7/mo Starter always-on instance + $0.25/GB-mo disk ([Render pricing](https://render.com/pricing)) | Yes | Full Docker container → Playwright works normally (needs `--shm-size` tuning) | Persistent disk add-on | Needs your own inbound-email listener (e.g., forward via Cloudflare Email Routing → webhook → Render, or poll IMAP) | Render manages the VM; you get a container, not root on the host | Low-medium (managed platform, but you own the Dockerfile/Playwright deps) | Region selectable (Oregon, Frankfurt, Singapore, etc.) |
| **Fly.io** | ~$2-20/mo depending on size; a realistic 1 CPU/1GB + 10GB volume + IPv4 setup is ~$10-20/mo ([bex.co](https://bex.co/blog/2026/08/16/flyio-pure-usage-pricing-always-on-app-cost), [runxbuild](https://www.runxbuild.com/blog/fly-io-pricing/)) | Yes (or scale-to-zero) | Full container, Playwright works, same shm/memory caveats | Fly Volumes, billed even when machine stopped ($0.15/GB-mo) | Own listener needed, same as Render | You get a Firecracker microVM; no inbound ports needed if you use Fly's proxy only | Low-medium | Region selectable globally including Tel Aviv-adjacent (fra/waw for EU) |
| **Railway** | Hobby plan $5/mo base + usage (~$10/GB-mo RAM, ~$20/vCPU-mo); a modest always-on worker can land at **$15-25/mo** once RAM/CPU/egress are added ([saaspricepulse](https://www.saaspricepulse.com/tools/railway)) | Yes | Full container, Playwright supported (official guide exists) ([Railway docs](https://docs.railway.com/guides/playwright)) | Volumes | Own listener needed | Managed container | Low | Region choice more limited |
| **Hetzner / DigitalOcean VPS + Docker** | Hetzner CX22 (2 vCPU/4GB) ≈ €3.79-4.59/mo ([bestusavps](https://bestusavps.com/reviews/hetzner/)); DO Basic Droplet $4-6/mo (512MB-1GB) ([costbench](https://costbench.com/software/cloud-infrastructure/digitalocean/)) | Yes, full control | Full root access, Playwright + Chromium run natively, persistent logged-in profile trivial to keep on disk | Full disk, snapshot/backup yourself | Run your own SMTP receiver or (better) Cloudflare Email Routing → Worker → webhook to your VPS, or just IMAP-poll a mailbox | **Best isolation model for this project**: put it behind a **Cloudflare Tunnel with zero open inbound ports**, free, unmetered ([dev.to](https://dev.to/recca0120/cloudflare-tunnel-in-2026-expose-localhost-without-opening-ports-or-buying-an-ip-32l5)); only outbound connections leave the box | Medium — you patch the OS, manage Docker, rotate secrets yourself | You pick the exact datacenter (Hetzner has Nuremberg/Falkenstein/Helsinki EU, Ashburn US; DO has Frankfurt, Amsterdam, etc.) — best control of any option |
| **AWS Lambda + SES** | SES inbound $0.10/1000 emails; Lambda near-free at this volume (~$1-5/mo even at 100k emails/mo) ([leadsnipper](https://leadsnipper.com/blog/amazon-ses-pricing-2026), [campaignhq](https://blog.campaignhq.co/amazon-ses-pricing-2026/)) | Only while invoked — no persistent process, so a stateful Playwright session across steps is awkward | Needs a Lambda container image with bundled Chromium (works, but cold starts + 250MB image limits are a headache); no persistent logged-in profile between invocations unless you externalize session state to S3/EFS | S3 for artifacts; EFS for persistent Playwright profile (adds cost/complexity) | SES receiving → S3 → Lambda trigger, well-trodden path | IAM-scoped, no open ports; multi-service AWS surface increases blast radius if misconfigured | Medium-high — SES sandbox mode, domain verification, IAM policies, Lambda packaging | Full region choice (e.g., eu-central-1 Frankfurt), but AWS's overall surface area is the biggest attack surface of any option here for a single user |
| **Google Cloud Run (min-instances=1)** | ~$10-12/mo for one warm always-on instance at small size ([various](https://cloudcostkit.com/guides/gcp-cloud-run-pricing/)) | Yes with min-instances ≥1 | Full container, Playwright works | Cloud Storage / persistent volumes (Cloud Run direct volume mounts are limited) | Needs Pub/Sub + a mail-receiving front door (no native inbound email) | Managed container, no open ports needed if using Cloud Run's own ingress controls | Medium | Region selectable (europe-west3 Frankfurt, etc.) |
| **Home server / Mac mini / Raspberry Pi + Cloudflare Tunnel** | ~$0/mo hosting (just electricity + existing hardware) + free Tunnel | Yes, if the box stays on | Full native support, easiest Playwright/session persistence of any option | Local disk, full control, but *you* own backup/disaster recovery | Cloudflare Email Routing → Worker → Tunnel to home box, or direct IMAP poll | **Zero open inbound ports** via Tunnel; biggest risk is physical/network access to your home LAN and reliance on home ISP uptime | Higher — you are the sysadmin for power outages, ISP outages, OS updates, no redundancy | Fully under your control; email/audit data never leaves a jurisdiction you choose unless you send it there |
| **Anthropic Managed Agents** | Standard Claude token rates + **$0.08/session-hour** ([Medium/roborhythms summary](https://www.roborhythms.com/anthropic-managed-agents-2026/)) | Sessions are on-demand sandboxed containers with checkpoint/resume, not natively "always listening" for inbound email | Sandbox is a Linux container — you could install Playwright, but this product is designed around agent *task execution*, not as a persistent mail-server/credential-vault process | Persistent append-only session logs + a credentials vault that keeps secrets **outside** the sandbox — genuinely attractive for this project's threat model | No native email trigger; you'd still need Cloudflare Email Routing (or similar) to invoke a Managed Agents session per inbound email | Anthropic-managed sandbox + credentials vault — good isolation story, but your credentials now also depend on Anthropic's vault security, not just yours | Low if you accept the abstraction; but it's new (April 2026) and adds a second vendor dependency beyond the model API itself | Anthropic's own infra/region policies apply — check current data processing terms before storing Gmail/LinkedIn creds there |
| **Modal.com** | Pay-per-second compute; sandboxes billed at a premium non-preemptible tier (~$0.00003942/core-s + $0.00000672/GiB-s), no subscription floor on Starter ([usagepricing](https://www.usagepricing.com/blueprint/modal), [beam.cloud](https://www.beam.cloud/blog/modal-pricing-explained)) | Scale-to-zero by default; can pin a "keep warm" container for always-on at added cost | Sandboxes support arbitrary containers, so Playwright works; good fit for the *browser automation leg specifically*, less natural as the always-on mail listener | Modal Volumes | No native inbound email; would need a webhook front door | Sandboxed, no open ports if invoked via webhook | Low-medium; more "give it a container image" than "manage a VM" | Region control more limited than Hetzner/DO/AWS |

### Recommendation on hosting
Given the LinkedIn Playwright requirement (which wants a *persistent, logged-in browser profile*, not a stateless per-call browser) and the "easy to kill" requirement, a **small Hetzner or DigitalOcean VPS running Docker, reached exclusively through a Cloudflare Tunnel**, is the most boring, most controllable, cheapest-per-capability option — root access, no open ports, snapshot-based backup, ~$5-12/mo. Cloudflare Workers + Agents SDK + Email Service is worth strongly considering for the **email ingestion/orchestration layer** even in this design (it's free-tier-friendly and the `onEmail` + Durable Object threading is genuinely well-built for this exact "request/response over email with per-thread state" pattern), while delegating only the Playwright/LinkedIn leg to the VPS (or a Modal sandbox invoked from the Worker). That hybrid gets you Cloudflare's inbound-email handling and DDoS/edge protection for the "front door" while keeping a real, persistent browser profile for LinkedIn on infrastructure you fully control.

---

## 2. Request/response protocol over email

### Design constraints
- Instinct is an LLM writing the request email; it needs a format it can reliably produce without a strict SDK (it's a black-box consumer agent, not code you control).
- The gatekeeper needs a format it can reliably *parse* even when Instinct's output is slightly malformed, wrapped in extra prose, or (in the injection scenario) altered by hostile page content it summarized.
- The user needs to be able to read the thread and understand what happened without decoding a wire protocol.
- Must support: threading (correlate request/response/clarification), error replies, "I need more info," long-running async tasks (LinkedIn actions can take tens of seconds), size limits/attachments, rate limiting, and idempotency (Instinct might resend a request after a timeout).

### Design A — Free text (baseline, not recommended alone)
Instinct writes a plain-English ask ("Please check if I have any new LinkedIn connection requests and accept the ones from people at my target companies"), gatekeeper replies in kind.
- **Pros**: zero integration burden on Instinct's side, most "natural" for an LLM.
- **Cons**: no machine-checkable request ID/verb, ambiguous scope ("which target companies?"), hard to build reliable auth/policy/rate-limiting logic against free text, hard to grep the audit log for "all LinkedIn actions in the last week," easy for injected content to blend into the request framing.

### Design B — Structured envelope only (strict)
Every request/response is a fenced JSON or YAML block and *nothing else* — subject line is a fixed tag (e.g. `[GATEKEEPER-REQUEST]`), body is just the structured payload.
```
Subject: [GATEKEEPER-REQUEST] req_8f3a1c2e

​```yaml
request_id: req_8f3a1c2e
verb: linkedin.accept_connections
params:
  filter: "company in target_list"
  max_actions: 5
requested_by: instinct
timestamp: 2026-09-14T10:02:00+03:00
​```
```
- **Pros**: trivially parseable, easy to validate against a JSON Schema, easy to rate-limit/authorize per verb, clean idempotency key (`request_id`).
- **Cons**: brittle if the LLM drifts from the schema (no prose fallback to recover intent), the human reading the thread has to mentally parse YAML, doesn't leave room for legitimate free-text nuance ("also, only if their headline mentions engineering").

### Design C — Hybrid: natural-language body + fenced structured block (recommended)
The email reads like a normal message a human could understand, with a small structured block appended that carries the machine-checkable parts (verb, request ID, threading info, and a natural-language `intent` field that both the human and the parser can lean on if the verb is ambiguous or missing).
```
Subject: Re: [gatekeeper] LinkedIn — accept relevant connection requests (req_8f3a1c2e)

Hi Gatekeeper,

Could you check my LinkedIn for new connection requests and accept the ones
from people at companies on my target list? Please don't accept recruiters
outside that list.

---GATEKEEPER-REQUEST---
request_id: req_8f3a1c2e
in_reply_to: null
verb: linkedin.accept_connections
intent: "Accept LI connection requests from target-list companies only"
params:
  filter: "company in target_list"
  max_actions: 5
  requires_approval: false
requested_by: instinct
timestamp: 2026-09-14T10:02:00+03:00
---END---
```
Gatekeeper's reply keeps `In-Reply-To`/`References` headers set to the original `Message-ID` (standard RFC 5322 threading, which every mail client and any LLM polling IMAP can follow), and includes its own structured block:
```
Subject: Re: [gatekeeper] LinkedIn — accept relevant connection requests (req_8f3a1c2e)

Done. I found 3 new connection requests, 2 matched your target-list
(Acme Corp, Globex) and were accepted. 1 was from a recruiter at a
company not on your list, so I skipped it per your instructions.

---GATEKEEPER-RESPONSE---
request_id: req_8f3a1c2e
status: completed
actions_taken:
  - accept_connection: "Jane Doe (Acme Corp)"
  - accept_connection: "John Roe (Globex)"
skipped:
  - reason: "not in target_list"
    who: "Recruiter X (Unlisted Co)"
cost_usd: 0.014
duration_ms: 8421
---END---
```
- **Verb vocabulary** should be a small, fixed, versioned enum (e.g. `email.search`, `email.send_draft_for_approval`, `linkedin.accept_connections`, `linkedin.send_message`, `status.query`, `clarify.answer`) — Instinct picks the closest verb and the gatekeeper validates params against that verb's schema; if the verb is missing/unrecognized, the gatekeeper falls back to LLM-classifying `intent` but flags the request as `verb_inferred: true` in the audit log for extra scrutiny.
- **Clarifying questions**: gatekeeper replies with `status: needs_clarification` and a `question` field; the *same* `request_id` is reused (not a new one) so the thread stays one logical transaction; Instinct's follow-up sets `in_reply_to: req_8f3a1c2e`.
- **Async/long-running**: gatekeeper immediately replies `status: acknowledged` with an ETA, then sends a second, separate email (same thread, same `request_id`, `status: completed`) when done — this also naturally solves "Instinct polls its inbox and might be looking at a stale state" since it just waits for the completion email.
- **Errors**: `status: error`, machine-readable `error_code` (e.g. `policy_denied`, `credential_expired`, `rate_limited`, `ambiguous_request`) plus a human-readable `message` — this is what lets Instinct (or its own LLM) decide whether to retry, rephrase, or give up.
- **Idempotency/replay**: `request_id` is the idempotency key; gatekeeper keeps a dedupe table (even a simple SQLite/D1 table) keyed on it, and replays of the exact same `request_id` return the cached prior response rather than re-executing (critical for "accept connections" — you don't want a retried email to double-fire an action).
- **Rate limiting**: enforce per-verb and global caps (e.g. "max 20 LinkedIn actions/day") in the gatekeeper, reply with `error_code: rate_limited` and a `retry_after` — this also doubles as anomaly detection (a sudden spike is either Instinct malfunctioning or a prompt-injection-driven loop).
- **Size limits/attachments**: cap structured block size (e.g. 8KB) and total email size (e.g. 200KB); if an attachment is needed (e.g. a screenshot proving an action), send it as a normal MIME attachment but never accept attachments *from* Instinct as instructions — attachment content from inbound mail should be treated as data to summarize, never as commands, which is the standard indirect-prompt-injection mitigation for email agents ([Nylas guide](https://cli.nylas.com/guides/email-prompt-injection-defense)).
- **Audit readability**: because the structured block is appended, not prepended, and the prose stays first, a human skimming the thread never has to look at YAML to understand what happened — the YAML is there for the parser and for forensic replay.

### Recommendation
Use **Design C (hybrid)**. It is the only one of the three that satisfies both "an LLM can reliably produce it without a strict SDK" and "a human can read the thread and a program can validate/replay it."

---

## 3. Human-in-the-loop & user visibility

- **BCC vs CC**: BCC the user on gatekeeper→Instinct replies. CC would put the user's address in a header Instinct's LLM can see and might reason about/reply to, muddying the two-party protocol; BCC keeps the user purely a silent observer of the canonical audit trail without changing the conversation Instinct thinks it's having.
- **Daily digest**: worthwhile even with the email thread as ground truth, because "read every email" doesn't scale past a handful of requests/day. A simple daily cron (Cloudflare Cron Trigger or a systemd timer) that summarizes the day's requests, actions, denials, and costs into one digest email is cheap to build and dramatically improves the "visibility" goal.
- **Tiny web dashboard**: recommended once request volume exceeds ~10-20/day — a read-only page (even a single static HTML page regenerated on each request, served from R2/Cloudflare Pages, or a minimal FastAPI/Flask view on the VPS behind Cloudflare Access) that lists requests, statuses, costs, and links back to the source email thread. This does not need to be built in the MVP but should be planned for early because retrofitting audit UI onto an email-only system is painful.
- **Push approvals for sensitive requests** — compare:

| Channel | Latency | Security notes | Cost |
|---|---|---|---|
| **Telegram bot (inline buttons)** | Seconds | Inline `callback_query` approvals are the most common pattern in 2026 agent tooling ([dev.to summary](https://dev.to/jameszh/human-in-the-loop-ai-agents-with-google-adk-and-telegram-5agd)); risk is forgeable callback data if the bot token leaks or if you don't verify the Telegram user ID against a hardcoded allowlist — must check `update.callback_query.from.id == YOUR_TELEGRAM_ID` server-side, not just trust the button click | Free |
| **ntfy.sh (self-hosted)** | Seconds | Plain HTTP pub/sub; self-hosting gives full control, no vendor dependency, good mobile app; action buttons in notifications can trigger HTTP callbacks — same "verify the request truly originated from your ntfy topic + a signed token" requirement applies | Free (self-hosted) |
| **Pushover** | Seconds | Mature apps, but every notification round-trips through Pushover's cloud — an outage there breaks your approval path; $4.99 one-time per platform | ~$5 one-time |
| **WhatsApp (via Instinct itself, or a separate bot)** | Seconds | Tempting since the user already lives in WhatsApp, but routing approvals *through* Instinct's own channel partially defeats the "Instinct has no direct access" design goal — better to use a channel fully independent of Instinct | Varies (Business API costs) |
| **Email-tap link (magic link in the gatekeeper's own email)** | Matches email latency (seconds-minutes) | Simplest to implement (no new channel), but weakest against forgery unless the link is a **signed, single-use, short-TTL token** (HMAC over request_id+expiry, checked server-side, invalidated after first use) — a bare "click to approve" URL without signing is trivially replayable | Free |

**Recommendation**: ntfy.sh self-hosted (or Pushover if you want zero ops) for time-sensitive approvals, with every approval link/button carrying a signed, single-use, short-TTL token regardless of channel — treat "approval link forgery" as the default assumption and require the signature check, not channel trust.

---

## 4. Audit logging & observability

- **Tamper-evident logging**: implement an append-only log where each entry stores `hash(entry_n) = SHA256(entry_n_content || hash(entry_n-1))`. This doesn't require a blockchain — a simple SQLite/D1 table with a `prev_hash` column and periodic export to write-once storage is enough for a single-user system. Store the periodic export in:
  - **Cloudflare R2 with Bucket Locks** — supports retention-until-date or indefinite locks, preventing deletion/overwrite, but explicitly **lacks compliance-mode immutability, legal hold, and SEC 17a-4 certification** ([Cloudflare docs](https://developers.cloudflare.com/r2/buckets/bucket-locks/)) — fine for "tamper-evident for personal accountability," not for regulatory compliance.
  - **AWS S3 Object Lock** if true WORM/compliance-mode certification is ever needed — heavier to operate for a single-user hobby project.
- **What to log** per request: raw inbound email (headers + body, including the structured block as received — before any sanitization, so you can see what an injection attempt looked like), the auth/verification verdict (SPF/DKIM/DMARC pass, sender allowlist match), the policy decision (verb allowed? rate limit ok? approval required and obtained?), every tool call made (with parameters and results), the exact data returned to Instinct, and token usage + cost per LLM call. This is exactly the level of granularity the project's own design goal ("email thread as human-readable audit log") implies, plus the machine-readable layer needed for real forensics.
- **LLM tracing tools**:
  - **Langfuse (self-hosted)** — MIT-licensed core, no enterprise gate on self-hosting, native OpenTelemetry GenAI semantic convention support, strong eval/prompt-management primitives; free tier on cloud is 50K events/mo, free entirely if self-hosted ([comparison](https://www.pkgpulse.com/guides/langfuse-vs-langsmith-vs-helicone-llm-observability-2026)). Best fit here: data ownership matters (this system handles the user's Gmail/LinkedIn data), and self-hosting is a first-class, not bolted-on, feature.
  - **LangSmith** — best if built on LangChain/LangGraph; self-hosting is an Enterprise add-on requiring a license key and (outside air-gapped licenses) mandatory egress to `beacon.langchain.com` — a poor fit if avoiding third-party egress of personal data is a goal.
  - **Helicone** — proxy-based, 5-minute integration, but as of March 2026 it's in maintenance mode after being acquired by Mintlify (security patches only, no new features) ([same comparison](https://www.pkgpulse.com/guides/langfuse-vs-langsmith-vs-helicone-llm-observability-2026)) — usable but not a long-term bet.
  - **Pydantic Logfire** — 10M spans/month free, good OTel-native story, worth a look if already in the Pydantic/FastAPI ecosystem.
  - **OpenTelemetry GenAI semantic conventions** — a CNCF-backed vendor-neutral schema (`gen_ai.request.model`, `gen_ai.usage.input_tokens`, etc.), still in "Development"/experimental status as of 2026 but already adopted by Google Cloud, AWS, Azure, Datadog and the above tools ([opentelemetry.io](https://opentelemetry.io/blog/2026/genai-observability/)) — instrumenting against these conventions now means you're not locked into any one vendor's schema later.
  - **Anthropic Console** — gives basic usage/cost dashboards for the API key itself; fine as a sanity check, not a substitute for request-level tracing.
- **Recommendation**: self-hosted Langfuse (same VPS or a small separate container) for LLM-call-level tracing, instrumented via OTel GenAI conventions so it's portable later, **plus** the hash-chained R2 log as the tamper-evident source of truth, **plus** the email thread itself as the plain-English layer the user actually reads day to day. Three layers, each serving a different audience (developer debugging, forensic integrity, human oversight).
- **Retention & privacy**: since these logs necessarily contain the user's personal data (email contents, LinkedIn activity), set an explicit retention window (e.g., 90 days hot, then archive-and-encrypt or delete) rather than "keep forever," and make sure whatever you pick supports deleting a user's data on request — ironically, Instinct's own inability to fully delete Gmail data on request was one of the user complaints ([TechCrunch](https://techcrunch.com/2026/08/24/instincts-powerful-ai-assistant-is-raising-privacy-and-security-concerns/)); don't rebuild that same flaw in the gatekeeper.

---

## 5. Kill switch & lifecycle

- **One-command disable**: for the VPS design, `docker compose down` (or a `systemctl stop gatekeeper`) plus, critically, **revoking the Gmail OAuth refresh token and killing the LinkedIn session cookie** at the same time — stopping the process alone leaves valid credentials sitting on disk. Keep a single `./killswitch.sh` script that does all three: stop the process, revoke OAuth grants via Google's revoke endpoint, and invalidate the LinkedIn session.
- **Auto-expiry of credentials**: prefer short-lived OAuth access tokens refreshed on demand over long-lived static credentials; set a policy that the LinkedIn session cookie is re-authenticated (or at minimum re-validated) on a schedule (e.g., weekly) so a stolen cookie has a bounded useful life.
- **Dead-man switch**: Healthchecks.io (free tier is sufficient for one check) — the gatekeeper pings it on a heartbeat; missed check-ins alert you that the box is down (or that something is wrong) ([healthchecks.io](https://healthchecks.io/faq/)). Cronitor and Dead Man's Snitch are paid alternatives with similar functionality.
- **Alerting on anomalies**: alert on (a) request volume spikes beyond your normal ~20-200/day baseline, (b) any new/unrecognized verb being invoked, (c) any policy-denied request (could indicate Instinct — or an injected instruction inside content Instinct summarized — is attempting something out of scope), (d) LLM cost spikes. Route these to the same push channel as approvals (ntfy/Pushover).
- **Backup/restore**: back up the SQLite/D1 audit DB and any persistent LinkedIn browser profile/session state regularly (daily snapshot to R2/S3 is enough at this scale); test restore at least once — an audit log you can't restore isn't an audit log.
- **Update strategy**: enable Dependabot or Renovate on the gatekeeper's repo for dependency patches (especially Playwright/Chromium, which ships frequent security fixes); **pin the exact Claude model version** in config (e.g., pin to a dated snapshot rather than a floating alias) so behavior doesn't silently shift, and bump deliberately after testing; consider a scheduled CI job that runs a small red-team prompt-injection test suite against the gatekeeper's policy layer on a cadence (weekly/monthly) to catch regressions as you iterate on the system prompt/verb schema.

---

## 6. Cost model

### LLM pricing (per Anthropic's current published rates, [claude.com/pricing](https://claude.com/pricing))

| Model | Input | Output | Cache read | Cache write (5m) |
|---|---|---|---|---|
| Claude Haiku 4.5 | $1 / MTok | $5 / MTok | $0.10 / MTok | $1.25 / MTok |
| Claude Sonnet 5 | $2 / MTok | $10 / MTok | $0.20 / MTok | $2.50 / MTok |
| Claude Opus 5 | $5 / MTok | $25 / MTok | $0.50 / MTok | $6.25 / MTok |

Batch API halves all standard rates; 1-hour cache TTL write costs ~2x input price instead of 1.25x, with identical read pricing — worth it only if calls are sparser than every 5 minutes.

### Estimated cost per request (illustrative, three tiers)
Assumes a system prompt / policy context of ~2-3K tokens kept warm via prompt caching, plus per-request dynamic content.

| Tier | Model(s) used | Typical tokens (in/out) | Est. cost/request |
|---|---|---|---|
| Cheap classify-only (e.g., simple status query, spam/irrelevant filter) | Haiku 4.5 | ~800 in / 150 out | ~$0.0016 |
| Standard task (search email, draft summary, simple LinkedIn action) | Sonnet 5, with caching | ~1,500 effective in / 700 out | ~$0.010–0.015 |
| Complex/high-stakes judgment (ambiguous approval, policy edge case) | Opus 5, occasional escalation | ~2,000 effective in / 1,000 out | ~$0.035–0.045 |

A sensible routing policy — Haiku for classification/triage of every inbound email, Sonnet for the actual task execution, Opus only escalated for genuinely ambiguous/sensitive decisions — blends to roughly **$0.01-0.02/request** on average.

### Monthly cost at two volumes

| Volume | LLM cost (blended ~$0.015/req) | Hosting (VPS + Cloudflare Tunnel + Email Routing) | Observability (self-hosted Langfuse, same box) | Push/alerting (ntfy self-hosted / Healthchecks free) | **Total estimate** |
|---|---|---|---|---|---|
| ~20 req/day (600/mo) | ~$9/mo | ~$5-12/mo (Hetzner CX22 or DO droplet) | $0 (same box) | $0 | **~$14-21/mo** |
| ~200 req/day (6,000/mo) | ~$90/mo | ~$5-12/mo (same box handles this easily) | $0 | $0 | **~$95-102/mo** |

At 200 req/day, LLM tokens dominate the bill, not hosting — this argues strongly for aggressive Haiku-first routing and prompt caching discipline (a stable, cached system/policy prompt) over any hosting optimization.

---

## 7. Latency

- **SMTP acceptance** (sender → recipient MTA 2xx response) is typically **seconds**, but **full inbox delivery** (spam filtering, Gmail's internal queuing) can add anywhere from a few seconds to several minutes, and occasionally longer for a brand-new sender/recipient pair (greylisting-like effects) or during reputation warm-up ([Suped](https://www.suped.com/learn/email-deliverability/why-are-my-emails-delayed-in-gmail-even-with-a-good-reputation-and-proper-authentication)).
- **Gatekeeper processing**: with prompt caching and a warm process, a single Claude call (classify + act) should complete in low single-digit seconds; a Playwright-driven LinkedIn action adds real browser-automation time — realistically **5-30 seconds** per action.
- **Outbound reply delivery**: same seconds-to-minutes SMTP/delivery variance as inbound.
- **Instinct's own inbox polling cadence** is the wildcard and likely the dominant factor: if Instinct polls IMAP every 1-5 minutes (typical for agent inbox-watching patterns) rather than using push (Gmail Pub/Sub push notifications, IMAP IDLE), that polling interval alone can add up to its full interval length on top of everything else.
- **Realistic end-to-end estimate**: **10 seconds on a good run, 1-5 minutes typical**, with occasional outliers past that on delivery hiccups.
- **Is that acceptable for WhatsApp-style interaction?** For anything the user is actively watching in a WhatsApp chat waiting for a reply, 1-5 minutes reads as "slow" by modern chat-app standards (WhatsApp itself is sub-second). For anything the user fires off and checks back on later ("go accept my LinkedIn connections while I'm in this meeting"), it's fine.
- **Alternative for time-sensitive paths**: expose a **low-latency webhook or MCP tool call** as the primary request/response channel between Instinct and the gatekeeper (sub-second to a few seconds round trip, no SMTP queue in the loop), while the gatekeeper *simultaneously* writes the equivalent structured request/response into the same email thread purely for audit purposes (fire-and-forget, doesn't block the response to Instinct). This preserves "email thread as human-readable audit log" as a non-blocking side effect rather than the critical path, and only use synchronous email-as-transport for the (probably rare) cases where the user explicitly wants the friction of an email round-trip as a deliberate speed bump (e.g., for the most sensitive verbs, where a slower, more deliberate channel is actually a feature).

---

## Recommended MVP deployment + protocol

1. **Hosting**: Hetzner CX22 VPS (or DigitalOcean Basic Droplet), Docker Compose running (a) the gatekeeper process, (b) Playwright/Chromium with a persistent LinkedIn profile volume, (c) self-hosted Langfuse, (d) self-hosted ntfy. Exposed to the internet **only** via a Cloudflare Tunnel (zero open inbound ports). DNS + Cloudflare Email Routing on the domain, routing inbound mail to a webhook the gatekeeper listens on (or IMAP-poll as a fallback). Total: ~$5-12/mo hosting.
2. **Email/audit transport**: Cloudflare Email Routing for inbound; SMTP (or Cloudflare Email Service) for outbound, with `Message-ID`/`In-Reply-To` threading.
3. **Protocol**: Design C (hybrid natural-language + fenced YAML block), fixed verb enum, `request_id` idempotency, BCC the user on every reply.
4. **Primary interactive path**: a webhook/MCP endpoint for Instinct's live requests (sub-second latency), with every exchange mirrored into the email thread asynchronously for audit.
5. **HITL**: self-hosted ntfy for push approvals on sensitive verbs, signed single-use approval tokens, daily digest email to the user.
6. **Audit**: hash-chained append-only log → periodic export to R2 with bucket lock; Langfuse for LLM-call tracing instrumented via OTel GenAI conventions.
7. **Model routing**: Haiku 4.5 for triage/classification of every inbound item, Sonnet 5 for task execution, Opus 5 reserved for escalated ambiguous/high-stakes decisions; 5-minute prompt caching on the policy/system prompt.
8. **Kill switch**: `killswitch.sh` (stop process + revoke Gmail OAuth + kill LinkedIn session) + Healthchecks.io dead-man's switch + volume/anomaly alerts via ntfy.
9. **Lifecycle**: Renovate/Dependabot on the repo, pinned dated Claude model version, monthly scheduled red-team prompt-injection test in CI.

## Open questions for the user

1. Does the user want the primary Instinct↔gatekeeper channel to actually be email (as originally scoped), or is a webhook/MCP path with email-as-audit-mirror preferable given the latency findings above? This is a meaningful architecture fork.
2. How sensitive are LinkedIn actions specifically — should *all* LinkedIn writes require push approval, or only certain verbs (e.g., accepting connections auto-approved, sending messages requires approval)?
3. Is self-hosting Langfuse/ntfy on the same VPS acceptable, or does the user want these on separate infrastructure for blast-radius isolation from the credential-holding process?
4. What retention period is acceptable for logs that necessarily contain Gmail/LinkedIn content — 30/90/365 days?
5. Is there an existing Cloudflare or Render project/account structure (the user mentioned both are already connected) this should slot into, or should it be a fresh project?
6. Should the gatekeeper itself use Claude, and if so is there a preference for pinning to a specific dated model snapshot now vs. tracking the latest Sonnet release going forward?

---

## Sources

- [TechCrunch — Instinct's powerful AI assistant is raising privacy and security concerns (2026-08-24)](https://techcrunch.com/2026/08/24/instincts-powerful-ai-assistant-is-raising-privacy-and-security-concerns/)
- [Claude API Pricing — claude.com/pricing](https://claude.com/pricing)
- [Cloudflare Workers Pricing](https://developers.cloudflare.com/workers/platform/pricing/)
- [Cloudflare Browser Run Pricing](https://developers.cloudflare.com/browser-run/pricing/)
- [Cloudflare Blog — Email for Agents (public beta)](https://blog.cloudflare.com/email-for-agents/)
- [Cloudflare R2 Bucket Locks docs](https://developers.cloudflare.com/r2/buckets/bucket-locks/)
- [Cloudflare Tunnel in 2026 — dev.to](https://dev.to/recca0120/cloudflare-tunnel-in-2026-expose-localhost-without-opening-ports-or-buying-an-ip-32l5)
- [Render Pricing](https://render.com/pricing)
- [Fly.io pure usage pricing analysis — bex.co](https://bex.co/blog/2026/08/16/flyio-pure-usage-pricing-always-on-app-cost)
- [Fly.io pricing 2026 — runxbuild](https://www.runxbuild.com/blog/fly-io-pricing/)
- [Railway Free Tier / pricing — saaspricepulse](https://www.saaspricepulse.com/tools/railway)
- [Railway Playwright guide](https://docs.railway.com/guides/playwright)
- [Hetzner Cloud pricing 2026 — bestusavps](https://bestusavps.com/reviews/hetzner/)
- [DigitalOcean pricing 2026 — costbench](https://costbench.com/software/cloud-infrastructure/digitalocean/)
- [Amazon SES pricing 2026 — leadsnipper](https://leadsnipper.com/blog/amazon-ses-pricing-2026)
- [Google Cloud Run pricing — cloudcostkit](https://cloudcostkit.com/guides/gcp-cloud-run-pricing/)
- [Modal pricing explained — beam.cloud](https://www.beam.cloud/blog/modal-pricing-explained)
- [Modal pricing blueprint — usagepricing.com](https://www.usagepricing.com/blueprint/modal)
- [Anthropic Managed Agents overview — roborhythms](https://www.roborhythms.com/anthropic-managed-agents-2026/)
- [Langfuse vs LangSmith vs Helicone comparison — pkgpulse](https://www.pkgpulse.com/guides/langfuse-vs-langsmith-vs-helicone-llm-observability-2026)
- [OpenTelemetry GenAI observability blog](https://opentelemetry.io/blog/2026/genai-observability/)
- [Nylas — Email Prompt Injection Defense guide](https://cli.nylas.com/guides/email-prompt-injection-defense)
- [Healthchecks.io FAQ](https://healthchecks.io/faq/)
- [ntfy vs Pushover / self-hosted comparison — bigiron](https://www.bigiron.cc/guides/gotify-vs-ntfy-vs-apprise-vs-pushover)
- [Telegram human-in-the-loop approval pattern — dev.to](https://dev.to/jameszh/human-in-the-loop-ai-agents-with-google-adk-and-telegram-5agd)
- [Gmail email delivery latency — Suped](https://www.suped.com/learn/email-deliverability/why-are-my-emails-delayed-in-gmail-even-with-a-good-reputation-and-proper-authentication)
- [Playwright Docker memory/shm requirements](https://www.browserless.io/blog/run-playwright-in-docker)
- [MCP vs A2A vs ACP agent protocols 2026](https://optinampout.com/blogs/mcp-vs-a2a-vs-acp-agent-protocols-2026)
