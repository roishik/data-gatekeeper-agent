# data-gatekeeper-agent

> **Status: live MVP (read-only) + local-only write access (2026-09-15).** The research below
> drove the design; `app/` is deployed on Cloud Run and answers allowlisted emails end to end for
> `gmail.search`/`calendar.list_events` — inbound AgentMail webhook → auth/policy → executor →
> reply, with a hash-chained audit log. This session added write verbs
> (`gmail.create_draft`, `calendar.create_event`/`update_event`/`delete_event`,
> `drive.create_file`) that are **not deployed yet** and deliberately depart from the read-only
> threat model below for calendar writes (autonomous, no recipient allowlist, no approval step
> — an explicit owner choice, not an oversight). Current state, infrastructure IDs and next
> steps: `CLAUDE.md`. `calendar.list_events` resolves relative day language ("tomorrow") to a
> `day_offset`/`days` pair the LLM picks and Python turns into a timezone-aware window — see
> `app/calendar_window.py`. See `docs/RUNBOOK.md` for how to run it and the tests.

A self-hosted agent that is the **only** thing holding my credentials (Gmail, LinkedIn, ...).
My consumer AI assistant (Instinct) never gets direct access. Instead it **emails** the
gatekeeper, and the gatekeeper checks the request, does the work, and emails back the result.
The email thread is the audit log, and cutting Instinct off means the gatekeeper stops replying.

```
 Me ──WhatsApp──► Instinct ──request email──► Gatekeeper ──► Gmail / Calendar / LinkedIn
                     ▲                             │
                     └───────response email────────┘   (+ BCC to me = audit log)
```

## How to read this repo

| # | File | Question it answers |
|---|---|---|
| 00 | [research/00-brief.md](research/00-brief.md) | What I asked for, in my words |
| 01 | [research/01-instinct-and-the-problem.md](research/01-instinct-and-the-problem.md) | What Instinct really is, what went wrong for other users, and whether the gatekeeper idea holds up |
| 02 | [research/02-agent-frameworks.md](research/02-agent-frameworks.md) | OpenClaw vs. clones vs. LangGraph vs. Claude Agent SDK vs. no framework (15 options scored) |
| 03 | [research/03-prompt-injection-and-fraud-defense.md](research/03-prompt-injection-and-fraud-defense.md) | How to make it injection- and fraud-resistant, and how to keep it that way |
| 04 | [research/04-data-connectors-and-credentials.md](research/04-data-connectors-and-credentials.md) | How to connect to Gmail, Calendar, LinkedIn and WhatsApp; where secrets live; the kill switch; the gatekeeper's own inbox |
| 05 | [research/05-deployment-protocol-and-observability.md](research/05-deployment-protocol-and-observability.md) | Hosting, the email protocol, human approvals, audit logs, cost, latency |
| 06 | [research/06-browser-automation-cost.md](research/06-browser-automation-cost.md) | *(Parked)* LinkedIn and other sites without an API: cheap, safe browser automation vs. computer use |
| 07 | [research/07-free-hosting-options.md](research/07-free-hosting-options.md) | Free or near-free always-on hosting (AgentCore, Vertex Agent Engine, Apps Script, Cloud Run, Workers, Oracle, ...) and logging to Drive |

Reports 01-05 were written by parallel research agents (Claude Sonnet) and then cross-checked by
an orchestrator (Claude Opus). The key claims were spot-checked against their primary sources on
2026-09-14 (see "Verification notes" below). Every report ends with its own sources list.

---

## TL;DR: where the research lands

1. **The problem is real and documented.** Instinct (Spear Street Technology, founder Noah Shinn)
   has public incidents. It kept Gmail data after Google access was revoked. It sent an email
   without asking. It used a sign-up code from someone's inbox without permission. It was
   prompt-injected by a plain email. Its terms of service grant a *"perpetual and irrevocable"*
   license to user materials. ([TechCrunch, 2026-08-24](https://techcrunch.com/2026/08/24/instincts-powerful-ai-assistant-is-raising-privacy-and-security-concerns/))
2. **The gatekeeper design fixes credential exposure, not data retention.** Instinct never holds
   your tokens, and revoking it becomes instant and total. But any data the gatekeeper *sends*
   to Instinct sits in Instinct's inbox, under its terms of service. So the gatekeeper also has
   to **minimize what it returns**, not just control access.
3. **Do not build on OpenClaw.** It has had a critical one-click RCE, several other CVEs, and a
   skill marketplace where roughly 12-20% of skills were malicious. Its "big general agent"
   shape is the opposite of what a credential holder needs. Lighter clones (NanoClaw, nanobot)
   are good *reference designs* to read.
4. **Build something small and purpose-built.** Deterministic code in the privileged path.
   The LLM is **quarantined**: it reads untrusted text but has no tools and can only emit a
   strict schema. It sits behind a **fixed menu of allowed actions** (the action-selector /
   plan-then-execute patterns, from the same family as CaMeL and Dual-LLM). Prompt injection is
   still unsolved, so classifiers are tripwires, never the gate.
5. **Email is authenticated at several layers, never trusted by itself.** The layers are a
   secret sub-address, a sender allowlist, DKIM/DMARC checks, request IDs with replay
   protection, and rate limits. Sensitive actions also need **approval on a channel that is not
   Instinct** (for example a push notification).
6. **LinkedIn is the hardest connector.** It has no official API for personal data. Every
   working path (Unipile, unofficial libraries, Playwright with cookies) breaks LinkedIn's terms
   and risks a ban on your real account. Recommendation: read-only and low frequency at most,
   or skip it for the MVP. **Never store the LinkedIn password.**
7. **Google is easy, with one trap.** An OAuth app left in "Testing" mode has its refresh
   tokens killed every 7 days. Switch the consent screen to "In production": an unverified,
   single-user app needs no Google review.
8. **Email latency is 10 seconds to 5 minutes per round trip.** That's fine for "do this and
   tell me" requests, but slow for live chat. Whether Instinct can use a faster channel
   (webhook/MCP) is **unverified**.
9. **Cost is small.** About $15-20/month at 20 requests/day. Roughly $100/month at
   200 requests/day, where LLM tokens dominate (the VPS itself is ~$5-12/month).

## Candidate architecture (for review, not decided)

```
Inbound email ─► [0] Mail gate: secret sub-address, sender allowlist, DKIM/DMARC
             ─► [1] Auth: request_id replay check, rate limits, (token if feasible)
             ─► [2] Quarantined reader LLM: no tools, emits a strict typed schema only
             ─► [3] Policy engine (plain Python): allowed verbs only, deny by default,
                    redact OTPs / reset links / financial data, anomaly checks
             ─► [4] Executor: fixed plan, per-connector isolated processes holding scoped creds
                    └─ sensitive verb? → push approval to me (signed, single-use, expiring)
             ─► [5] Reply guard: reply only to the verified requester, no links/images/
                    attachments, size caps, BCC me
             ─► hash-chained audit log + the email thread itself
```

### Recommended options per layer (with the main alternative)

| Layer | Leading option | Main alternative | Why / trade-off | Detail |
|---|---|---|---|---|
| Runtime / framework | Plain Python + Pydantic schemas + Anthropic Messages API (quarantined role only) | LangGraph control plane + Claude Agent SDK executor; or fork and strip NanoClaw | Smallest attack surface, fully readable. LangGraph gives durable approval pauses (`interrupt()`) for free, at the cost of a bigger dependency | 02 |
| Injection defense | Action-selector + Dual-LLM + strict structured output + deny-by-default policy | Full CaMeL / FIDES (information-flow control) | The leading option is practical today. CaMeL/FIDES give stronger guarantees but are research-grade and much more work | 03 |
| Classifier tripwire | Self-hosted LLM Guard or Prompt Guard 2 | Lakera / Model Armor (SaaS) | SaaS options update more often but send my content to another third party | 03 |
| Gatekeeper inbox | Cloudflare Email Routing + Worker (own domain, raw MIME and DKIM results visible) | AgentMail (fastest to set up, native threading) | Full control vs. speed. AgentMail adds another vendor holding the audit trail | 04, 05 |
| Hosting | Hetzner/DO VPS + Docker, reachable only through a Cloudflare Tunnel (no open ports) | All Cloudflare Workers + Durable Objects | A VPS can keep a persistent browser profile (needed if LinkedIn uses Playwright). Workers are cheaper and have native `onEmail`, but no persistent browser | 05 |
| Gmail / Calendar | Direct Google OAuth, least-privilege scopes, consent screen "In production" | Nango self-hosted for token plumbing | Avoid hosted unified-API vendors (Composio was breached in May 2026: ~5.2k API keys and ~5k GitHub tokens stolen) | 04 |
| LinkedIn | None in MVP → read-only Unipile if needed | Playwright + `li_at` cookie on the VPS | All paths break LinkedIn's terms. Unipile takes on the checkpoint maintenance but holds your session cookie | 04 |
| Secrets | SOPS + age (YubiKey-backed) + one process per connector | Self-hosted Infisical | No third party holds secrets, and decrypting needs a physical key touch. Infisical adds a UI and audit logs | 04 |
| Protocol | Hybrid: human-readable prose + fenced YAML block (verb enum, `request_id`, status) | Strict YAML only | An LLM can write it, a human can read it, and code can validate it | 05 |
| Approvals | ntfy (self-hosted) or Pushover with signed single-use links | Telegram bot (check the sender's user ID server-side) | Must be independent of Instinct | 05 |
| Audit | SQLite hash chain → R2 bucket lock; Langfuse (self-hosted) for LLM traces; BCC + daily digest | S3 Object Lock | Tamper-evident, and each layer serves a different audience | 03, 05 |
| Models | Haiku 4.5 for triage and extraction, Sonnet 5 when needed; pin dated versions | Use a different vendor's model for the quarantined reader | Cheap; a different vendor lowers the chance that one attack fools both models | 05, 02 |
| Staying current | promptfoo / AgentDojo injection suite in CI (weekly) + Renovate + advisories | Garak, PyRIT | Covers the "updated regularly against fraud" requirement | 03 |

---

## Where the reports disagree or overreach (read with care)

- **LinkedIn writes.** Report 05's example protocol uses `linkedin.accept_connections` (a write
  action). Report 04 recommends **never** writing to LinkedIn. Treat 05's example as an
  illustration of the format only. The MVP verb list should be read-only.
- **Webhook/MCP instead of email.** Report 05 suggests a low-latency webhook or MCP channel as
  the main path. Nothing found confirms that Instinct (a closed consumer product) can call
  either. Its confirmed channel is email. This needs a hands-on test.
- **Capability tokens.** Report 03's strongest request authentication needs Instinct to attach
  signed tokens deterministically. If only Instinct's LLM copies a token into the email body, a
  successful injection can leak it. Treat such tokens as low-trust: layers [3]-[5] must hold
  up even if the token is known.
- **Framework ranking.** Report 02's top pick is LangGraph + Agent SDK, but its own scores put
  "plain Python loop" and "CaMeL-style DIY" higher (9/10 vs. 8/10). Given my past no-framework
  agent build (apartments-agent-from-scratch), plain Python looks like the more natural start.
  LangGraph earns its place only if durable approval pauses get painful to build.
- **Secondary sources.** Report 01 flags that many Instinct write-ups are SEO sites repackaging
  TechCrunch/Forbes. Claims sourced only from those sites are marked "uncertain" in that report.

## Verification notes (orchestrator spot-checks, 2026-09-14)

| Claim | Result |
|---|---|
| Instinct incidents and terms-of-service quotes (TechCrunch 2026-08-24) | ✅ Confirmed. The article also reports two incidents 01 missed: **Peter Yang** (Gmail indexed and deletion initially refused) and a tester whose **sign-up code** Instinct took from email for a Resy booking without authorization |
| Instinct's own email address (TechCrunch 2026-09-09) | ✅ Confirmed. It can email outside businesses. **No mention of standing instructions**, so the core feasibility question stays open |
| Claude pricing (Haiku 4.5 $1/$5, Sonnet 5 $2/$10, Opus 5 $5/$25 per MTok) | ✅ Confirmed at claude.com/pricing. Report 02 had outdated Sonnet numbers; fixed |
| Composio breach (May 21, 2026: ~5,241 API keys + ~5,001 GitHub OAuth tokens) | ✅ Confirmed (Material Security write-up) |

---

## Decided

- **2026-09-14 — Personal, single-user use only.** (Google OAuth app stays unverified,
  "In production".)
- **2026-09-14 — MVP scope is Google only** (Gmail, Calendar, and optionally Drive/Contacts)
  plus the gatekeeper's dedicated inbox. LinkedIn and other sites without an API are parked;
  see [06](research/06-browser-automation-cost.md).
- **2026-09-14 — Inbox: AgentMail** (free tier: 3 inboxes, 3,000 emails/mo, 100/day; verified).
- **2026-09-14 — Google access: read-only** (`gmail.readonly`, `calendar.readonly`,
  `drive.readonly`, `contacts.readonly`), plus `drive.file` so the gatekeeper can write its own
  log sheet (it only reaches files the app itself creates).
- **2026-09-14 — Storage: my own Google Drive** (a log sheet created by the app, with a hash
  chain). The BCC'd email thread in my personal inbox is the second copy, which the
  gatekeeper can't rewrite.
- **2026-09-14 — Hosting: Google Cloud Run** (Python, always-free tier, receives AgentMail's
  webhook with Svix signature verification, secrets in Secret Manager, same GCP project as the
  OAuth client). Rejected: Cloudflare Workers (TypeScript-native), AgentCore / Vertex Agent
  Engine (not free, overkill), Apps Script (can't verify webhook signatures, weak isolation),
  Oracle Always Free (idle reclamation, 2026 policy cuts). See
  [07](research/07-free-hosting-options.md).

## Decisions I need to make before building

**Blocking (these change the architecture):**
1. **Does Instinct actually cooperate?** Before any build, spend 30 minutes testing: tell Instinct
   "for anything about my Gmail, email X and wait for the reply" and watch whether it keeps
   doing that over days. *If it doesn't, the whole design changes* (see #2).
2. **Gatekeeper or replacement?** Keep Instinct (for its UX) behind a gatekeeper, or replace it
   with my own WhatsApp agent so no third party ever sees my data? (Report 01 §5.3.)
3. **LinkedIn risk appetite:** none / read-only digest via Unipile / Playwright. Each carries a
   different ban risk for my real account.
4. **Transport:** email only (slow, but the audit log is automatic), or push for a faster channel
   if Instinct supports one?

**Important, not blocking:**
5. MVP verb list, and which verbs need my push approval (suggested: all sends and all
   LinkedIn actions need approval; bounded Gmail/Calendar reads are automatic).
6. Hosting: VPS + Tunnel, or all Cloudflare.
7. Gatekeeper inbox: my own domain on Cloudflare, or AgentMail.
8. Is a WhatsApp connector needed at all? (Probably not, since Instinct already covers WhatsApp.)
9. Log retention (30 / 90 / 365 days), given the logs contain my email content.
10. Personal Gmail or Google Workspace (Workspace removes the unverified-app warning; ~$6-12/mo).

## Suggested next phases

1. **Feasibility spike (no code):** the Instinct cooperation test from decision #1. Also send a
   hand-written structured request email to a test inbox and see whether Instinct follows the
   protocol format.
2. **Threat model + verb spec:** freeze the MVP verb list, the schemas, the redaction rules and
   the approval matrix.
3. **Walking skeleton:** inbound email → authentication → one read-only verb
   (`gmail.search`) → reply with BCC and the hash-chained log. Build the injection test suite
   in CI from day one.
4. Add Calendar, approvals, the kill-switch script and the daily digest. Decide on LinkedIn last.
