# 04 — Data connectors and credentials

Research date: 2026-09-14. Scope: for each data source the gatekeeper must touch (Gmail, Calendar/Drive/Contacts, LinkedIn, WhatsApp, plus a brief pass on Outlook/Slack/Notion/GitHub/banking/X), evaluate the official API, the auth model, the unofficial fallback, ban/ToS risk, and reusable MCP servers — then cover credential storage architecture, a kill-switch playbook, and options for the gatekeeper's own inbox.

## Executive summary

- **Gmail, Calendar, Drive, Contacts** all have solid official Google APIs with fine-grained OAuth scopes. The catch is entirely on the *auth lifecycle*, not the API: an OAuth app left in "Testing" publishing status gets its refresh tokens **killed after 7 days**, which will silently break the gatekeeper every week. The fix is either (a) publish the OAuth consent screen to "In production" as an *unverified* app (fine for restricted scopes like `gmail.modify`/`drive.readonly` used by a single named person — Google does not require verification for apps under 100 users, it just shows a scary "Google hasn't verified this app" warning the owner clicks through), or (b) use a Google Workspace **internal** app if the user moves to Workspace, which has no 100-user cap and no unverified-app warning. Restricted-scope **CASA security assessment** ($500–$75k/yr depending on tier) only applies if you distribute the app to the public — a single-user personal project never needs it. Recommendation: unverified "In production" personal OAuth app, minimal scopes (`gmail.modify` not `mail.google.com`), Pub/Sub push instead of polling.
- **LinkedIn is the hard problem.** There is no official API for reading a personal profile's own feed/DMs/connections at the level Instinct wants. The only paths are: (1) LinkedIn's tiny self-serve OAuth (login + posting only — no DM read, no feed read), (2) unified-API vendors like **Unipile** that operate your real LinkedIn session via `li_at` cookie under the hood, (3) unofficial libraries (`linkedin-api`, Playwright + stored cookies) that hit the same private Voyager endpoints LinkedIn actively fingerprints and bans for. LinkedIn has successfully sued and shut down scraping vendors (Proxycurl, July 2025; hiQ Labs before that) and its User Agreement §8.2 explicitly prohibits automated access — meaning **any of these paths puts the user's real LinkedIn account at genuine risk of restriction or permanent ban**, full stop, regardless of vendor. Unipile reduces *engineering* risk (maintained, handles 2FA/checkpoints) but not *account* risk — it's driving the same session. Concrete recommendation: treat LinkedIn as **read-light, write-never** (only fetch notifications/InMail digests at low frequency, never auto-connect or auto-message), use Unipile or a dedicated throwaway/secondary account if the user wants any automation, and get explicit acknowledgment from the user that this is against LinkedIn's ToS.
- **WhatsApp**: the official Cloud API is built for *business* messaging on a *business-registered* number, not for reading a personal account's existing chat history with friends/family. "Coexistence mode" lets a WhatsApp Business App number also route through the Cloud API and replays ~6 months of history, but it requires converting to a Business App number — not simply "log into my personal number." Reading the user's actual personal WhatsApp (the Instinct use case) realistically means either (a) Instinct keeps handling WhatsApp itself (already does, per the brief) and the gatekeeper never touches WhatsApp directly, or (b) an unofficial library (Baileys / whatsapp-web.js) which reverse-engineers the multi-device protocol and carries real ban risk for personal numbers sending outbound traffic. Given the brief's architecture (Instinct is already the WhatsApp surface; the gatekeeper only needs an *email* channel to talk to Instinct), **the gatekeeper likely does not need WhatsApp API access at all** — flag this as an open question.
- **Unified-API vendors** (Unipile, Nango, Composio, Pipedream, Merge, Arcade.dev) trade engineering effort for a new single point of failure holding all your credentials. This is not hypothetical: **Composio was breached in May 2026** — a compromised employee Gmail OAuth token cascaded into ~5,241 API keys and ~5,001 GitHub OAuth tokens being exfiltrated. For a project whose entire premise is "reduce blast radius of a compromised agent," routing every credential through a third-party SaaS vendor is in tension with the goal unless that vendor is self-hosted (Nango is MIT/Elastic-licensed and self-hostable; most others are not).
- **Credential storage**: for a single-user, self-hosted project, the pragmatic stack is **Infisical (self-hosted, MIT)** or plain **SOPS + age** (no server, keys never leave disk, works great with a hardware key via `age-plugin-yubikey`) for secrets-at-rest, combined with **per-connector process isolation** (each integration — Gmail, LinkedIn — runs as a separate OS process/container with only its own credential injected, so a prompt-injected LLM call in the Gmail connector physically cannot read the LinkedIn cookie).
- **Gatekeeper's own inbox**: for a from-scratch build, **AgentMail** (YC-backed, free tier, built specifically for agent inboxes with threading + webhooks) is the fastest path to a working two-way email loop. For a more "own the infrastructure" approach, **Cloudflare Email Routing + Workers** is free, self-hosted-feeling, and gives full control of parsing — at the cost of building your own threading/storage. A second Gmail account via the Gmail API is the most familiar but reintroduces Google OAuth lifecycle management for the gatekeeper's *own* mailbox, doubling the OAuth surface to babysit.

---

## 1. Gmail

### Official API
The Gmail API (`gmail.googleapis.com`) supports full read/search, send, label management, drafts, and threading. [Gmail API Scopes Guide — Unipile](https://www.unipile.com/gmail-api-scopes-guide/); [EmailEngine Gmail scopes reference](https://learn.emailengine.app/docs/accounts/gmail/gmail-api-scopes).

### Minimal scopes per capability
| Capability | Scope | Notes |
|---|---|---|
| Read/search only | `gmail.readonly` | Restricted scope, needs app verification for public distribution (not for single-user unverified apps) |
| Send only | `gmail.send` | No read access — good for a "reply back to Instinct" channel with zero read blast radius |
| Read + send + label + trash (no permanent delete) | `gmail.modify` | The practical scope for "read a thread, reply, label it processed" |
| Labels only | `gmail.labels` | Create/read/update/delete labels only |
| Drafts + send | `gmail.compose` | |
| Everything including permanent delete | `mail.google.com` | Avoid — full account access, highest-risk scope, exactly what NOT to request |

Recommendation: request **`gmail.modify` + `gmail.labels`** for the gatekeeper's own working mailbox (to label processed requests) and a separate **`gmail.readonly`** grant if it must also *read* the user's primary Gmail for lookups (search receipts, etc.) — keep primary-Gmail read and gatekeeper-mailbox read/write as two separate OAuth grants so a compromised gatekeeper-mailbox token can't touch the primary account.

### Push vs. polling
`users.watch` + Cloud Pub/Sub delivers push notifications the moment a message changes, avoiding polling. Cost: `users.watch` = 100 quota units per call, `users.history.list` = 5 units, default daily quota 1M units/project. The watch must be renewed at least every 7 days (Google recommends daily) or notifications silently stop. [Configure push notifications — Google for Developers](https://developers.google.com/workspace/gmail/api/guides/push); [Gmail API Push Notifications guide — Unipile](https://www.unipile.com/gmail-api-push-notifications/). For a single-user gatekeeper, either push+Pub/Sub or a simple 1–5 minute poll of `users.history.list` since last `historyId` both work fine within quota; push is lower latency and cheaper in the long run, polling is simpler to operate (no GCP Pub/Sub topic/subscription to maintain, no separate webhook endpoint to secure).

### OAuth app verification / the 7-day refresh token trap
This is the single most important operational fact for this whole project:

- While the OAuth consent screen is in **Testing** status, Google treats the app as unverified and **expires every refresh token after exactly 7 days** — the gatekeeper would silently stop working weekly and need re-authorization. [Google OAuth Refresh Token explainer — Unipile](https://www.unipile.com/google-oauth-refresh-token/).
- Moving the consent screen to **In production** (even while remaining "unverified" by Google, i.e. no CASA audit, no Google review) removes the 7-day cap — refresh tokens become effectively indefinite (subject to normal revocation conditions: password change, 6 months inactivity, explicit revoke, etc.). Users just see a "Google hasn't verified this app" interstitial they click through once. [Restricted scope verification — Google for Developers](https://developers.google.com/identity/protocols/oauth2/production-readiness/restricted-scope-verification).
- Verification / CASA security assessment is only mandatory if the app is distributed publicly and requests restricted scopes at scale; a **single-user personal app can stay unverified in production indefinitely** — unverified third-party apps accessing fewer than 100 users, or apps requesting non-sensitive/only-basic-profile scopes, are exempt from the review pipeline. [When is verification not needed](https://support.google.com/cloud/answer/13464323?hl=en); [Restricted scope verification](https://developers.google.com/identity/protocols/oauth2/production-readiness/restricted-scope-verification).
- CASA cost, if ever triggered: roughly **$500–$4,500** for lighter assurance tiers up to **$15,000–$75,000/year** for full restricted-scope assessments at higher tiers, revalidated annually. [Google CASA overview — Deepstrike](https://deepstrike.io/blog/google-casa-security-assessment-2025); [Google's $15k–$75k OAuth verification — GMass](https://www.gmass.co/blog/google-oauth-verification-security-assessment/). Not relevant at single-user scale.
- **Internal apps** (Google Workspace org only) are fully exempt from the 100-user cap and the unverified-app warning screen, but require the user's Google account to be a Workspace account, not personal Gmail — a personal `@gmail.com` account always counts toward the 100-user limit and always shows the unverified warning. [Additional considerations for Workspace](https://developers.google.com/identity/protocols/oauth2/production-readiness/google-workspace).

**Action item for this project**: create the OAuth client, add the user as a test user initially to develop, then flip consent screen to "In production" before relying on it long-term — this is a one-click Cloud Console change, no Google review needed for a handful of restricted scopes at 1 user.

### MCP servers
Google now ships **official remote MCP servers for Gmail and Calendar** (`developers.google.com/workspace/gmail/api/guides/configure-mcp-server`), usable from Claude/Antigravity with an OAuth client ID/secret as a custom connector. Third-party security scoring site AgentSeal rated the broader "Google Services" MCP integration 75/100 (review recommended, no critical issues) but rated a separate community "Gmail & Calendar MCP Server" only 40/100 (risky, 5 critical/high findings) — **the score is implementation-specific, always verify which exact server binary/repo is being scored**, don't assume "official-sounding name" = safe. [Gmail MCP: Google's server is real, but gated](https://www.usecarly.com/blog/gmail-mcp/); [Google Workspace MCP Server security — Strac](https://www.strac.io/blog/google-workspace-mcp-server). Given this project's threat model (an LLM reading untrusted email content), the official first-party MCP server honors the *user's* full read scope and will return anything visible to that scope, including any injected instructions in email bodies — MCP alone does not solve prompt injection; that has to be handled at the gatekeeper's policy layer regardless of which connector is used.

---

## 2. Google Calendar, Drive/Docs, Contacts

### Calendar
Scopes range from broad (`calendar` — full read/write to all calendars) down to narrow: `calendar.readonly`, `calendar.events.readonly`, `calendar.events` (events only, no calendar settings), `calendar.calendarlist.readonly`, `calendar.events.freebusy` (busy/free only, no event details — good for "can Instinct check if I'm free" without exposing meeting content). [Choose Google Calendar API scopes](https://developers.google.com/workspace/calendar/api/auth). Google ships an official Calendar MCP server too. [Configure the Calendar MCP server](https://developers.google.com/workspace/calendar/api/guides/configure-mcp-server).

### Drive / Docs
`drive.file` is the standout scope here: it's classified **non-sensitive** (no verification burden at all) and only grants access to files the app itself created or that the user explicitly picked via the Drive Picker — the app can never see the rest of the user's Drive. [Drive API scopes guide](https://developers.google.com/workspace/drive/api/guides/api-specific-auth). `drive.readonly` and `drive.metadata.readonly` are **Restricted** scopes requiring the same CASA path as Gmail's restricted scopes if ever distributed publicly (again, irrelevant at single-user scale, but do budget for the unverified-app click-through). Google Docs API doesn't expose a documents-only readonly scope distinct from Drive's; document content access typically rides on `drive.readonly` or the narrower `documents.readonly`-style scope under the Docs API namespace — use `drive.file` wherever the gatekeeper only needs to create/read files it manages itself (e.g., writing an audit-log doc), reserving `drive.readonly` only if it genuinely needs to search the user's whole Drive.

### Contacts (People API)
Key scopes: `contacts.readonly` (read personal contacts), `directory.readonly` (Workspace directory, not relevant for personal use), `userinfo.profile` (own profile only). [People API scopes reference](https://developers.google.com/workspace/guides/configure-mcp-servers). Contacts is a Restricted scope like Gmail/Drive-readonly.

---

## 3. LinkedIn

This is the riskiest connector in the whole project and deserves a blunt walkthrough.

### What the official API actually allows for an individual
LinkedIn's self-serve developer tier (available instantly, no review) covers exactly three things: OpenID Connect sign-in (name/headline/photo/email), and posting on the authenticated member's own behalf (`w_member_social`). **There is no self-serve scope to read your own feed, your own DMs/messages, your own connections list, or anyone else's profile at scale.** Everything beyond that — Marketing Developer Platform, Sales Navigator API, Talent/Recruiter API, Compliance API — requires a formal partner application that LinkedIn can take weeks to approve and is generally gated to companies building recruiting/marketing/sales products, not personal-use tools. [LinkedIn API 2026: A Developer's Reality Check — SocialCrawl](https://www.socialcrawl.dev/blog/linkedin-data-api-2026); [Profile API — Microsoft Learn](https://learn.microsoft.com/en-us/linkedin/shared/integrations/people/profile-api).

**Conclusion: official API cannot deliver what "let the gatekeeper read my LinkedIn notifications/messages" needs.** Everything below is some flavor of unofficial access.

### Unipile and similar unified-API vendors
Unipile (and comparable vendors like Linked API) work by taking your **`li_at` session cookie** (and `li_a` if you have Sales Navigator/Recruiter) directly from your browser and driving your real LinkedIn session server-side through the private Voyager endpoints — this is *not* a LinkedIn-sanctioned integration, it's a managed, commercially-supported wrapper around the same technique the unofficial libraries use. [Unipile LinkedIn link-accounts docs](https://developer.unipile.com/v2.0/docs/linkedin-link-accounts). Pricing: ~€49–55/mo minimum for up to 10 linked accounts, then per-account fees down to ~€3–3.50/account at scale — for a single personal account you're paying the full ~€49-55/mo floor. [Unipile pricing 2026](https://www.unipile.com/pricing-api/). What Unipile buys you over a DIY unofficial library: maintained handling of LinkedIn's 2FA/checkpoint flows, automatic reconnection UX, and someone else's engineering effort absorbing LinkedIn's endpoint changes. **What it does not buy you: any reduction in LinkedIn account ban risk** — the session cookie is still driving your account through unofficial endpoints, still violates LinkedIn's User Agreement, and LinkedIn's automated detection cannot distinguish "Unipile-mediated" traffic from any other bot traffic on the same session.

### Unofficial libraries (`linkedin-api`, Playwright + stored cookies)
The popular `linkedin-api` Python package explicitly hits LinkedIn's internal Voyager API and is documented as violating LinkedIn's User Agreement §8.2; community reports describe LinkedIn rotating token/endpoint formats specifically in response to this library's popularity, and "account restricted after 2 days" reports are common across the various forks. [How to get banned with linkedin-api python — Medium](https://medium.com/@mhmdjmala51/how-to-get-banned-with-linkedin-api-python-c9ecaec93f5e); [LinkedIn Scraping Tools benchmarked by ban risk — Clura](https://clura.ai/blog/linkedin-scraping-tools). Playwright with a saved `storageState` (cookies) is architecturally identical to the Unipile approach minus the vendor — same session, same detectable footprint, plus the operational burden of re-harvesting the session whenever a 2FA/device checkpoint or CAPTCHA fires (checkpoints observed include `2FA`, `OTP`, `IN_APP_VALIDATION`, `CAPTCHA`, `PHONE_REGISTER`). [LinkedIn security verification when signing in — LinkedIn Help](https://www.linkedin.com/help/linkedin/answer/a1339220); [LinkedIn checkpoint types discussion](https://lite.ego.app/article/ai-scraping-login-walls). A stored TOTP secret can auto-clear a 2FA prompt, but CAPTCHA and novel-device checks generally require a human in the loop or break automation outright.

### Data vendors (Proxycurl and similar) — mostly dead
Proxycurl, the best-known LinkedIn-data-enrichment API, was sued by LinkedIn/Microsoft in January 2025 over allegations it ran "hundreds of thousands" of fake accounts to scrape data, and **permanently shut down July 4, 2025** despite $10M ARR. [Proxycurl shutdown coverage — StartupHub](https://www.startuphub.ai/ai-news/startup-news/2025/the-1-linkedin-scraping-startup-proxycurl-shuts-down); [LinkedIn wins legal case against data scrapers](https://www.socialmediatoday.com/news/linkedin-wins-legal-case-data-scrapers-proxycurl/756101/). This follows the earlier hiQ Labs precedent, where a 2022 consent judgment forced hiQ to pay $500k, stop scraping, and destroy all scraped data/code — hiQ ceased to exist. **This is not abstract legal risk; LinkedIn has a demonstrated pattern of successfully litigating scraping vendors out of existence.** Any vendor in this space should be assumed one lawsuit away from disappearing with your data pipeline mid-flight.

### Concrete risk to the user's own account
Be very direct about this, since the brief specifically asks for it:
- **Storing the LinkedIn password** (rather than just a session cookie) is strictly worse — it exposes full account takeover if the credential store is compromised, and offers no functional benefit since none of the above access paths need the password after initial login (Voyager/Unipile-style access all works off the `li_at` cookie). **Never store the password; store only the session cookie, and treat that cookie as equivalent to a live authenticated session (because it is one).**
- LinkedIn's 2026 detection stack does behavioral analysis, device fingerprinting, and IP monitoring; documented thresholds that trigger restriction include >3% of your connection count in daily invites, 200+ connection requests/day, 100+ messages in a few hours, or bulk profile pulls (2,500+ profiles). [LinkedIn automation safety guide 2026 — GetSales](https://getsales.io/blog/linkedin-automation-safety-guide-2026/).
- Outcome is usually **restriction before outright ban** (temporary feature lockout, e.g. no more connection requests for N days), but repeated or severe automation triggers permanent bans. [Will LinkedIn ban you for automation in 2026 — LinkedNav](https://www.linkednav.com/blog/will-linkedin-ban-me-for-using-automation).
- The safest usage pattern for this project, if LinkedIn access is kept at all: **read-only, low-frequency polling of notifications/messages only** (no bulk profile fetching, no auto-connecting, no auto-messaging), ideally via Unipile so 2FA/checkpoint handling is someone else's maintenance burden, with the explicit understanding this is a ToS violation the user is knowingly accepting for their own account.

### MCP servers
No official LinkedIn MCP server exists. Community servers vary wildly in what they actually do under the hood — some use the official (narrow) API, some scrape via headless browser with stored cookies. AgentSeal's scoring illustrates the spread: `stickerdaniel/linkedin-mcp-server` (browser-automation/scraping) scored 93/100 for code quality but is explicitly built on cookie-based scraping (ToS violation, account risk inherent to the approach regardless of code quality); a `linkedapi` MCP wrapper scored only 40/100 (risky, findings present); `souravdasbiswas/linkedin-mcp-server`, which sticks to the official narrow API, carries no scraping/account risk but also can't do the things this project wants. [LinkedIn MCP servers compared — Taplio](https://taplio.com/blog/linkedin-mcp-github); [souravdasbiswas/linkedin-mcp-server (official API only)](https://github.com/souravdasbiswas/linkedin-mcp-server); [stickerdaniel/linkedin-mcp-server (scraping)](https://github.com/stickerdaniel/linkedin-mcp-server). **Do not casually plug in a community LinkedIn MCP server** — read its source to confirm whether it's driving a live session with your cookie (account risk) before trusting it with credentials, and never commit the `li_at` cookie to a repo (documented incidents of exactly this happening, with sessions remaining valid for weeks).

---

## 4. WhatsApp

### Cloud API (official) — built for business numbers, not personal history
The WhatsApp Business On-Premises API was fully sunset October 23, 2025; Meta's Cloud API is now the only supported official path. [WhatsApp Developer News 2026](https://whatsapp.checkleaked.cc/blog/whatsapp-developer-news-2026). It requires a **business-verified phone number**, and reading pre-existing chat history is limited: "Coexistence mode" lets a WhatsApp Business App number also run through the Cloud API on the same number, replaying **up to 6 months** of that number's existing chat history to your webhook on onboarding, after which everything is real-time-capture-only going forward. [WhatsApp Coexistence explained 2026 — ChakraHQ](https://chakrahq.com/article/whatsapp-business-app-api-coexistence-202/). Critically: **you cannot put a personal WhatsApp account into coexistence mode** — the number must first be converted to a WhatsApp Business App number, the WhatsApp Business app is mandatory, and the app must be opened at least once every 14 days to keep the API connection alive. Throughput on a coexistence number is capped at 20 msg/sec. This product is designed for a business owner who wants automation layered on top of their existing customer-facing WhatsApp Business number — not for reading a personal user's regular chats with friends/family.

Ban risk on the Cloud API itself is near-zero if used within Meta's policy (opt-in, approved templates, quality rating maintained) — but that's moot here since it doesn't solve the actual use case.

### Unofficial libraries (Baileys, whatsapp-web.js)
These reverse-engineer the multi-device WhatsApp Web protocol to give full read/write access to a personal account's existing chats — this is the only path that matches "read my own WhatsApp chats" literally. Real-world ban data is grim: sources report roughly **68% of businesses using unofficial WhatsApp automation report at least one ban within 12 months**, and any proactive/outbound messaging particularly increases detection risk; purely passive reading is somewhat lower-risk but still runs on an unsupported, actively-detected protocol implementation that can break or trigger a ban with any Meta-side change. [WhatsApp Cloud API vs Unofficial Libraries](https://whatsapp.checkleaked.cc/blog/whatsapp-cloud-api-vs-unofficial).

### Recommendation — reframe the requirement
Per the project brief, **Instinct already is the WhatsApp surface** (the user talks to Instinct over WhatsApp; Instinct is the thing that currently needs — and is being stripped of — direct data access). The gatekeeper's job is to receive Instinct's *requests* over **email**, not to independently operate WhatsApp. Unless there's a concrete scenario where the gatekeeper itself needs to read/send WhatsApp messages Instinct can't see, **this project likely doesn't need a WhatsApp connector at all** — flagging this explicitly as an open question rather than assuming it's in scope, since building one means taking on Baileys/whatsapp-web.js-grade ban risk against the user's real personal number for a capability that may be redundant with what Instinct already has.

---

## 5. Other sources (brief)

| Source | Official API | Auth | Risk notes |
|---|---|---|---|
| **Outlook / Microsoft 365** | Microsoft Graph, mature and well-scoped | Delegated `Mail.Read`, `Mail.Send`, `Mail.ReadWrite`; works against personal Microsoft accounts, not just org tenants. [Graph permissions reference](https://learn.microsoft.com/en-us/graph/permissions-reference) | Low risk, straightforward OAuth, no 7-day-token trap like Google's testing mode |
| **Slack** | Official Web API, excellent scoping | Bot tokens (`xoxb-`) vs user tokens (`xoxp-`) are architecturally different: a bot only sees channels it's invited to and DMs sent to it; `channels:history` + `chat:write` cover read/write to public channels. [Bot vs user tokens — Slack Developers](https://slack.dev/two-keys-to-one-platform-understanding-bot-and-user-tokens/) | Low risk; prefer bot token scoped to a dedicated channel over a user token that impersonates the human |
| **Notion** | Official API, integration tokens (PATs) | One token per workspace, scoped to pages/databases explicitly shared with the integration | Low risk, but "shared with integration" is opt-in per page — remember to share the pages the gatekeeper needs |
| **GitHub** | Official REST/GraphQL API | Fine-grained PATs: up to 64 permission types, 50 tokens/user, max 366-day expiry — force periodic rotation by design. [Fine-grained PAT docs](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens) | Low risk, good scoping primitives; prefer fine-grained over classic PATs |
| **Bank / financial (Plaid etc.)** | Plaid and similar aggregators are SOC2/ISO27001-certified and reasonably secure | OAuth-like Link flow, stores bank credentials at the aggregator, issues long-lived access tokens to your app | **Recommend against** integrating this into a prompt-injection-exposed LLM agent. Even setting aside Plaid's own security posture, giving an LLM-driven agent (however sandboxed) any path to financial account data or the ability to reason about/move money is a different risk class than email/calendar; if ever added, it should be strictly read-only, heavily rate-limited, and arguably kept entirely outside the gatekeeper's LLM loop (a hardcoded, non-agentic read path only) |
| **X / Twitter** | API v2, pay-per-use as of 2026: $0.015/post write, $0.005/post read, 2M reads/mo cap on pay-per-use; free tier discontinued for new developers except case-by-case "public good" grants | Standard OAuth2 | Low technical risk, real cost risk if usage isn't capped; low priority given the user's stated stack (Gmail/Calendar/LinkedIn/WhatsApp) |

---

## 6. Unified-API vendors — comparison

| Vendor | Model | Self-hostable | Relevant coverage | Notable risk |
|---|---|---|---|---|
| **Unipile** | Per-account monthly fee (~€49-55/mo floor), unified REST+webhooks over LinkedIn/WhatsApp/Gmail/Outlook/IMAP/Instagram/Telegram/Calendar | No — hosted SaaS only | Best coverage of LinkedIn + WhatsApp + email in one API; abstracts LinkedIn's checkpoint flows | LinkedIn/WhatsApp access here is still unofficial-session-driven underneath; your session cookies live on Unipile's infrastructure |
| **Nango** | Open-source core (Elastic License 2.0), 900+ integrations, code-first | **Yes** — free self-hosted edition (Docker Compose: Postgres + Redis + server) for auth/token-vault + proxy; enterprise self-host for full platform | Broad general SaaS coverage (Gmail, Calendar, Slack, Notion, GitHub etc.) via OAuth; no special LinkedIn/WhatsApp handling | Best fit if "self-hosted, I hold the keys" matters — this is the one vendor on the list that actually satisfies this project's own stated threat model |
| **Composio** | Hosted, 1,000+ integrations, delegated auth, sandboxed tool execution | No | Broad coverage, agent-native tool-calling design | **Breached May 2026**: a compromised employee Gmail OAuth token cascaded into ~5,241 API keys + ~5,001 GitHub OAuth tokens exfiltrated across customers. [Composio breach — Material Security](https://material.security/resources/the-composio-breach-one-token-10242-doors) — concrete evidence that centralizing many users' third-party credentials at one hosted vendor is a real, exploited attack surface |
| **Pipedream Connect** | Low-code, large prebuilt action library, per-app MCP server | No | Broad coverage, no data-sync/RAG support | Same hosted-custody concerns as Composio, no known breach reported as of this writing |
| **Merge** | Unified data model per category (HRIS, ATS, CRM etc.), managed sync | No | Not really aimed at this project's consumer-app use case (Gmail/LinkedIn/WhatsApp) — more B2B SaaS categories | Not a good fit here |
| **Arcade.dev** | Lightweight, stateless, MCP-native tool calling and auth orchestration | No | No data sync/webhook support, thinner feature set | Newer, less battle-tested than the above |

**Takeaway**: given the project's explicit goal of minimizing blast radius, **Nango self-hosted** is the only unified-API option that doesn't reintroduce a third-party custody problem — worth using purely for its OAuth-flow/token-refresh plumbing on the Google/Slack/Notion/GitHub side, while keeping LinkedIn on a separate, more careful path (direct Unipile relationship only if the user accepts that specific vendor's custody of the LinkedIn cookie, or DIY Playwright if they don't want any vendor touching it).

---

## 7. Credential storage

### Options compared
| Option | Self-hosted? | License | Fit for this project |
|---|---|---|---|
| Plain env vars / `.env` files | N/A | — | Fine for local dev only; no encryption at rest, no audit trail, no rotation — don't use in production |
| **SOPS + age** | Yes, no server at all | Open source (Mozilla/community) | Strong fit: encrypted secrets committed to a private git repo, decrypted only where the age private key lives (disk, or a hardware key via `age-plugin-yubikey`); no daemon, no vendor, no network dependency to decrypt. [SOPS + age guide](https://www.jonashietala.se/blog/2026/05/31/sops_age_and_sealed_secrets/); [age-plugin-yubikey](https://esli.blog.br/beyond-gpg-hardware-backed-file-encryption-with-age-and-yubikey) |
| **Doppler** | **No** — managed SaaS only, not open source | Proprietary | Fastest onboarding but rules itself out if "no third party ever sees my raw secrets" matters |
| **Infisical** | Yes — Docker Compose / Helm, well documented | MIT | Strong fit: full audit logging, dynamic secrets, a real UI/API for a growing number of connectors, and it's actually open source so it can be audited/forked |
| **HashiCorp Vault** | Yes | Business Source License (not fully open source since 2023) | Most powerful (dynamic secrets, PKI, fine-grained policy) but heavier operational burden than this project needs for a single user |
| **1Password Connect / Service Accounts** | Connect server: self-hosted, caches decrypted secrets locally for HA; Service Accounts: no infra needed, lighter weight | Proprietary (built on 1Password subscription) | Good if the user already lives in 1Password day-to-day; Connect gives a local decrypting proxy so raw secrets don't round-trip to 1Password's cloud on every read. [1Password Secrets Automation](https://developer.1password.com/docs/secrets-automation/) |
| **Bitwarden Secrets Manager** | Yes (Bitwarden is fully open source and self-hostable) | Open source (server), proprietary cloud option too | Reasonable if already on Bitwarden; newer/less mature feature set than Vault/Infisical for secrets specifically |
| **Cloud KMS / Secret Manager** (AWS Secrets Manager, GCP Secret Manager) | No — tied to that cloud | Proprietary | Fine if already deploying on that cloud; adds a cloud-vendor dependency |
| **Hardware key / TPM** (YubiKey via `age-plugin-yubikey`) | Yes, local | — | Best-in-class protection for the *root* key that decrypts everything else — every decrypt requires a physical touch, which specifically defeats "malware silently exfiltrates all secrets" scenarios. Pair this with SOPS+age as the actual secrets-at-rest layer rather than treating it as a standalone secrets manager |

### Recommendation
For a self-hosted, single-user gatekeeper: **SOPS + age, with the age private key protected by a YubiKey** (`age-plugin-yubikey`), secrets committed encrypted to the gatekeeper's own private repo. This has zero third-party custody, zero recurring cost, and a physical-touch requirement on every decrypt. If a nicer UI/audit trail is wanted later, layer in self-hosted **Infisical** — it's MIT-licensed, so it doesn't reintroduce the "vendor holds my secrets" problem, and it adds real access logging, which the project's "auditability" requirement benefits from.

### Per-capability credential isolation
Run each connector (Gmail, Calendar, LinkedIn, gatekeeper's own mailbox) as a **separate OS process or container**, each injected with only its own decrypted credential at startup, communicating with the orchestrating LLM loop over a narrow RPC/tool-call boundary (e.g., stdio, a local Unix socket, or an MCP server per connector). Concretely:
- A "LinkedIn worker" process holds the `li_at` cookie and exposes only high-level operations (`get_notifications()`, `get_unread_messages()`) — the orchestrating LLM never sees the raw cookie and cannot use it to construct arbitrary Voyager API calls even if an injected prompt tries to convince it to.
- A "Gmail worker" process holds the Gmail OAuth refresh token, similarly scoped.
- This directly mitigates the Composio-breach failure mode: a single compromised OAuth token in one worker cannot be pivoted into every other connector's credentials, because they're never co-located in the same process memory or the same token store the LLM can reach.
- Combine with the principle of minimal scopes from sections 1–2 above: even *within* one worker, request `gmail.send`-only for the outbound-to-Instinct channel rather than `gmail.modify`, if the gatekeeper's reply path never needs to read.

### Kill-switch playbook (revoke everything within 5 minutes)
| Credential | Revoke path | Time |
|---|---|---|
| Google OAuth (Gmail/Calendar/Drive/Contacts) | `myaccount.google.com/connections` → click the app → **Remove access** → Confirm. Token is invalidated immediately server-side; a stolen refresh token stops working the instant this is clicked. [How to revoke Google OAuth access](https://email-unsubscriber.com/blog/revoke-google-account-app-access) | <1 min |
| LinkedIn session cookie (`li_at`) | Log into linkedin.com → Settings & Privacy → Sign in & security → **Where you're signed in** → sign out of the suspicious/unrecognized session (or sign out of all sessions). This invalidates the `li_at` cookie the gatekeeper/Unipile was using. If password may be compromised too, change the password (invalidates all sessions) | 1–2 min |
| WhatsApp (if ever wired up) | On the phone: Settings → Linked Devices → tap the device → **Log out**, or **Log out from all devices**. No universal single button on all versions; review the device list. [WhatsApp linked devices logout](https://anycontrol.app/blog/post/log-out-of-whatsapp-active-sessions-on-all-devices) | 1–2 min |
| Microsoft Graph (Outlook) | Azure AD / Microsoft account → Apps and services → find the app → Remove | <1 min |
| Slack token | Slack admin → App Management → Installed apps → Remove/Uninstall app (invalidates the bot/user token) | <1 min |
| GitHub fine-grained PAT | GitHub → Settings → Developer settings → Personal access tokens → **Delete** | <1 min |
| Vendor-held credentials (Unipile, Nango cloud, etc.) | Vendor dashboard → disconnect the linked account; additionally rotate/revoke on the underlying provider (LinkedIn session sign-out, Google OAuth revoke) since the vendor's disconnect alone doesn't always invalidate the upstream session | 2–5 min |
| Gatekeeper's own secrets store | If SOPS+age: revoke the YubiKey/rotate the age key and re-encrypt; if Infisical: rotate/delete the affected secret and force re-fetch | Varies — pre-stage this so a full secrets rotation is a single scripted command, not a manual walk of every file |

**Practical advice**: pre-build a single `./kill-switch.sh` (or equivalent) that (1) calls each connector's programmatic revoke where an API exists (Google's token revoke endpoint, GitHub's token delete API, Slack app uninstall API), and (2) prints the manual steps above for the ones without a revoke API (LinkedIn, WhatsApp) — since those require clicking through the provider's own UI, a script can only shorten the list, not fully automate it.

---

## 8. The gatekeeper's own inbox

| Option | Setup effort | Cost | What the app sees (DKIM/SPF exposure) | Deliverability | Push vs poll | Threading | Custom domain sender verification |
|---|---|---|---|---|---|---|---|
| **New Gmail account + Gmail API** | Medium — full OAuth app setup, same 7-day-testing-mode trap as section 1 | Free | Gatekeeper only sees what the Gmail API returns (fully parsed, no raw MIME/DKIM handling needed) | Excellent (Gmail's own deliverability) | Push via Pub/Sub or poll, same as any Gmail integration | Native Gmail threading (`threadId`) | Yes, via standard Gmail SPF/DKIM if Instinct sends through a real domain; if Instinct sends via its own provider, alignment depends on Instinct's setup, not this app's |
| **Google Workspace alias/account** | Medium-high — needs a paid Workspace subscription | ~$6-12/user/mo | Same as above, plus can go **internal** OAuth app (no unverified warning, no 100-user cap) | Excellent | Same as Gmail API | Native | Yes, full domain control |
| **AgentMail (agentmail.to)** | **Low** — purpose-built for exactly this (agent inbox, threading, webhooks/websockets, reply-preserving-thread API) | Free tier: 3 inboxes, 3,000 emails/mo, no card; usage-based beyond that | Full raw MIME parsed to structured messages; AgentMail's infra handles inbound auth checks | Good (Y Combinator-backed infra, still relatively new vendor — less of a deliverability track record than Google/AWS) | Real-time webhooks/websockets, no polling needed | Native, purpose-built (it's the one item in this whole comparison specifically designed around "thread as a persistent object") | Custom domain support exists per their docs; verify current domain-verification flow before committing |
| **Cloudflare Email Routing + Workers** | Medium — free but you write the Worker: parse with `postal-mime`, handle SPF/DKIM pass/fail logic yourself, wire up storage/threading | Free (Cloudflare Workers free tier covers light traffic) | Full raw MIME (`message.raw`) available in the Worker — you see everything including headers, so you control SPF/DKIM policy directly; Cloudflare requires either SPF pass or valid DKIM before accepting mail, rejects if both fail. [Cloudflare Email Routing setup](https://developers.cloudflare.com/email-routing/) | Good, Cloudflare's own infra | Push (Worker invoked per inbound email) | You build it yourself (no native thread object) | Yes — full control since it's your domain's MX/DNS on Cloudflare |
| **Postmark inbound webhook** | Low-medium — one webhook endpoint, clean parsed payload | Paid (transactional email pricing) | Parsed webhook payload, good developer ergonomics | Excellent, best-in-class deliverability reputation | Push (webhook) | You build it | Yes |
| **SendGrid Inbound Parse** | Low-medium | Free tier + paid tiers (Twilio) | Parsed webhook payload | Good, broad ecosystem | Push (webhook) | You build it | Yes |
| **Mailgun Routes** | Medium — supports complex per-recipient routing rules (regex on sender/subject/recipient) | Paid | Parsed, most flexible routing logic of the bunch | Good | Push (webhook) | You build it | Yes |
| **Resend inbound** | Low, but inbound capability is comparatively limited/newer, not built for multi-tenant thread-heavy use | Paid | Parsed | Good (modern, developer-friendly) | Push (webhook) | Limited | Yes |
| **AWS SES inbound + Lambda** | High — no inbox object at all; raw MIME lands in S3/SNS/Lambda and you build storage, parsing, threading, search entirely yourself | Very cheap at low volume (pay-per-message + S3/Lambda costs, likely cents/month) | You see 100% raw MIME, full control, but 100% of the parsing/threading burden too | Good if SES sending reputation is warmed up properly | Push (Lambda trigger) | You build it entirely | Yes, full control via Route53/SES domain verification |
| **Fastmail (JMAP)** | Low-medium — JMAP is a clean modern API, less agent-specific tooling than AgentMail | ~$3-9/mo | Full mailbox access via JMAP, parsed | Excellent | JMAP supports push via `EventSource`/webhooks | Native JMAP threading | Yes, standard domain verification |
| **Self-hosted IMAP** (e.g., on the same box as the gatekeeper) | High — own mail server (Postfix/Dovecot), or thinnest option: rent a mailbox and just poll IMAP | Low (VPS cost) if self-hosted; near-zero if just IMAP-polling an existing mailbox | Full access, but running your own SMTP-receiving server invites its own deliverability/spam-reputation problems from scratch | Poor if self-hosting the SMTP server from a fresh domain (cold IP/domain reputation); fine if just IMAP-polling an established mailbox | Poll only (IMAP IDLE gives near-push but still polling-shaped) | Manual, via `References`/`In-Reply-To` headers | Only if you also self-host the sending side and warm up reputation — real effort |

**Recommendation for MVP**: **AgentMail** for fastest time-to-working-loop (free tier covers a single-user gatekeeper comfortably, and threading/reply-preservation is exactly the primitive this project's "email thread = audit log" design needs out of the box). If the user later wants zero third-party mail infra in the loop, **Cloudflare Email Routing + Workers** is the best self-hosted-feeling fallback — free, full control over parsing/threading logic, and the user already appears comfortable in a Cloudflare-adjacent stack based on session context (multiple Cloudflare skills available). Whichever is chosen, this is a *second* mailbox distinct from the user's real Gmail — don't reuse the same Google OAuth app/credentials for "gatekeeper's own inbox" and "reads the user's real Gmail," to keep the two blast radii separate per the per-capability isolation principle above.

---

## 9. Recommended MVP connector stack (Gmail + Calendar + LinkedIn)

| Connector | Recommended approach | Why |
|---|---|---|
| Gmail (user's real inbox) | Direct Google OAuth, `gmail.modify` scope, consent screen flipped to "In production" (unverified, single user) to dodge the 7-day token trap; Pub/Sub push or a simple poll loop | Official, well-scoped, no vendor custody; the 7-day trap is avoidable with a one-time config change |
| Google Calendar | Direct Google OAuth, `calendar.events` or `calendar.events.readonly` depending on whether write is needed, same OAuth client as Gmail (can share a consent screen since it's all Google) | Same reasoning as Gmail |
| LinkedIn | **Start with nothing automated.** If truly needed, use Unipile with a dedicated read-only usage pattern (notifications/DM digest only, no writes), explicit user sign-off on ToS risk, and treat the `li_at` cookie as a live-session secret with the same isolation as the Gmail token — never in the same process/store | No official path exists; every alternative carries real account risk. Minimize scope and frequency rather than trying to eliminate risk entirely, since elimination isn't on the table without LinkedIn partner-level access this project won't qualify for |
| Gatekeeper's own inbox | AgentMail (MVP) or Cloudflare Email Routing (fallback) | Fast, threading built-in, keeps the "audit log = email thread" design cheap to build |
| Credential storage | SOPS + age (YubiKey-backed), per-connector process isolation | No third-party custody, physical-touch protection on decrypt, Composio-style breach is structurally harder |

### Pros/cons snapshot
- **Pros**: every official-API connector (Gmail, Calendar) is well-scoped, well-documented, and free; the one genuinely hard connector (LinkedIn) is isolated to its own worker with minimal blast radius; credential storage has no SaaS vendor in the critical path.
- **Cons**: LinkedIn access remains a standing ToS violation with real account risk no matter which technical path is chosen — this is a business/risk decision for the user, not something engineering can fully de-risk; Google's unverified-app warning screen requires a one-time manual click-through that could confuse a future re-auth flow; AgentMail is a newer/smaller vendor than Google/AWS, worth revisiting deliverability track record before fully committing long-term.

---

## Open questions for the user

1. **Is a WhatsApp connector actually needed on the gatekeeper side**, given Instinct already owns the WhatsApp surface? If yes, what's the concrete scenario (e.g., "gatekeeper needs to read a WhatsApp group Instinct doesn't have access to")?
2. **How much LinkedIn risk are you willing to accept?** Options range from "no LinkedIn automation at all" (safest) → "read-only digest via Unipile" (moderate risk, real cost) → "full read/write via unofficial library" (highest risk, cheapest). This needs an explicit choice, not a default.
3. **Personal Gmail or move to Google Workspace?** Workspace ($6-12/mo) buys an *internal* OAuth app with no unverified-warning screen and no 100-user cap — worth it only if the unverified-app click-through is a real annoyance or if there's a plan to eventually add more Google-account users.
4. Are Outlook, Slack, Notion, GitHub, or X actually in scope, or were they included in the brief just for completeness? Each is low-risk to add but adds OAuth-lifecycle surface to maintain.
5. Is bank/financial data genuinely wanted here? Recommend explicitly deferring this — it's a different risk class than the rest of the stack and probably shouldn't be reachable by the same LLM loop that's also parsing injected email content.
6. For the gatekeeper's own inbox: is "the user never has to think about it" (AgentMail, managed) preferred over "the user owns 100% of the infra" (Cloudflare Workers, self-built)? This is a build-effort-vs-control tradeoff worth deciding explicitly before implementation starts.

---

## Sources

- [Gmail API Scopes Explained — Unipile](https://www.unipile.com/gmail-api-scopes-guide/)
- [Gmail API Scopes Reference — EmailEngine](https://learn.emailengine.app/docs/accounts/gmail/gmail-api-scopes)
- [Google OAuth Refresh Token: Expiration & 7-Day Limit — Unipile](https://www.unipile.com/google-oauth-refresh-token/)
- [Manage App Audience — Google Cloud Platform Console Help](https://support.google.com/cloud/answer/15549945?hl=en)
- [Restricted scope verification — Google for Developers](https://developers.google.com/identity/protocols/oauth2/production-readiness/restricted-scope-verification)
- [When is verification not needed — Google Cloud Platform Console Help](https://support.google.com/cloud/answer/13464323?hl=en)
- [Google CASA — Cloud Application Security Assessment 2026 — Deepstrike](https://deepstrike.io/blog/google-casa-security-assessment-2025)
- [Google's $15,000-$75,000 OAuth verification process — GMass](https://www.gmass.co/blog/google-oauth-verification-security-assessment/)
- [Additional considerations for Google Workspace — Google for Developers](https://developers.google.com/identity/protocols/oauth2/production-readiness/google-workspace)
- [Configure push notifications in Gmail API — Google for Developers](https://developers.google.com/workspace/gmail/api/guides/push)
- [Gmail API Push Notifications: Pub/Sub, Watch & History — Unipile](https://www.unipile.com/gmail-api-push-notifications/)
- [Choose Google Calendar API scopes — Google for Developers](https://developers.google.com/workspace/calendar/api/auth)
- [Choose Google Drive API scopes — Google for Developers](https://developers.google.com/workspace/drive/api/guides/api-specific-auth)
- [Configure the Google Workspace MCP servers — Google for Developers](https://developers.google.com/workspace/guides/configure-mcp-servers)
- [Gmail MCP: Google's Server Is Real, but Gated — usecarly](https://www.usecarly.com/blog/gmail-mcp/)
- [Google Workspace MCP Server: Setup & Security Risks — Strac](https://www.strac.io/blog/google-workspace-mcp-server)
- [LinkedIn API in 2026: A Developer's Reality Check — SocialCrawl](https://www.socialcrawl.dev/blog/linkedin-data-api-2026)
- [Profile API — LinkedIn — Microsoft Learn](https://learn.microsoft.com/en-us/linkedin/shared/integrations/people/profile-api)
- [Link accounts — Unipile Getting Started](https://developer.unipile.com/v2.0/docs/linkedin-link-accounts)
- [How LinkedIn API Pricing Works — Unipile](https://www.unipile.com/how-linkedin-api-pricing-works/)
- [Unipile API Pricing](https://www.unipile.com/pricing-api/)
- [How to get banned with linkedin-api python — Medium](https://medium.com/@mhmdjmala51/how-to-get-banned-with-linkedin-api-python-c9ecaec93f5e)
- [LinkedIn Scraping Tools: Benchmarked by Block Rate and Ban Risk — Clura](https://clura.ai/blog/linkedin-scraping-tools)
- [The #1 LinkedIn Scraping Startup Proxycurl Shuts Down — StartupHub](https://www.startuphub.ai/ai-news/startup-news/2025/the-1-linkedin-scraping-startup-proxycurl-shuts-down)
- [LinkedIn Wins Legal Case Against Data Scrapers — Social Media Today](https://www.socialmediatoday.com/news/linkedin-wins-legal-case-data-scrapers-proxycurl/756101/)
- [LinkedIn automation safety guide 2026 — GetSales](https://getsales.io/blog/linkedin-automation-safety-guide-2026/)
- [Will LinkedIn Ban You for Automation in 2026 — LinkedNav](https://www.linkednav.com/blog/will-linkedin-ban-me-for-using-automation)
- [Security verification when signing in — LinkedIn Help](https://www.linkedin.com/help/linkedin/answer/a1339220)
- [AI Scraping Behind Login Walls: X and LinkedIn — ego](https://lite.ego.app/article/ai-scraping-login-walls)
- [LinkedIn MCP on GitHub: Open-Source Servers Compared — Taplio](https://taplio.com/blog/linkedin-mcp-github)
- [souravdasbiswas/linkedin-mcp-server (GitHub, official API)](https://github.com/souravdasbiswas/linkedin-mcp-server)
- [stickerdaniel/linkedin-mcp-server (GitHub, browser scraping)](https://github.com/stickerdaniel/linkedin-mcp-server)
- [WhatsApp Developer News 2026 — Checkleaked](https://whatsapp.checkleaked.cc/blog/whatsapp-developer-news-2026)
- [WhatsApp Coexistence Explained 2026 — ChakraHQ](https://chakrahq.com/article/whatsapp-business-app-api-coexistence-202/)
- [WhatsApp Cloud API vs Unofficial Libraries Compared — Checkleaked](https://whatsapp.checkleaked.cc/blog/whatsapp-cloud-api-vs-unofficial)
- [WhatsApp Bot Banned in 2026? 12 Fixes from 50+ Cases — Achiya](https://achiya-automation.com/en/blog/whatsapp-spam-detection-2026/)
- [How to Log Out of WhatsApp on All Devices — AnyControl](https://anycontrol.app/blog/post/log-out-of-whatsapp-active-sessions-on-all-devices)
- [Microsoft Graph permissions reference — Microsoft Learn](https://learn.microsoft.com/en-us/graph/permissions-reference)
- [Bot and user tokens explained — Slack Developers](https://slack.dev/two-keys-to-one-platform-understanding-bot-and-user-tokens/)
- [Managing your personal access tokens — GitHub Docs](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens)
- [Personal access tokens — Notion Docs](https://developers.notion.com/guides/get-started/personal-access-tokens)
- [Is Plaid Safe? — Security.org](https://www.security.org/digital-safety/is-plaid-safe/)
- [X (Twitter) API Pricing in 2026 — Postproxy](https://postproxy.dev/blog/x-api-pricing-2026/)
- [Best unified API platform for AI agents & RAG in 2026 — Nango Blog](https://nango.dev/blog/best-unified-api-platform-for-ai-agents-and-rag/)
- [Pipes compared to Nango, Composio, Arcade, Paragon, and Merge — WorkOS](https://workos.com/blog/pipes-vs-nango-composio-arcade-paragon-and-merge)
- [GitHub - NangoHQ/nango](https://github.com/nangohq/nango)
- [Self-host Nango — Nango Docs](https://nango.dev/docs/guides/platform/self-hosting)
- [The Composio Breach: One Token, 10K Doors — Material Security](https://material.security/resources/the-composio-breach-one-token-10242-doors)
- [Composio Security Incident: What Happened — Metorial](https://metorial.com/blog/composio-security-incident-mcp-security)
- [Update on Exposed MCP Servers — Trend Micro](https://www.trendmicro.com/vinfo/us/security/news/vulnerabilities-and-exploits/update-on-exposed-mcp-servers-the-threat-widens-to-the-cloud)
- [The Best Secrets Management Tools in 2026 — Infisical](https://infisical.com/blog/best-secret-management-tools)
- [HashiCorp Vault vs AWS, Doppler, Infisical, Azure — guptadeepak.com](https://guptadeepak.com/top-5-secrets-management-tools-hashicorp-vault-aws-doppler-infisical-and-azure-key-vault-compared/)
- [How to Use SOPS with Age Encryption — OneUptime](https://oneuptime.com/blog/post/2026-02-09-sops-age-encryption-kubernetes-secrets/view)
- [Commit Your Secrets to Git, Encrypted, with SOPS and age](https://tvi.al/commit-your-secrets-to-git-encrypted-with-sops-and-age/)
- [1Password Secrets Automation — 1Password Developer](https://developer.1password.com/docs/secrets-automation/)
- [Beyond GPG: Hardware-Backed File Encryption with age and YubiKey](https://esli.blog.br/beyond-gpg-hardware-backed-file-encryption-with-age-and-yubikey)
- [How to revoke third-party app access to your Google account](https://email-unsubscriber.com/blog/revoke-google-account-app-access)
- [AgentMail — Email Inbox API for AI Agents](https://www.agentmail.to/)
- [Best Email APIs for Receiving and Parsing Replies in AI Agents (2026) — AgentMail](https://www.agentmail.to/blog/best-inbound-email-apis-ai-agents)
- [AgentMail vs Amazon SES for AI Agents (2026) — AgentMail](https://www.agentmail.to/blog/agentmail-vs-amazon-ses)
- [Cloudflare Email Routing docs](https://developers.cloudflare.com/email-routing/)
- [Email agent — Cloudflare Agents docs](https://developers.cloudflare.com/agents/examples/email-agent/)
- [Resend vs Postmark vs Mailgun for Solo Developers in 2026 — DEV Community](https://dev.to/devtoolpicks/resend-vs-postmark-vs-mailgun-for-solo-developers-in-2026-5gfl)
- [Best Inbound Email Notification APIs in 2026 — Pingram](https://www.pingram.io/blog/best-inbound-email-notification-apis)
