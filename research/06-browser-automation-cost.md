# 06 — Browser automation for sites without an API (saved for later)

*Status: parked. The MVP is Google-only (see README "Decided"). Written 2026-09-14 by the
orchestrator from the user Q&A; current tool pricing/features are NOT yet verified.*

## Question
LinkedIn (and other sites) have no official API for personal data. Does that mean "computer
use", and how do we keep it affordable?

## Answer: browser automation, yes. Screenshot-driven "computer use", mostly no.

| Tier | How it works | LLM cost per task | Fragility |
|---|---|---|---|
| **0. Notification emails** | LinkedIn and most sites email you about messages, invites and mentions. Read them through the Gmail API the gatekeeper already has | ~$0 | Low (but often only a preview of the content) |
| **1. Scripted Playwright** | Fixed code per verb, using a saved session cookie (never the password); no LLM drives the browser | ~$0 (LLM only summarizes the output, quarantined) | Breaks when the site layout changes |
| **2. AI-authored, cached scripts** | An LLM figures out the steps once and they're cached as a script (e.g. Stagehand / browser-use caching); the LLM is called again only when a step fails | ~$0 per normal run | Self-healing |
| **3. Full computer use** | Screenshot → model picks an action → repeat | ~$0.20–0.50/task* | Most adaptive |

\*Estimate: a 1280×800 screenshot ≈ 1.4k tokens (px/750); 15–30 steps with a growing context;
Sonnet 5 $2/$10 per MTok ≈ $0.40/task, Haiku 4.5 ≈ half. 20 tasks/day ≈ $5–10/mo in LLM
cost alone. Sending the page as text (DOM / accessibility tree) is not automatically cheaper:
a LinkedIn page can be 10–20k tokens. **The savings come from taking the LLM out of the
step-by-step loop.**

## Security alignment
Cheap and safe point the same way. A computer-use agent that is logged into LinkedIn and reads
an injected DM can act on it. Fixed per-verb scripts can't go outside their script, and the LLM
only sees the extracted text, with no tools. This matches the action-selector design in 03.

## Plan when we get to it
1. Tier 0 first: answer "what's new on LinkedIn" from the notification emails in Gmail.
2. Tier 1 for read-only verbs (`linkedin.get_unread_messages`, `linkedin.get_profile(url)`).
3. Tier 2 later, to self-heal selector breakage.
4. Tier 3 only for rare one-offs, and each one needs push approval first.

## Account safety ("for my own use" ≠ safe; LinkedIn judges behavior, not purpose)
- Low volume, read-only first. Automated sending and connecting gets accounts restricted.
- A real Chrome profile (not a bare headless browser) on the user's **usual residential IP**.
  A login from a datacenter IP in another country triggers checkpoints, which argues for
  running the browser worker on a home machine behind a Cloudflare Tunnel rather than on
  the VPS.
- Store only the `li_at` session cookie, in its own isolated worker process (see 04).

## To verify before building
Current pricing and features of Stagehand, browser-use, Playwright MCP, and the Anthropic/OpenAI
computer-use tools, and LinkedIn notification-email content (full text vs. preview).
