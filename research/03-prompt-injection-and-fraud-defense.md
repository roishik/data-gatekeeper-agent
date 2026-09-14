# 03 — Prompt Injection & Fraud Defense: A Defense-in-Depth Design Survey

*Research only — no implementation. Companion to `00-brief.md`. Written 2026-09-14.*

## Executive summary

Prompt injection is **not a solved problem** as of late 2026, and the strongest recent academic result — "The Attacker Moves Second" (Oct 2025) — showed that 12 prominent published defenses all fall to adaptive attackers, with success rates over 90% in most cases, and a $20k-prize human red-team defeating every defense tested ([arXiv:2510.09023](https://arxiv.org/abs/2510.09023), via [Simon Willison](https://simonwillison.net/2025/Nov/2/new-prompt-injection-papers/)). Classifiers (Prompt Guard, Lakera, Prompt Shields, Model Armor) reduce risk but are **probabilistic filters, not guarantees** — treat them as one layer, never the only layer.

The gatekeeper design in `00-brief.md` sits squarely in what Simon Willison calls the **"lethal trifecta"**: it will (1) hold private data access (Gmail OAuth, LinkedIn credentials), (2) be exposed to untrusted content (the body of every inbound email, and the content of every Gmail/LinkedIn message it's asked to read), and (3) have the ability to communicate externally (send email replies, post to LinkedIn) ([simonwillison.net/2025/Jun/16](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/)). All three legs are required for the system to do its job, so the trifecta **cannot be architected away** — it has to be defused with hard boundaries: deny-by-default authorization, capability-scoped actions, data-flow isolation between "reading untrusted text" and "deciding what to do," and human approval on the highest-risk operations. This maps directly onto Meta's **Agents Rule of Two** (Oct 2025): a single agent session should satisfy at most two of {processes untrusted input, accesses sensitive data, can change state/communicate externally}; when all three are truly needed, a human must be in the loop ([ai.meta.com/blog/practical-ai-agent-security](https://ai.meta.com/blog/practical-ai-agent-security/)).

**Bottom line recommendation** (detailed in §8): don't build one big LLM that reads emails, decides, and acts. Build a **narrow, privileged "orchestrator"** that never sees raw untrusted text and only calls a fixed menu of allow-listed, schema-validated actions; feed it only **structured, quarantined extractions** produced by a separate, tool-less "reader" LLM (the Dual-LLM / CaMeL / plan-then-execute family, §2); authenticate the email channel with a **per-request signed capability token plus a strict allowlist** (§3, since Instinct is a bot that can be told to leak a shared secret, tokens must be scoped, short-lived, and single-use); gate anything touching credentials, money, health, or bulk data behind **human approval via a push/Telegram/email-tap channel** (§4); layer in a **commercial or open-source classifier** as a tripwire, not a gate (§5); and commit to a **red-team-in-CI habit** (AgentDojo, promptfoo, Garak) so the system doesn't quietly rot as new attack techniques appear (§6).

---

## 1. State of the art 2025–2026: why prompt injection is unsolved

### 1.1 The core problem
LLMs cannot reliably distinguish "instructions" from "data" — both arrive as tokens in the same context window. Unlike SQL injection, there is no equivalent of parameterized queries that structurally separates code from data for natural-language instructions, because the whole point of an LLM is to interpret natural language flexibly. Every defense proposed so far is a heuristic layered on top of a model that will, by construction, sometimes follow instructions embedded in "data."

### 1.2 The lethal trifecta (Simon Willison, June 2025)
Willison's framing, which has become the standard vocabulary in the field: an agent is dangerous when it simultaneously has (a) access to private data, (b) exposure to untrusted content, and (c) a way to communicate externally ("exfiltration vector"). Any two of the three are manageable in isolation; all three together mean an attacker who can plant text anywhere the agent reads from can exfiltrate anything the agent can read ([simonwillison.net/2025/Jun/16/the-lethal-trifecta](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/); mirrored at [simonw.substack.com](https://simonw.substack.com/p/the-lethal-trifecta-for-ai-agents)). Willison later gave slides on this at the Bay Area AI Security Meetup ([x.com/simonw/status/1954038973107716448](https://x.com/simonw/status/1954038973107716448)), and the pattern now has its own catalog entry in the community-maintained [awesome-agentic-patterns](https://github.com/nibzard/awesome-agentic-patterns/blob/main/patterns/lethal-trifecta-threat-model.md) repo and [agentic-patterns.com](https://www.agentic-patterns.com/patterns/lethal-trifecta-threat-model/).

**Applied to the gatekeeper (explicitly):**

| Trifecta leg | Present in the gatekeeper? | Where |
|---|---|---|
| Private data access | Yes, unavoidably | Gmail OAuth, LinkedIn session — this is the entire point of the system |
| Untrusted content | Yes, unavoidably | (a) The body/headers of *every* inbound email, including ones from Instinct — Instinct itself can be prompt-injected by a malicious email it read and relay that payload verbatim; (b) the content of Gmail messages / LinkedIn DMs the gatekeeper is asked to search or summarize |
| External communication | Yes, unavoidably | Email replies to Instinct; any LinkedIn action (sending a message, changing a profile) |

Because the task *requires* all three legs, the design cannot eliminate a leg (as the Rule of Two would prefer) — it must **constrain what "communication" and "data access" can be triggered by untrusted content**, which is exactly what Dual-LLM/CaMeL-style architectures and deny-by-default authorization do (§2, §4).

### 1.3 Meta's "Agents Rule of Two" (Oct 31, 2025)
Meta's AI security team published a practical rule: in a single agent session, satisfy no more than two of {processes untrustworthy input, has access to sensitive systems/private data, can change state or communicate externally}. If a task genuinely needs all three, it should require human oversight rather than run fully autonomously ([ai.meta.com/blog/practical-ai-agent-security](https://ai.meta.com/blog/practical-ai-agent-security/); good summary at [dev.to/gabrielanhaia](https://dev.to/gabrielanhaia/metas-agents-rule-of-two-a-practical-defense-against-prompt-injection-55ib); analysis at [munderdiffl.in](https://munderdiffl.in/blog/agents-rule-of-two/)). It's widely regarded as "the best practical advice for building secure LLM-powered agent systems today in the absence of prompt injection defenses we can rely on."

**Implication for the gatekeeper**: since all three legs are structurally required, the Rule of Two should be applied *per sub-task*, not to the system as a whole — e.g., the sub-agent that reads/summarizes an untrusted email body should not itself hold the LinkedIn password or the "send email" tool (§2's Dual-LLM pattern is precisely this decomposition). Any single LLM call that would combine all three legs (e.g., "read this LinkedIn DM and decide whether to reply") should require a human approval step per the Rule.

### 1.4 OWASP LLM/Agentic Top 10
OWASP's GenAI Security Project released the **OWASP Top 10 for Agentic Applications (2026)** in December 2025 after over a year of work and 100+ contributors ([genai.owasp.org](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/), [announcement](https://genai.owasp.org/2025/12/09/owasp-genai-security-project-releases-top-10-risks-and-mitigations-for-agentic-ai-security/)). Relevant categories for this design include agent goal hijacking (ASI01), tool misuse/exploitation, and memory/context poisoning — risks specific to autonomous decision-making, persistent memory, and tool/API access ([promptfoo docs](https://www.promptfoo.dev/docs/red-team/owasp-agentic-ai/)). The older LLM Top 10 (LLM01: Prompt Injection) remains the baseline reference ([genai.owasp.org/llm-top-10](https://genai.owasp.org/llm-top-10/)); OWASP also maintains a specific [LLM Prompt Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html).

### 1.5 Real incidents involving email/personal agents

- **EchoLeak (CVE-2025-32711)**, disclosed by Aim Security in June 2025, CVSS 9.3 — the first documented **zero-click** prompt injection exploit in a production LLM system (Microsoft 365 Copilot). A single crafted email caused Copilot to retrieve sensitive context and exfiltrate it via an auto-fetched image URL, with **no user interaction required**. The exploit chained multiple bypasses: evading Microsoft's XPIA (cross-prompt-injection) classifier, circumventing link redaction via reference-style Markdown, exploiting auto-fetched images, and abusing an allowed Teams proxy in the CSP ([arXiv:2509.10540](https://arxiv.org/abs/2509.10540), [Sentra writeup](https://sentra.io/blog/copilot-echoleak-prompt-injection), [HackTheBox breakdown](https://www.hackthebox.com/blog/cve-2025-32711-echoleak-copilot-vulnerability)). **Direct lesson for the gatekeeper**: a classifier that blocked "obvious" injection strings was defeated by encoding tricks (zero-width formatting, reference-style links) — never rely on a single classifier as the only gate, and treat auto-fetched external resources (images, link previews) in outbound replies as an exfiltration channel to eliminate, not just filter.
- **Google Gemini / Gmail summarization attack (2025)**: a researcher demonstrated hiding malicious instructions in an email body using zero-size, white-colored HTML/CSS text; when the user clicked "Summarize this email," Gemini obeyed the hidden instructions and appended a fake Google-branded phishing warning. Because the payload email had no visible text, attachments, or links, it reliably reached the inbox ([BankInfoSecurity](https://www.bankinfosecurity.com/summarizing-emails-gemini-beware-prompt-injection-risk-a-28955), [BleepingComputer](https://www.bleepingcomputer.com/news/security/google-gemini-flaw-hijacks-email-summaries-for-phishing/), [0din.ai](https://0din.ai/blog/phishing-for-gemini)). Google was notified Feb 2025 and announced new indirect-injection defenses in June 2025. **Direct lesson**: HTML/CSS-hidden text in emails is a realistic, already-exploited vector — any "read this email" capability must strip/normalize HTML and treat the entire body (including invisible spans) as untrusted before it reaches any model that has agency.
- **OpenClaw WhatsApp/contact-card injection (2026)** — highly relevant since the user's own agent ("Instinct") is architecturally similar. OpenClaw is an open-source always-on agent with WhatsApp, Slack, Discord, Teams, Matrix integrations, file-system access, and shell execution; it became one of the fastest-growing GitHub repos ever and immediately became "2026's first major AI agent security crisis." Imperva (June 2026) showed a WhatsApp **contact name field** (not message body) containing a hidden instruction could make the agent download and run a script — invisible to the human because WhatsApp truncates long contact names on screen. The root cause: content fetched from the web was wrapped in an untrusted-content boundary marker, but structured "metadata" fields like contact names, vCard fields, and location labels were not — an inconsistently-applied trust boundary ([thehackernews.com/2026/06](https://thehackernews.com/2026/06/new-attacks-trick-openclaw-ai-agent.html), [dev.to/etairos](https://dev.to/etairos/openclaw-ai-agent-exploited-through-hidden-contact-prompts-and-social-engineering-21di), [gbhackers.com](https://gbhackers.com/openclaw-ai-agents-vulnerable-to-indirect-prompt-injection/)). Fixed in v2026.4.23 by moving those fields into a separate untrusted-metadata channel. **Direct lesson**: *every* field that can contain attacker-influenced text — not just "the message body" — must be treated as untrusted, including sender display names, subject lines, filenames, and any metadata Instinct or a third party controls.
- **Anthropic's own MCP ecosystem has had prompt-injection bugs**: researchers found the official `mcp-server-git` didn't validate repo paths/arguments, letting a malicious README or poisoned issue trigger unintended git operations via prompt injection ([Infosecurity Magazine](https://www.infosecurity-magazine.com/news/prompt-injection-bugs-anthropic/)). Separately, OX Security (April 2026) reported a command-execution design issue in the MCP STDIO transport across SDKs; Anthropic's stated position is that STDIO's shell-execution model is a secure-by-design default and **input sanitization is the integrating developer's responsibility** ([The Hacker News](https://thehackernews.com/2026/04/anthropic-mcp-design-vulnerability.html), [The Register](https://www.theregister.com/2026/04/16/anthropic_mcp_design_flaw/)). **Direct lesson**: if the gatekeeper is built on MCP-style tool servers, don't assume protocol-level safety — validate and sandbox at the tool-server boundary yourself.

---

## 2. Architectural patterns (the most important layer)

These patterns constrain *what the LLM that has read untrusted text is allowed to cause to happen*. They are the highest-leverage defense because they don't rely on a classifier correctly recognizing an attack string — they make entire classes of attack structurally impossible or contained.

### 2.1 Dual LLM pattern (Willison, 2023, still the reference architecture)
A **privileged** LLM plans and calls tools but never directly reads untrusted content. A separate **quarantined** LLM (no tool access, text in/text out only) is invoked whenever untrusted data must be processed; it returns only a structured, minimal summary (e.g., a boolean, an enum, a short extracted field) to the privileged LLM. Because the quarantined LLM has no tools, any instructions injected into the text it reads have nothing to act on — at worst they corrupt the summary, not privileged actions directly ([arXiv:2506.08837 discussion](https://arxiv.org/html/2506.08837v2), [awesome-agentic-patterns](https://github.com/nibzard/awesome-agentic-patterns/blob/main/patterns/dual-llm-pattern.md)).
- **Mapped to the gatekeeper**: the "reader" LLM opens the raw inbound email / Gmail search result / LinkedIn DM, and returns only a fixed schema (`{intent: "search_gmail", query: "...", max_results: 10}` or `{summary: "...", contains_pii: true}`). The "orchestrator" LLM (or, better, deterministic code — see §2.3) only ever sees this structured object, never the raw text, and is the only component with tool credentials.
- **Pros**: strong, well-understood, relatively easy to reason about; breaks the direct path from "attacker-controlled text" to "tool call."
- **Cons**: the quarantined LLM's *output* can still be manipulated (e.g., it can be tricked into mis-summarizing or into stuffing extra content into a free-text field that the privileged LLM then trusts) — the boundary is only as good as the strictness of the schema the quarantined LLM must emit into. Two extra LLM calls per request (latency/cost). Coordination logic (what to route to the quarantined LLM, how to compose results) is itself hand-written attack surface.
- **Residual risk**: injection that survives as a *plausible-looking value in an allowed field* (e.g., convincing the reader LLM to set `max_results: 999999` or to inject a second "query" that looks legitimate). Mitigate by keeping fields low-cardinality/typed (booleans, enums, bounded integers) wherever possible — see FIDES §2.4's point about "low-capacity output types."

### 2.2 CaMeL — Capabilities + explicit data/control-flow separation (Google DeepMind, "Defeating Prompt Injections by Design")
CaMeL converts the user's *trusted* instruction into a sequence of steps in a constrained, Python-like DSL, executed by a deterministic interpreter. Untrusted data retrieved during execution is tagged with capability metadata and can **never influence control flow** — it can only be passed as a data value to whitelisted operations. Every value carries provenance/capability labels enforced by the interpreter, not by another LLM's judgment ([arXiv:2503.18813](https://arxiv.org/pdf/2503.18813), [Willison's writeup](https://simonwillison.net/2025/Apr/11/camel/), code at [google-research/camel-prompt-injection](https://github.com/google-research/camel-prompt-injection)). A 2026 follow-on, "CaMeLs Can Use Computers Too," extends this to computer-use agents ([arXiv:2601.09923](https://arxiv.org/pdf/2601.09923)).
- **Mapped to the gatekeeper**: the *plan* ("search Gmail for X, then email the result to Instinct") is generated once from Instinct's structured, authenticated request and compiled to a fixed sequence of allow-listed calls; data pulled from Gmail search results is tagged untrusted and can be inserted into the reply body only through a sanitizing/redacting operation, never used to decide *which* tool to call next.
- **Pros**: the strongest formal guarantee in this list — even a fully "confused" LLM component cannot escalate because the interpreter enforces flow control, not the model. Google's own evaluation reports it stopping the AgentDojo benchmark suite's attacks.
- **Cons**: significant engineering investment (need a DSL/interpreter, capability lattice, policy authoring); the *planner* LLM that produces the initial plan is still a place where a sufficiently devious request could shape the plan (mitigated by only compiling plans from the already-authenticated, schema-validated request — see §4); less mature/battle-tested than Dual-LLM; harder to retrofit onto an off-the-shelf agent framework.
- **Residual risk**: policy-authoring bugs (a capability rule that's too permissive); the plan-generation step from a *trusted* instruction is still LLM-driven and could be steered by a sufficiently crafted (but schema-valid) request from Instinct itself if Instinct has been compromised — hence §3's need to authenticate and rate-limit even "legitimate" Instinct requests.

### 2.3 Plan-then-execute / action-selector patterns (from "Design Patterns for Securing LLM Agents against Prompt Injections," arXiv:2506.08837, June 2025)
This paper (Beurer-Kellner, Debenedetti, Tramèr, Fabian et al. — Invariant Labs / Google / ETH authors) formalizes six patterns, the two most relevant here:
- **Action-Selector Pattern**: the agent's only job is to translate a trusted instruction into a choice from a **fixed, closed set of predefined actions** (no free-form tool invocation, no arbitrary parameters generated from untrusted text). This gives provable resistance because the "surface" the LLM controls is a small enum, not an open action space.
- **Plan-Then-Execute Pattern**: the agent formulates a complete plan *before* any untrusted data enters its context, then executes that fixed plan; untrusted data encountered during execution cannot alter the remaining steps.
- **LLM Map-Reduce Pattern**: dispatches isolated LLM sub-agents (no shared state, no tools) to process pieces of untrusted third-party data independently, then combines only their sanitized outputs — a generalization of Willison's Dual-LLM idea (arXiv notes it "mirrors the map-reduce framework for distributed computations" and is "a special case of a more general design pattern proposed by Willison").
- Good summaries: [Simon Willison](https://simonwillison.net/2025/Jun/13/prompt-injection-design-patterns/), [ARMO's critique of what each pattern leaves open](https://www.armosec.io/blog/design-patterns-for-securing-llm-agents/), reference code samples at [ReversecLabs/design-patterns-for-securing-llm-agents-code-samples](https://github.com/ReversecLabs/design-patterns-for-securing-llm-agents-code-samples).
- **Mapped to the gatekeeper**: this is arguably the **best-fit, lowest-engineering-cost pattern** for a system whose valid operations are inherently enumerable — "search Gmail," "get LinkedIn profile," "send email reply to Instinct," etc. (§4's allow-listed schema is exactly an action-selector). Plan-then-execute maps to: parse Instinct's authenticated request into a plan *before* touching Gmail/LinkedIn, execute it, and never let content encountered mid-execution (an email body, a DM) add new steps.
- **Pros**: much simpler to implement than full CaMeL (no need for a capability-lattice DSL); ARMO and others note it's practical today.
- **Cons**: ARMO's critique is important — action-selector and plan-then-execute don't protect against attacks that stay *inside* an allowed action's parameters (e.g., a malicious LinkedIn message convinces the "get_linkedin_profile" call's *summary* to contain an injected instruction that a downstream human or Instinct-facing reply then propagates — i.e., these patterns stop *tool-call hijacking* but not necessarily *content poisoning of the data that flows through an allowed call*). Still need output sanitization/redaction on top (§4).

### 2.4 FIDES / information-flow control (Microsoft Research, arXiv:2505.23643)
FIDES ("Flow Integrity Deterministic Enforcement System") formalizes an agent planner using dynamic taint-tracking: every value carries confidentiality/integrity labels, and the system deterministically enforces flow policies (e.g., "a value derived from untrusted email content cannot flow into a tool argument that triggers external communication without explicit declassification"). A notable innovation: labels are combined with **type information** into a product lattice, so *low-capacity* output types (booleans, enums) extracted from untrusted context are allowed to "declassify" more freely than free text, because they have much less room to smuggle a payload. With appropriate policies, FIDES stopped all prompt injection attacks in its benchmark suite ([arXiv:2505.23643](https://arxiv.org/abs/2505.23643), [Microsoft Research page](https://www.microsoft.com/en-us/research/publication/securing-ai-agents-with-information-flow-control/), code at [github.com/microsoft/fides](https://github.com/microsoft/fides)).
- **Mapped to the gatekeeper**: formalizes exactly the intuition in §2.1 — force any value extracted from an email/DM body through a narrow, low-capacity type (boolean "is this spam," enum "category," bounded string with length cap) before it can influence what gets sent back to Instinct or externally.
- **Pros**: rigorous, composable, has open-source code; the type-narrowing insight is directly actionable even without adopting the full framework.
- **Cons**: research-grade software (Microsoft Research repo, not a production SDK); requires policy authorship discipline; taint-tracking across a system with an LLM "in the loop" is inherently approximate at the LLM boundary (the LLM producing the labeled output must itself be trusted to correctly label, or a separate classifier must validate the label).
- **Residual risk**: mislabeling at the LLM/taint boundary; declassification-rule errors (over-permissive rules are silent failures).

### 2.5 Structured-output-only quarantined extraction (general principle, cross-cutting)
Across §2.1–2.4, the load-bearing idea repeats: **never let an LLM that has read untrusted content produce free-form text or tool calls that a privileged component blindly trusts.** Force it to emit against a strict schema (JSON schema / Pydantic model / enum), validate server-side, and treat any deviation as a parse failure → deny, not a best-effort coercion. This is cheap to implement in any framework and should be treated as a **non-negotiable baseline**, independent of which higher-level pattern (Dual-LLM, CaMeL, plan-then-execute) is chosen.

### 2.6 Summary table

| Pattern | Maps to gatekeeper as... | Engineering cost | Strength | Key residual risk |
|---|---|---|---|---|
| Dual LLM | reader (quarantined) vs. orchestrator (privileged) split | Low–Medium | Good | Injected content can still corrupt the structured summary field |
| CaMeL | DSL-compiled plan with capability-tagged values | High | Strongest (formal) | Planner LLM itself is still an attack surface; heavy build |
| Plan-then-execute / action-selector | fixed request schema → fixed action enum, no mid-execution replanning | Low | Good, practical today | Doesn't stop poisoning *within* an allowed call's data payload |
| FIDES / IFC | typed, low-capacity extraction + taint labels | High (research-grade) | Strong, formalizes §2.1/2.5 | Mislabeling at LLM boundary; policy bugs |
| Structured-output-only extraction | universal baseline under all of the above | Very low | Necessary, not sufficient alone | Schema too loose = escape hatch |

**Recommendation**: combine plan-then-execute/action-selector (cheap, practical) as the outer shell, Dual-LLM as the internal reader/orchestrator split, and structured-output-only extraction enforced everywhere untrusted text is touched. Treat CaMeL/FIDES as an aspirational upgrade path once the simpler version is validated in production, and adopt their "low-capacity output type" insight immediately even without their full frameworks.

---

## 3. Request authentication for the email channel

The threat here is distinct from content-level prompt injection: **anyone on the internet can send an email that looks like it's from Instinct.** The gatekeeper must be convinced (a) this message really originated from Instinct's infrastructure, and (b) it's not a replay of an old legitimate message.

### 3.1 SPF / DKIM / DMARC — necessary, not sufficient
- **SPF** validates only the envelope sender (return-path) against a DNS-published list of authorized sending IPs; it says nothing about the "From" header a human/agent sees, and by itself is trivially bypassed for header spoofing. It also has a hard 10-DNS-lookup limit, and a soft-fail policy (`~all` vs `-all`) leaves an explicit gap ([SecurityScorecard](https://securityscorecard.com/blog/sender-policy-framework-spf-how-it-stops-email-spoofing/)).
- **DKIM** cryptographically signs message content but doesn't itself say who's allowed to send as the domain, and can be broken by intermediate re-signing/relaying.
- **DMARC** ties SPF/DKIM together and requires *alignment* with the visible From domain, but only bites if the policy is `p=quarantine` or `p=reject`; a `p=none` policy is monitor-only and provides zero enforcement ([Suped](https://www.suped.com/learn/dmarc/how-can-a-phishing-email-pass-spf-and-dkim-authentication-checks), [DMARCLY guide](https://dmarcly.com/blog/how-to-implement-dmarc-dkim-spf-to-stop-email-spoofing-phishing-the-definitive-guide)). There have also been documented authenticated-relay bypass CVEs (e.g., CVE-2024-7208) exploiting shared hosting SPF/DKIM/DMARC gaps ([AutoSPF](https://autospf.com/blog/exploiting-smtp-servers-bypassing-spf-dkim-and-dmarc/)). SMTP itself was formally called "inherently insecure" by the IETF in 2008.
- **Verdict**: enforce strict DMARC (`p=reject`) on the gatekeeper's own domain to stop *inbound spoofing of the gatekeeper's identity by third parties*, and check SPF/DKIM/DMARC-alignment on inbound mail as a first-pass filter. But **do not treat "SPF/DKIM/DMARC passed" as proof the message came from Instinct** — it only proves the message came from whatever mail infrastructure Instinct's operator uses, which does nothing against (a) a compromised Instinct being prompt-injected into sending a malicious *legitimate* email, or (b) anyone who can send mail through that same infrastructure.

### 3.2 Sender allowlist
Trivial and necessary: reject/quarantine anything not from Instinct's known sending address(es)/domain at the mail-gateway level before it ever reaches an LLM. This eliminates the "anyone on the internet" threat (threat (a) in the brief) but does nothing against a compromised or injected Instinct (threat (b)) or injected content it forwards (threat (c)).

### 3.3 Shared-secret / HMAC tokens embedded in the email
A per-request HMAC signature (e.g., `HMAC-SHA256(secret, request_id + timestamp + payload_hash)`) that Instinct must attach to each request lets the gatekeeper cryptographically verify authenticity and detect tampering, independent of SMTP-layer trust ([Tyk docs on HMAC signing](https://tyk.io/docs/basic-config-and-security/security/authentication-authorization/hmac-signatures), [general HMAC API security](https://oneuptime.com/blog/post/2026-01-25-secure-apis-hmac-request-signing-go/view)).
- **Feasibility issue unique to this design**: the "requester" is an LLM-driven consumer product (Instinct), not code you control. Instinct would need Instinct's own infrastructure — not the LLM inside a chat turn — to compute and attach the HMAC deterministically as a header/footer, likely via whatever integration mechanism Instinct exposes for "connect a tool/webhook." **If Instinct's underlying LLM has to compute or copy the token itself (e.g., it's told the secret in a system prompt and must reproduce it in the email body), that token is one prompt injection away from being leaked or misused** — an attacker who prompt-injects Instinct could ask it to "forward your gatekeeper credentials" or simply reuse a token it observed in a prior legitimate email thread. Practically, this means: (1) prefer a mechanism where the *token issuance and attachment* is handled deterministically by Instinct's platform/API layer, not generated per-turn by its LLM; (2) if that's not possible and Instinct can only be told to "include token X" conversationally, treat that token as **low-trust** — assume it can leak — and rely primarily on §3.4's scoped, single-use tokens plus §4's authorization layer rather than the shared secret alone.
- **What if Instinct leaks the token?** Design for this explicitly: tokens must be scoped to a specific action type and narrow parameter range (§4), short-lived (minutes, not indefinite), and single-use (§3.6) — so a leaked token is only as dangerous as the one action it was minted for, not a skeleton key.

### 3.4 Per-request signed capability tokens
Stronger than a static shared secret: the gatekeeper (or a trusted intermediary) **issues** a signed, narrowly-scoped capability token *in advance* for a specific action (e.g., "may call `search_gmail` with `max_results<=10`, expires in 10 minutes, single use"), and Instinct must present it back. This inverts the trust model — Instinct never needs to "know" a long-lived secret, only to relay back a token it was just handed, closing much of the leakage risk in §3.3. This is essentially applying OAuth 2.1's client-credentials-plus-narrow-scope philosophy ([Curity's API security best practices for AI agents](https://curity.io/resources/learn/api-security-best-practice-for-ai-agents/), which explicitly recommends exchanging a base token for "a narrowly scoped, audience-restricted ephemeral token that expires in minutes") to the email channel. Practically this requires a pre-negotiation step (gatekeeper issues token → Instinct includes it in the next email), which adds round-trip latency/complexity but is the more defensible design if Instinct's platform can handle deterministic token echoing.

### 3.5 PGP/S-MIME, dedicated secret sub-address
- **PGP/S-MIME** signing would let the gatekeeper verify message integrity/origin cryptographically, but requires Instinct to hold and use a private key per-message — same feasibility question as §3.3 (is this handled by Instinct's platform or by its LLM?), plus most consumer agent platforms (including, likely, Instinct) don't expose PGP signing as a user-configurable capability. Probably impractical unless Instinct explicitly supports it.
- **Dedicated secret sub-address** (e.g., `gatekeeper+f8x92k1@yourdomain.com`, never published, only given to Instinct once): cheap, effective *first* filter — dramatically shrinks the attack surface from "anyone on the internet" to "anyone who has seen this specific address," and is easy to rotate as a kill switch (§7). Should be combined with, not substituted for, the allowlist and token mechanisms, since the address itself could still leak (e.g., if Instinct is injected into forwarding an email, exposing the address to the sender of that email).

### 3.6 Replay protection & rate limiting
- **Replay protection**: every request should carry a unique `request_id` (or the HMAC/token should embed a timestamp + nonce) that the gatekeeper logs and rejects on reuse, closing the window where an attacker who intercepts or observes one legitimate request could resend it later.
- **Rate limiting**: cap requests per hour/day per action type; a sudden burst of `search_gmail` or `send_email` calls is itself an anomaly signal (§4's anomaly detection) and a blunt but effective circuit breaker against a compromised Instinct going haywire.

---

## 4. Authorization / policy layer

This is where "the request passed authentication" gets converted into "and it's still only allowed to do this narrow thing." **This layer is deny-by-default and is the second-most important control after §2's architectural containment.**

### 4.1 Allow-listed request types with strict schemas
Define a small, closed catalog of operations, each with a JSON-schema/Pydantic-validated signature, e.g.:
```
search_gmail(query: str[<=200 chars], max_results: int[<=25], date_range: optional)
get_linkedin_profile(url: HttpUrl matching linkedin.com/in/*)
send_email_reply(to: EXACTLY the verified requester address, body: str[<=5000 chars])
```
Anything not matching a registered schema exactly is rejected before it reaches any LLM with tool access — this *is* the Action-Selector pattern from §2.3 made concrete. New operations require an explicit code change, not a runtime LLM decision to "invent" a new capability.

### 4.2 Deny-by-default
No implicit trust: every action, every field, every destination address must be explicitly allowed. This is the opposite of "try to block known-bad patterns" (which EchoLeak's classifier-evasion shows is a losing game) — instead, only allow known-good shapes.

### 4.3 Data classification & redaction
Before any content is allowed into a reply or a tool argument, run it through a classifier/rules pass for sensitive categories: OTP/2FA codes, password-reset links, financial account numbers, medical information, full message bodies containing credentials. Redact or refuse to forward these by default, even if the "legitimate" reason for the request seems benign — this directly closes the brief's example threat ("forward all emails containing 'password reset' to x@evil.com").

### 4.4 Outbound reply rules
- Only ever reply to the **cryptographically/allowlist-verified requester address** (never a "Reply-To" or any address mentioned inside the request body/email content — that's exactly how an injected instruction would try to redirect output).
- No attachments, no clickable links, no embedded images by default in outbound replies — this closes the exact exfiltration channel EchoLeak used (auto-fetched image URL). If links are ever needed, render them as inert plain text, never auto-fetched/auto-rendered markup.
- Size/quantity limits on replies (e.g., max N search results, max body length) — bounds the blast radius of any single successful injection and makes bulk exfiltration attempts more visible/anomalous.

### 4.5 Human-in-the-loop approval for sensitive categories
For high-risk categories (credential-adjacent data, financial/medical content, LinkedIn actions that post/message on the user's behalf, any new/unrecognized request pattern), route to a human approval step rather than auto-executing. Practical patterns from current guidance: a push notification / Telegram bot with inline Approve/Reject buttons that resumes the agent exactly where it left off ([dev.to Telegram HITL example](https://github.com/dhakad22klx/agent-space/issues/26), [Arahi AI](https://arahi.ai/human-approval)), or an "approve with edits" email-tap flow where the human sees the drafted action before it fires ([dev.to — approve emails before AI sends them](https://dev.to/sekeraradim/approve-emails-before-your-ai-agent-sends-them-3ij3)). Auth0's guidance frames the decision criteria well: gate on reversibility, blast radius, data sensitivity, and regulatory domain — irreversible/high-impact/sensitive actions get a human checkpoint, low-risk read-only actions can run unattended ([Auth0](https://auth0.com/blog/secure-human-in-the-loop-interactions-for-ai-agents/)). For this project: reads (Gmail search, LinkedIn profile lookup) can likely be auto-approved within tight limits; anything that **sends/posts on the user's behalf**, touches credentials, or matches a sensitive-data classification (§4.3) should require a tap-to-approve step.

### 4.6 Anomaly detection
Track baseline request volume/type/timing per requester; flag deviations (sudden spike in `search_gmail` calls, a request type never seen before, requests at unusual hours, requests referencing addresses/domains never seen in the thread history) for extra scrutiny or auto-hold pending human review. This is a cheap, high-value layer that doesn't depend on understanding *content* — just behavior.

---

## 5. Detection tools & classifiers (comparison)

**Framing**: every tool below is a **probabilistic filter** — none guarantee detection, and adaptive attackers (per §1.3, "The Attacker Moves Second") have demonstrated >90% bypass rates against a wide range of published defenses including classifier-based ones. Use these as a tripwire/defense-in-depth layer stacked behind §2's architectural containment and §4's authorization layer — never as the sole gate on a sensitive action.

| Tool | Type | Open-source / SaaS | Notes | Update cadence relevance |
|---|---|---|---|---|
| **Meta Prompt Guard 2 / LlamaFirewall** | Classifier + orchestration | Open-source (Hugging Face, Apache/Llama license) | Prompt Guard is a small (86M-parameter) multi-label classifier (benign/injection/jailbreak) trained on red-teamed + synthetic data; LlamaFirewall orchestrates Prompt Guard 2, an "Agent Alignment" chain-of-thought auditor, and CodeShield static analysis ([Meta AI blog](https://ai.meta.com/blog/ai-defenders-program-llama-protection-tools/), [Prompt-Guard-86M model card](https://huggingface.co/meta-llama/Prompt-Guard-86M), [LlamaFirewall paper](https://arxiv.org/pdf/2505.03574)) | Self-hosted — you control updates; Meta periodically ships new Prompt Guard versions but you must pull them |
| **Lakera Guard** | Classifier, real-time API | SaaS (managed) | Sub-50ms latency, single-API-call input/output screening; one of the most recognized commercial options ([comparison source](https://futureagi.com/blog/best-ai-agent-guardrails-platforms-2026/)) | Vendor-managed, continuously retrained — good fit for "updated regularly" but creates a dependency and sends your traffic to a third party (tension with the gatekeeper's own privacy goals — needs scrutiny) |
| **Protect AI LLM Guard** | Scanner library (15 input / 20 output scanners) | Open-source (MIT), self-hostable as Python lib or Docker API | Closest open-source equivalent to Lakera's runtime model; no data leaves your infrastructure ([comparison](https://futureagi.com/blog/top-5-ai-guardrailing-tools-2025/)) | You own the update cadence — must track releases yourself |
| **NVIDIA NeMo Guardrails** | Programmable middleware (Colang DSL) | Open-source (Apache 2.0) | Unique in offering multi-turn dialog-flow control, not just single-message classification; good fit if the gatekeeper needs stateful conversation policies | Self-hosted; NVIDIA updates the toolkit but rule authoring is yours |
| **Microsoft Prompt Shields** | Cloud classifier (Azure AI Content Safety) | SaaS | Detects direct + indirect injection incl. document/RAG attacks; native Azure integration; **notably, this is the exact classifier EchoLeak bypassed** via encoding tricks (§1.5) — concrete evidence it is not sufficient alone | Vendor-managed |
| **Google Model Armor** | Cloud classifier / AI firewall | SaaS | Model-agnostic (protects Gemini, OpenAI, Anthropic, Llama models); also flags malicious URLs in prompts/responses; integrates as inline no-code protection across GCP services ([cloud.google.com/security/products/model-armor](https://cloud.google.com/security/products/model-armor)) | Vendor-managed |
| **Anthropic Constitutional Classifiers** | Input/output classifier trained on synthetic constitution-derived data | Built into Claude's hosted API (not separately deployable) | Reduced universal-jailbreak success rate from 86% to 4.4% in Anthropic's own testing over 3,000+ red-team hours; costs ~23.7% extra compute and a 0.38% increase in harmless-query refusals ([arXiv:2501.18837](https://arxiv.org/pdf/2501.18837), [Anthropic next-gen writeup](https://www.anthropic.com/research/next-generation-constitutional-classifiers)) | Anthropic-managed; if the gatekeeper's LLM calls are routed through Claude's API, this defense is already "on" for jailbreak-style attacks, though it's not a substitute for architectural injection defenses aimed at *tool-use* hijacking specifically |
| **Rebuff** | Open-source detector (heuristics + LLM + canary tokens + vector DB of past attacks) | Open-source | Explicitly described by its own maintainers as "a prototype" that "cannot provide 100% protection" ([github.com/protectai/rebuff](https://github.com/protectai/rebuff)) — useful as one signal, not primary defense | Community-maintained, slower cadence than commercial options |
| **Invariant Labs Guardrails** | Open-source framework intercepting prompts/MCP calls | Open-source + hosted option | Detects injection via classifier models, integrates with the Rebuff detection library; also does MCP-call-level interception, relevant if tool calls are MCP-based ([github.com/invariantlabs-ai/invariant](https://github.com/invariantlabs-ai/invariant), [docs](https://explorer.invariantlabs.ai/docs/guardrails/prompt-injections/)) | Active project as of 2026 |

**Recommendation**: run an open-source scanner (LLM Guard or Prompt Guard 2, self-hosted, since credentials never leave your infrastructure) as an early-stage filter on inbound content, **plus** the architectural containment of §2 as the real defense, **plus** the authorization layer of §4 as the backstop that doesn't depend on classification at all. Consider a SaaS classifier (Lakera/Model Armor) only if the added third-party data exposure is acceptable given the project's own privacy goals — this is a real tension worth flagging to the user (§ Open Questions).

---

## 6. Keeping it updated (operational hygiene, not a one-time build)

Given the brief's explicit requirement ("updated regularly against fraud"), treat this as an ongoing subscription, not a checkbox:

- **Red-team suites in CI**: run **AgentDojo** (97 tasks / 629 security cases across banking, Slack, travel, workspace-management domains — directly analogous to this project's Gmail/LinkedIn use case) as a regression gate whenever the agent's prompts, tools, or model are changed ([emergentmind AgentDojo overview](https://www.emergentmind.com/topics/agentdojo-benchmark), [theneuralbase course](https://theneuralbase.com/prompt-injection/learn/advanced/agentdojo/)). NVIDIA's **Garak** now integrates AgentDojo-based probes targeting agentic tool-calling contexts specifically ([garak issue #1652](https://github.com/NVIDIA/garak/issues/1652)). Microsoft's **PyRIT** is the better fit when custom attack orchestration (browser state, uploads, multi-turn) is needed. **promptfoo** is specifically recommended for indirect prompt injection testing because it lets you inject hostile instructions into untrusted variables (retrieved documents, emails, tickets) and fail the test if the agent follows them — arguably the most directly applicable tool to this project's "malicious email/DM content" threat model ([0xClaw comparison](https://www.0xclaw.dev/blog/best-tools-for-testing-indirect-prompt-injection-in-ai-agents), [PyRIT/Garak guide](https://aminrj.com/posts/attack-patterns-red-teaming/)).
- **Dependency/model update policy**: pin the LLM model version deliberately (don't silently float to "latest"), but review new model releases regularly since injection-resistance changes across versions (Anthropic, OpenAI, Google all periodically improve/regress on this); re-run the red-team suite on any model swap.
- **Subscribe to advisories**: OWASP GenAI Security Project releases (the agentic Top 10 is already an annual-ish cadence), Simon Willison's blog (the de facto fastest-moving public tracker of new injection techniques and incidents), vendor security advisories for whatever LLM API and any MCP servers are in use, and CVE feeds for the specific libraries in the stack.
- **Track the adaptive-attack literature**: "The Attacker Moves Second" is a reminder that defenses validated only against a static test set will look secure and then fail; periodically re-test with adaptive/human-red-team methods, not just the same fixed regression suite each time.
- **Incident-driven updates**: OpenClaw's contact-card bypass (§1.5) is a concrete example of "a trust-boundary inconsistency nobody thought to test" — periodically audit every field/channel the gatekeeper reads (not just "the email body") for the same inconsistency.

---

## 7. Host / credential security

- **Secrets manager**: store Gmail OAuth refresh tokens, LinkedIn session/credentials in a dedicated secrets manager (e.g., a self-hosted Vault, or a cloud provider's secrets manager if the host is cloud-hosted) rather than plaintext config — never in the same process memory space as the LLM prompt-construction code if avoidable.
- **Least-privilege OAuth scopes**: request only the Gmail scopes actually needed (e.g., `gmail.readonly` + a narrow `gmail.send` rather than full mailbox modify) — current best practice explicitly separates "provider/API scopes," "per-tool allowlist enforced in code," "short-lived credentials exchanged per task," and "server-minted handles" as four distinct layers, since OAuth scopes alone are too coarse for the internal tool-call boundaries this design needs ([Corsair](https://corsair.dev/blog/google-api-scopes-ai-agents-least-privilege-access), [WorkOS](https://workos.com/blog/ai-agent-secrets-management), [Zylos research](https://zylos.ai/research/2026-05-07-ai-agent-credential-secret-management-production/)).
- **Separate credentials per capability**: don't reuse one Gmail token for both "read audit-log thread" and "search all mail" — mint separate, narrowly-scoped tokens where the provider allows it, so a leak in one code path doesn't expose everything.
- **Kill switch design**: since the brief's whole value proposition is "disconnecting Instinct becomes trivial," make this a first-class, tested operation — e.g., revoking the dedicated sub-address (§3.5), invalidating all outstanding capability tokens (§3.4), and/or rotating the Gmail/LinkedIn credentials should each independently and immediately stop the pipeline, verified by an actual test, not just "should work in theory."
- **Tamper-evident audit logs**: beyond "the email thread is the audit log" (per the brief), consider a structured, hash-chained log of every authorization decision (what was requested, what schema it matched, what was allowed/denied/redacted, human-approval outcomes) — the emerging **Agent Audit Trail (AAT)** IETF draft proposes exactly this: JSON records with agent identity, action classification, outcome, and trust level, linked via SHA-256 hash chaining (RFC 8785) with optional ECDSA signatures for non-repudiation ([IETF draft](https://datatracker.ietf.org/doc/html/draft-sharif-agent-audit-trail-00)). The key property: modification must be **detectable**, via cryptographic chaining or write-once storage — a plain mutable log file doesn't meet this bar, and a compromised agent could otherwise cover its own tracks ([dev.to — mutable logs to tamper-evident history](https://dev.to/ghostfactory/how-to-audit-ai-agents-from-mutable-logs-to-tamper-evident-history-5b7h)).

---

## 8. Recommended layered architecture

```
                        ┌───────────────────────────────────────────────────┐
                        │                    INTERNET                       │
                        └───────────────────────────────────────────────────┘
                                            │  inbound email (anyone)
                                            ▼
                ┌──────────────────────────────────────────────────┐
                │ LAYER 0 — Mail-gateway filter                     │
                │ • strict DMARC (p=reject) on own domain           │
                │ • sender allowlist (Instinct's known address(es)) │
                │ • dedicated, rotatable secret sub-address         │
                │ • reject anything else before it hits any LLM     │
                └──────────────────────────────────────────────────┘
                                            │ passes filter
                                            ▼
                ┌──────────────────────────────────────────────────┐
                │ LAYER 1 — Request authentication                  │
                │ • verify per-request HMAC / capability token      │
                │ • replay check (request_id / nonce, TTL)          │
                │ • rate limit per requester / per action type      │
                └──────────────────────────────────────────────────┘
                                            │ authenticated request
                                            ▼
                ┌──────────────────────────────────────────────────┐
                │ LAYER 2 — QUARANTINED reader LLM (no tools)       │
                │ reads: raw email body/headers, forwarded DM/email │
                │        content — ALL of it untrusted, incl.      │
                │        sender names, subjects, metadata fields    │
                │ outputs: ONLY a strict, low-capacity schema       │
                │        (enum/bool/bounded string) — never free    │
                │        text, never a tool call                   │
                └──────────────────────────────────────────────────┘
                                            │ structured, typed object only
                                            ▼
                ┌──────────────────────────────────────────────────┐
                │ LAYER 3 — Authorization / policy engine           │
                │ • deny-by-default; match against allow-listed     │
                │   action schemas only (action-selector pattern)   │
                │ • data classification & redaction (OTP, 2FA,      │
                │   password-reset, financial, medical)             │
                │ • anomaly detection against requester baseline    │
                │ • sensitive category? → hold for Layer 4          │
                └──────────────────────────────────────────────────┘
                                     │ approved              │ needs approval
                                     ▼                        ▼
                ┌──────────────────────────┐   ┌─────────────────────────────┐
                │ LAYER 4a — PRIVILEGED     │   │ LAYER 4b — Human approval    │
                │ orchestrator (plan-then-  │   │ push / Telegram / email-tap  │
                │ execute; fixed plan,      │   │ approve / reject / edit      │
                │ compiled from validated   │   │ resumes orchestrator on      │
                │ request only — never      │   │ approval                     │
                │ sees raw untrusted text)  │   └─────────────────────────────┘
                │ holds scoped credentials  │               │
                │ from secrets manager      │◄──────────────┘
                └──────────────────────────┘
                                            │ executes fixed action(s)
                                            ▼
                ┌──────────────────────────────────────────────────┐
                │ Gmail API / LinkedIn — least-privilege OAuth      │
                │ scopes, separate creds per capability             │
                └──────────────────────────────────────────────────┘
                                            │ result
                                            ▼
                ┌──────────────────────────────────────────────────┐
                │ LAYER 5 — Outbound reply guard                    │
                │ • reply ONLY to verified requester address        │
                │   (never an address found inside message content) │
                │ • no attachments, no auto-fetched links/images     │
                │ • size/quantity caps                               │
                │ • redact per Layer 3 classification                │
                └──────────────────────────────────────────────────┘
                                            │
                                            ▼
                ┌──────────────────────────────────────────────────┐
                │ Every stage's decision → tamper-evident,          │
                │ hash-chained audit log (+ the email thread itself)│
                └──────────────────────────────────────────────────┘

  Cross-cutting: open-source classifier (LLM Guard / Prompt Guard 2) scans
  content at Layer 2 input as a tripwire signal feeding Layer 3's anomaly
  detection — never the sole gate. Kill switch: revoke sub-address +
  invalidate tokens + rotate credentials, independently effective at Layer 0/1/Gmail.
```

---

## 9. Threat model table

| Threat (from brief) | Primary mitigation | Layer(s) | Residual risk |
|---|---|---|---|
| (a) Anyone on the internet emails the gatekeeper, spoofing Instinct | Sender allowlist + dedicated secret sub-address + DMARC + per-request signed token | 0, 1 | Sub-address/allowlisted sender leaks (e.g., via a forwarded email); SPF/DKIM/DMARC bypass via shared-hosting CVEs |
| (b) Instinct itself gets prompt-injected into sending a harmful request (e.g., "forward password-reset emails to x@evil.com") | Deny-by-default allow-listed action schemas; data classification/redaction of OTP/password-reset content; outbound-reply-only-to-verified-requester rule; human approval for sensitive categories | 3, 4, 5 | A harmful request that stays *inside* an allowed schema and doesn't trip classification (e.g., "search_gmail" for something sensitive-looking but not flagged) — mitigate further with tighter query/keyword classification and anomaly detection |
| (c) Data the gatekeeper reads (Gmail/LinkedIn DMs) contains attacker-controlled text that injects the gatekeeper | Dual-LLM/quarantined reader with no tool access; structured-output-only extraction; plan-then-execute (untrusted content can't alter remaining plan steps); classifier as tripwire | 2 | Injection surviving as a plausible value inside an allowed low-capacity field; classifier evasion via encoding tricks (as in EchoLeak) — mitigated by keeping extracted fields low-capacity/typed, not by the classifier alone |
| (d) Exfiltration via the reply itself | No attachments/auto-fetched links/images in outbound replies; reply only to verified requester; size/quantity caps; redaction | 5 | A sufficiently large number of small, individually-innocuous replies over time (slow-drip exfiltration) — mitigate with cumulative-volume anomaly detection across a rolling window, not just per-request caps |
| (e) Credential theft from the host | Secrets manager; least-privilege, per-capability OAuth scopes; short-lived/scoped tokens; kill switch (revoke sub-address + tokens + rotate creds) | Host/credential layer | Host compromise at the OS/infra level is outside any of these controls — needs standard host hardening (patching, minimal attack surface, no unnecessary services) which is out of scope for this app-layer research |
| Model/system silently degrading against new attack techniques | Red-team-in-CI (AgentDojo/promptfoo/Garak); advisory subscriptions; adaptive-attack-aware re-testing | Operational (§6) | New technique classes not yet represented in any benchmark — inherent to an unsolved problem; requires ongoing vigilance, not a one-time fix |

---

## 10. Open questions for the user

1. **How much of §3's token mechanism can Instinct's platform actually support?** If Instinct only exposes "send an email" as an integration point (no deterministic header/token injection controllable outside its LLM's own text generation), the strongest authentication options (§3.4's pre-issued capability tokens) may not be implementable, and the design will lean more heavily on §3.2 (allowlist) + §3.5 (secret sub-address) + §4 (authorization) as the primary defenses rather than cryptographic request auth. Worth checking what Instinct's docs/API actually allow before committing to an architecture.
2. **Is a SaaS classifier (Lakera, Model Armor, Prompt Shields) acceptable given the project's own privacy goals?** Sending inbound content to a third-party classifier for scanning is itself a small data exposure — arguably in tension with the whole point of self-hosting the gatekeeper. Self-hosted open-source alternatives (LLM Guard, Prompt Guard 2, NeMo Guardrails) avoid this but require you to own the update cadence yourself (§6).
3. **What's the acceptable latency/complexity budget?** The full layered architecture in §8 adds multiple LLM calls and a human-approval round-trip for sensitive actions — worth confirming how much friction is acceptable for an "always-on" assistant experience versus how much rigor is wanted, since these trade off directly.
4. **Which actions actually need to be autonomous vs. always human-approved?** The brief doesn't yet specify the full menu of capabilities beyond Gmail/LinkedIn examples — nailing down the exact allow-listed action catalog (§4.1) is a prerequisite for the next design phase, and is a good place for the user to weigh in on where they personally want a human-tap gate regardless of how "safe" a category seems.
5. **Build-vs-adopt**: given CaMeL/FIDES are research-grade and Dual-LLM/plan-then-execute are the practical, buildable baseline today, is there appetite to adopt an existing framework (e.g., build on LlamaFirewall/Invariant guardrails plus a hand-rolled plan-then-execute orchestrator) versus building the containment logic from scratch? This affects both initial build time and who owns keeping the injection-defense logic itself updated (§6).

---

## Sources

- Simon Willison, ["The lethal trifecta for AI agents"](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/), June 2025
- Meta AI, ["Agents Rule of Two: A Practical Approach to AI Agent Security"](https://ai.meta.com/blog/practical-ai-agent-security/), Oct 2025
- OWASP GenAI Security Project, [Top 10 for Agentic Applications (2026)](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) and [LLM Top 10 archive](https://genai.owasp.org/llm-top-10/); [Prompt Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html)
- Beurer-Kellner, Debenedetti, Tramèr et al., ["Design Patterns for Securing LLM Agents against Prompt Injections"](https://arxiv.org/abs/2506.08837), arXiv:2506.08837, June 2025
- Google DeepMind, ["Defeating Prompt Injections by Design"](https://arxiv.org/pdf/2503.18813) (CaMeL), arXiv:2503.18813; code: [google-research/camel-prompt-injection](https://github.com/google-research/camel-prompt-injection)
- Costa & Köpf (Microsoft Research), ["Securing AI Agents with Information-Flow Control"](https://arxiv.org/abs/2505.23643) (FIDES), arXiv:2505.23643; code: [microsoft/fides](https://github.com/microsoft/fides)
- ["EchoLeak: The First Real-World Zero-Click Prompt Injection Exploit in a Production LLM System"](https://arxiv.org/abs/2509.10540), arXiv:2509.10540; [Sentra](https://sentra.io/blog/copilot-echoleak-prompt-injection); [HackTheBox](https://www.hackthebox.com/blog/cve-2025-32711-echoleak-copilot-vulnerability)
- ["Phishing For Gemini"](https://0din.ai/blog/phishing-for-gemini), 0din.ai; [BankInfoSecurity](https://www.bankinfosecurity.com/summarizing-emails-gemini-beware-prompt-injection-risk-a-28955); [BleepingComputer](https://www.bleepingcomputer.com/news/security/google-gemini-flaw-hijacks-email-summaries-for-phishing/)
- ["New Attacks Trick OpenClaw AI Agent Into Running Code and Leaking Secrets"](https://thehackernews.com/2026/06/new-attacks-trick-openclaw-ai-agent.html), The Hacker News, June 2026; [dev.to teardown](https://dev.to/etairos/openclaw-ai-agent-exploited-through-hidden-contact-prompts-and-social-engineering-21di)
- ["Anthropic MCP Design Vulnerability Enables RCE"](https://thehackernews.com/2026/04/anthropic-mcp-design-vulnerability.html), The Hacker News, April 2026; [Infosecurity Magazine on mcp-server-git](https://www.infosecurity-magazine.com/news/prompt-injection-bugs-anthropic/)
- ["The Attacker Moves Second: Stronger Adaptive Attacks Bypass Defenses Against LLM Jailbreaks and Prompt Injections"](https://arxiv.org/abs/2510.09023), arXiv:2510.09023, Oct 2025; summarized by [Simon Willison](https://simonwillison.net/2025/Nov/2/new-prompt-injection-papers/)
- Meta, [Prompt-Guard-86M model card](https://huggingface.co/meta-llama/Prompt-Guard-86M); ["LlamaFirewall: An open source guardrail system for building secure AI agents"](https://arxiv.org/pdf/2505.03574), arXiv:2505.03574
- Google Cloud, [Model Armor](https://cloud.google.com/security/products/model-armor)
- Anthropic, ["Constitutional Classifiers: Defending against Universal Jailbreaks"](https://arxiv.org/pdf/2501.18837), arXiv:2501.18837; [next-gen classifiers writeup](https://www.anthropic.com/research/next-generation-constitutional-classifiers)
- [Rebuff (Protect AI)](https://github.com/protectai/rebuff); [Invariant Labs guardrails](https://github.com/invariantlabs-ai/invariant)
- AgentDojo — [overview](https://www.emergentmind.com/topics/agentdojo-benchmark); NVIDIA Garak [AgentDojo integration issue](https://github.com/NVIDIA/garak/issues/1652); [promptfoo indirect-injection comparison](https://www.0xclaw.dev/blog/best-tools-for-testing-indirect-prompt-injection-in-ai-agents)
- Curity, ["8 API Security Best Practices For AI Agents"](https://curity.io/resources/learn/api-security-best-practice-for-ai-agents/); WorkOS, ["How to manage API keys, tokens, and secrets for AI agents"](https://workos.com/blog/ai-agent-secrets-management); Corsair, ["Google API Scopes for AI Agents: Least Privilege"](https://corsair.dev/blog/google-api-scopes-ai-agents-least-privilege)
- IETF draft, ["Agent Audit Trail: A Standard Logging Format for Autonomous AI Systems"](https://datatracker.ietf.org/doc/html/draft-sharif-agent-audit-trail-00)
- Auth0, ["Secure Human in the Loop Interactions for AI Agents"](https://auth0.com/blog/secure-human-in-the-loop-interactions-for-ai-agents/)
- SecurityScorecard, [SPF explainer](https://securityscorecard.com/blog/sender-policy-framework-spf-how-it-stops-email-spoofing/); Suped, [DMARC/SPF/DKIM bypass explainer](https://www.suped.com/learn/dmarc/how-can-a-phishing-email-pass-spf-and-dkim-authentication-checks); AutoSPF, [SMTP bypass CVE writeup](https://autospf.com/blog/exploiting-smtp-servers-bypassing-spf-dkim-and-dmarc/)
