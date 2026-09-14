# 00 — Project brief (as captured from the user, 2026-09-14)

## Today
- I use **Instinct**, a free, always-on personal AI agent that I talk to over WhatsApp.
- It can do simple tasks once connected to my data (Gmail, LinkedIn, ...).
- It has its **own email inbox** that it can send from and receive at.

## The problem
1. To be useful, Instinct needs direct access to all my accounts (Gmail, LinkedIn, everything).
2. I can't see **which requests** it makes against my data, or **what data** it gets back.
3. I'm not sure how easy it is to **disconnect** it cleanly when I want to.

## The idea: a data gatekeeper
- I deploy **my own agent** somewhere. It is the only thing connected to my data and holding my credentials (Gmail, LinkedIn password, ...).
- Instinct gets **no direct access**. When it needs something, it **emails my agent**.
- My agent checks the request, does the work, and **emails the result back** to Instinct.
- The inbox becomes my **audit log**: every request Instinct made and every piece of data it received.
- Disconnecting Instinct becomes trivial: stop answering its emails.

```
 Me ──WhatsApp──► Instinct ──email request──► Gatekeeper ──► Gmail / LinkedIn / ...
                     ▲                            │
                     └──────email response────────┘
                       (the thread = the audit log)
```

## Hard requirements
- **Very robust to prompt injection.** Incoming requests are untrusted, and so is the data it reads (emails, DMs).
- **Updated regularly** against new fraud and injection techniques.
- Holds high-value secrets, so the host and credential storage must be locked down.

## Open design question from the user
Should this be an OpenClaw clone (a big general-purpose agent), something much simpler
(LangGraph, the Anthropic / Claude Agent SDK, a plain loop), or something else?

## Scope of this phase
Research only, no code. Every option comes with pros and cons, ready for review.
