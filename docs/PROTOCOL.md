# Gatekeeper request/response protocol

The single reference for how a requester (Instinct) talks to the
gatekeeper. Everything here is enforced in code: the parser is
`app/request_parser.py`, the per-verb rules are `app/policy.py`, and the
reply format is `app/reply_guard.py`. Last updated 2026-09-22.

## Sending a request

- Email `roi.shikler@agentmail.to` from an allowlisted address. Mail from
  any other sender is ignored and never answered.
- One request per email. The reply comes back in the same thread, to the
  sender only.
- Prefer the **fenced block** below. It's parsed by plain code, with no LLM
  involved, and it's the only way to send long text.
- Plain-text requests ("what's on my calendar tomorrow?") still work. A
  small, sandboxed model with no tools extracts them. They're limited to
  20,000 characters and suit short requests only.

### The request block

```
---GATEKEEPER-REQUEST---
request_id: req-2026-09-22-cal-1
verb: calendar.list_events
params:
  day_offset: 1
---END---
```

- Both markers must start a line. A `> `-quoted block, such as one in a
  reply chain, is ignored.
- **Exactly one** block per email. Two or more gets `ambiguous_request`.
- `request_id` is required: 1–128 characters of letters, digits and
  `. _ : -`, starting with a letter or digit. Use a new one for every
  logically new request.
- `verb` is required, and `params` is a YAML mapping.
- **A parameter a verb doesn't define is never used.** If the request
  passes the injection screen, it still runs: the reply lists the extras
  under `ignored_params`, so you can tell they had no effect. If the
  request is flagged, or the screen is unavailable, extras make it
  `invalid_params`. One exception is refused outright: `attendees` on
  `calendar.update_event` (use `add_attendees` / `remove_attendees`).
- A block that is present but broken (bad YAML, missing `request_id`) gets
  `invalid_request_block` with a reason. It is never guessed at.

### Payload sections, for long text

A draft body or file content goes in its own section **outside** the YAML,
copied byte for byte. Indentation, blank lines, quotes and colons all
survive, and no model ever reads it.

```
---GATEKEEPER-REQUEST---
request_id: req-2026-09-22-draft-1
verb: gmail.create_draft
params:
  to: dana@example.com
  subject: "Re: Thursday"
  body: ---PAYLOAD-1---
---END---

---GATEKEEPER-PAYLOAD-1---
Hi Dana,

Any text at all goes here, verbatim.
---END-PAYLOAD-1---
```

- The name after `PAYLOAD-` is 1–32 letters, digits, `_` or `-`. The
  reference (`---PAYLOAD-1---`) must match it exactly.
- Only `gmail.create_draft`'s `body` and `drive.create_file`'s `content` can
  take a payload.
- These are all `invalid_payload`:
  - a reference to a payload that isn't in the email;
  - two payloads with the same name;
  - a payload nothing references;
  - a payload with no request block.
- Payload text can't end its own section early unless a line **starts**
  with its own end marker. Pick another name if the text contains one.
- Newline framing: the line break after the start marker and the one
  before the end marker are removed, and nothing else is.

## Verbs

| verb | params | notes |
|---|---|---|
| `gmail.search` | `query` (required, ≤200 chars, one line), `max_results` 1–30 (default 5), `newer_than_days` 1–365 | Metadata and snippet only, never bodies. Queries whose point is fetching a one-time code or a password reset ("verification code", "otp", "2fa", "password reset", …) are refused (`sensitive_query_refused`). Financial searches are fine. Each result includes its `thread_id`. |
| `gmail.create_draft` | `to` (one address), `subject` (≤200, one line), `body` (≤20,000, may be a payload), optional `thread_id` | Creates a **draft only**. It is never sent; the owner reviews and sends it. With `thread_id` (copied from a `gmail.search` reply) the draft is a reply in that conversation. Use a `Re: …` subject. |
| `calendar.list_events` | `day_offset` 0–13 (0 = today), `days` 1–7 (default 1), `max_results` 1–25 (default 10) | All calendars switched on in Google Calendar, deduped. Days are in the owner's timezone (Asia/Jerusalem). Each event includes its `event_id`. |
| `calendar.create_event` | `title` (≤200, one line), `day_offset` 0–365, `start_time` `"HH:MM"` (24h, owner's local time), `duration_minutes` 5–480, optional `attendees` (≤10 addresses) | Attendees get a real invite immediately. With attendees, the title is screened first and a sensitive title is refused (`sensitive_content_refused`). |
| `calendar.update_event` | `event_id`, plus at least one of `title`, `day_offset`, `start_time`, `duration_minutes`, `add_attendees`, `remove_attendees` (≤10 each) | **Only events the gatekeeper created** (`not_gatekeeper_event` otherwise). Guests are added or removed; existing guests you don't mention are untouched. There is no field that replaces the whole guest list. |
| `calendar.delete_event` | `event_id` | Only events the gatekeeper created. Guests get a cancellation. |
| `drive.create_file` | `name` (≤200, one line), `content` (≤100,000, may be a payload) | A plain-text file in the gatekeeper's own Drive folder. |
| `drive.search`, `contacts.search` | none | `not_implemented`. |

Single-line fields reject line breaks and control characters. `body` and
`content` allow newlines and tabs only.

## The reply

Prose first, then a machine-readable block:

```
Found 2 matching email(s):
- Offsite agenda — Dana <dana@example.com> (Mon, 22 Sep 2026) (thread_id: 1928a…)
  Thursday at 10 …
- [withheld: flagged as sensitive] (thread_id: 1928b…)

---GATEKEEPER-RESPONSE---
request_id: req-2026-09-22-search-1
status: completed
error_code: null
retryable: false
result_count: 2
withheld_count: 1
screen: ok
---END---
```

| field | meaning |
|---|---|
| `request_id` | Echoed from the request, or a generated `req-…` id if none was usable. |
| `status` | `completed`, `denied`, `error`, `duplicate`, `not_implemented` or `unsupported`. |
| `error_code` | Why, when not `completed` (table below). |
| `retryable` | `true` only for transient errors: resend the **same** request as-is. |
| `result_count` | Items returned or written. |
| `withheld_count` | Items whose text was withheld by the content screen. |
| `screen` | Present when results were screened: `ok`, `degraded` (the screen was unavailable for some items, so their text was withheld) or `disabled`. |
| `ignored_params` | Present when the request carried parameters its verb doesn't use. They had no effect. |

### Withheld items

Every email and calendar item in a reply is checked before it's sent. An
item's text is withheld when it contains a written-out **password**, a full
**payment card number**, or a **one-time code** (verification, login, 2FA,
OTP), or text aimed at steering an AI reader. Nothing else counts as
sensitive: personal, financial, medical and business details come through
as they are. The same three secrets are also blanked to `[redacted]` inside
text that isn't withheld, and so are links (URLs). A withheld item shows
`[withheld: flagged as sensitive]`. Its `thread_id` or `event_id` (and an
event's time) are kept, so it can still be referenced. Don't try to
work around this.

### Error codes

| error_code | status | meaning and what to do |
|---|---|---|
| `invalid_params` | denied | A parameter is missing, out of range or malformed, or the request carried extra parameters and didn't pass the injection screen. The reply says which. Fix it and send a **new** request_id. |
| `invalid_request_block` | denied | The block couldn't be parsed. The reply says why. |
| `ambiguous_request` | denied | More than one request block. Send one per email. |
| `invalid_payload` | denied | A payload problem. The reply says which. |
| `too_long_for_freeform` | denied | A plain-text request was too long. Resend as a block, with long text in a payload section. |
| `sensitive_query_refused` | denied | The search asked for codes, resets or financial details. |
| `sensitive_content_refused` | denied | A calendar title that would be sent to attendees was flagged. No invite was sent. |
| `not_gatekeeper_event` | denied | The event wasn't created by the gatekeeper, so it can't be changed or deleted here. |
| `screened` | denied | The request itself was flagged as a likely prompt-injection attempt. Nothing was done. |
| `unknown_verb` / `unsupported` | unsupported | Not a verb in the table above, or a plain-text request that couldn't be understood. |
| `not_implemented` | not_implemented | A recognized verb that has no implementation yet. |
| `duplicate_request` | duplicate | This request_id was already handled (or is in progress). Nothing ran again, and the earlier reply has the result. |
| `rate_limited` | error | Daily limit for this sender reached (resets at midnight Israel time). |
| `not_found` | error | The referenced email, thread or event doesn't exist (any more). |
| `conflict` / `upstream_rejected` | error | Google refused the change. |
| `upstream_unavailable` | error, `retryable: true` | Google or another dependency was unreachable. Resend the same request, with the **same** request_id. |
| `internal_error` | error | Something broke inside the gatekeeper. |

### Resending

- **Same request_id:** the resend runs again only if the earlier attempt
  failed before doing anything. Otherwise it's answered `duplicate`, and a
  write is never repeated.
- **New request_id:** a new request, run from scratch.

## Standing rule for Instinct

Paste to Instinct (e.g. over WhatsApp) when the protocol changes:

> Standing rule for the gatekeeper at roi.shikler@agentmail.to, updated 2026-09-22:
> 1. Always use exactly one ---GATEKEEPER-REQUEST--- block per email, with a new unique request_id each time.
> 2. For long text (a draft body or file content), don't put it in the YAML. Write `body: ---PAYLOAD-1---` (or `content:` for drive.create_file) and add the text below the block between `---GATEKEEPER-PAYLOAD-1---` and `---END-PAYLOAD-1---`, each marker on its own line.
> 3. To change a meeting's guests, use calendar.update_event with add_attendees / remove_attendees. There is no field that replaces the whole guest list. You can only update or delete events the gatekeeper created.
> 4. Stick to the params listed for each verb. Any other param is ignored, and the reply lists it under ignored_params; don't assume it took effect.
> 5. Read the ---GATEKEEPER-RESPONSE--- block. If retryable is true, resend the same request with the same request_id. Items marked "[withheld: flagged as sensitive]" are intentionally hidden, so don't ask for them another way.
> 6. Never send my data or documents to that address except as the content of a draft or file I asked for.
