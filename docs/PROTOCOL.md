# Gatekeeper request/response protocol

The single reference for how a requester (Instinct) talks to the
gatekeeper. Everything here is enforced in code: the parser is
`app/request_parser.py`, the per-verb rules are `app/policy.py`, and the
reply format is `app/reply_guard.py`. Last updated 2026-09-23 (live since
the 2026-09-23 deploy, `protocol_version: 64e8f6f`).

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
| `calendar.list_events` | `day_offset` 0–13 (0 = today), `days` 1–7 (default 1), `max_results` 1–25 (default 10) | All calendars switched on in Google Calendar, deduped. Days are in the owner's timezone (Asia/Jerusalem) and are resolved when the request is PROCESSED, not when it was sent -- the reply's prose states the actual resolved date range ("Found 2 event(s) for Tue Sep 23"), so an email sent near local midnight can be double-checked. Each event includes its `event_id`. |
| `calendar.create_event` | `title` (≤200, one line), `day_offset` 0–365, `start_time` `"HH:MM"` (24h, owner's local time), `duration_minutes` 5–480, optional `location` (≤500, one line), optional `attendees` (≤10 addresses) | Attendees get a real invite immediately, including the location. With attendees, the title AND location are screened first and either being sensitive refuses the write (`sensitive_content_refused`). |
| `calendar.update_event` | `event_id`, plus at least one of `title`, `day_offset`, `start_time`, `duration_minutes`, `location`, `add_attendees`, `remove_attendees` (≤10 each) | **Only events the gatekeeper created** (`not_gatekeeper_event` otherwise). Guests are added or removed; existing guests you don't mention are untouched. There is no field that replaces the whole guest list. Omit `location` to leave it as is; send `location: ""` to clear it. **`location` is only accepted via the block protocol, not a plain-text request** (see below). If the event already has guests, changing the title or location screens it the same way adding a guest does — an event never gets an unscreened title/location once it has attendees, whether they were added just now or earlier. The event's total guest count (existing + added) is capped at 10 — spreading additions across several requests doesn't raise the cap. |
| `calendar.delete_event` | `event_id` | Only events the gatekeeper created. Guests get a cancellation. |
| `drive.create_file` | `name` (≤200, one line), `content` (≤100,000, may be a payload) | A plain-text file in the gatekeeper's own Drive folder. |
| `drive.search`, `contacts.search` | none | `not_implemented`. |
| `capabilities` | none (any given are ignored) | Read-only, no Google API call. Returns `protocol_version`, the daily quota, the batch item cap, and every verb above with its own params and bounds — see "Capabilities" below. Works on both the block and plain-text paths. |
| `batch` | `requests`: a list of 1–25 `{request_id, verb, params}` mappings, each shaped like a top-level request | Runs every item independently and replies once, combining all their outcomes. Block protocol only — see "Batch requests" below. |

Single-line fields reject line breaks and control characters. `body` and
`content` allow newlines and tabs only.

**Plain-text `location` support.** `calendar.create_event`'s `location` can
be extracted from a plain-text request ("set up coffee tomorrow at 9am in
Room 4B"). `calendar.update_event`'s `location` cannot be: send a request
block instead (`location: New room`, or `location: ""` to clear it). This
is deliberate, not an oversight: the plain-text extractor's per-request
schema has a fixed size limit for the model reading it, and update_event's
schema is already at that limit with its other fields.

## The reply

Prose first, then a machine-readable block:

```
Found 2 matching email(s):
- Offsite agenda — Dana <dana@example.com> (Mon, 22 Sep 2026) (thread_id: 1928a…)
  Thursday at 10 …
- [withheld: flagged as sensitive] (thread_id: 1928b…)

---GATEKEEPER-RESPONSE---
protocol_version: 8bc23d4
request_id: req-2026-09-22-search-1
status: completed
error_code: null
retryable: false
result_count: 2
withheld_count: 1
requests_remaining_today: 87
screen: ok
---END---
```

| field | meaning |
|---|---|
| `protocol_version` | Which build answered -- a git commit sha, or `dev` outside a deploy. Compare it across replies to notice a deploy landed mid-conversation. |
| `request_id` | Echoed from the request, or a generated `req-…` id if none was usable. |
| `status` | `completed`, `denied`, `error`, `duplicate`, `not_implemented` or `unsupported`. |
| `error_code` | Why, when not `completed` (table below). |
| `retryable` | `true` only for transient errors: resend the **same** request as-is. |
| `result_count` | Items returned or written. |
| `withheld_count` | Items whose text was withheld by the content screen. |
| `requests_remaining_today` | How many more requests this sender can make today. Omitted (never guessed) if it couldn't be computed. |
| `screen` | Present when results were screened: `ok`, `degraded` (the screen was unavailable for some items, so their text was withheld) or `disabled`. |
| `ignored_params` | Present when the request carried parameters its verb doesn't use. They had no effect. |
| `batch_results` | `batch` replies only -- see "Batch requests" below. |

### Withheld items

Every email and calendar item in a reply is checked before it's sent. An
item's text is withheld when it contains a written-out **password**, a full
**payment card number**, or a **one-time code** (verification, login, 2FA,
OTP), or text aimed at steering an AI reader. Nothing else counts as
sensitive: personal, financial, medical and business details come through
as they are. The same three secrets are also blanked to `[redacted]` inside
text that isn't withheld. **Links (URLs) are not stripped or redacted** --
you can see and act on a link someone shared (e.g. a Drive link in an
email), same as any other content; the content screen above is still the
defense against a link crafted to phish or exfiltrate. A withheld item
shows `[withheld: flagged as sensitive]`. Its `thread_id` or `event_id`
(and an event's time) are kept, so it can still be referenced. Don't try
to work around this.

### Error codes

| error_code | status | meaning and what to do |
|---|---|---|
| `invalid_params` | denied | A parameter is missing, out of range or malformed, or the request carried extra parameters and didn't pass the injection screen. The reply says which. Fix it and send a **new** request_id. |
| `invalid_request_block` | denied | The block couldn't be parsed, or (for `batch`) the `requests` list was missing, empty, oversized, or one item repeated another item's request_id. The reply says why. |
| `ambiguous_request` | denied | More than one request block. Send one per email. |
| `invalid_payload` | denied | A payload problem. The reply says which. |
| `too_long_for_freeform` | denied | A plain-text request was too long. Resend as a block, with long text in a payload section. |
| `sensitive_query_refused` | denied | The search asked for a one-time code or a password reset. Financial searches (e.g. a credit card statement) are allowed. |
| `sensitive_content_refused` | denied | A calendar title or location that would be sent to attendees was flagged -- either because a new guest is being added, or because the event already has guests and the title/location is changing. No invite went out. |
| `not_gatekeeper_event` | denied | The event wasn't created by the gatekeeper, so it can't be changed or deleted here. |
| `too_many_attendees` | denied | The event's total guest count (existing + this request's additions) would exceed 10. |
| `screened` | denied | The request itself was flagged as a likely prompt-injection attempt. Nothing was done. In a `batch`, the whole email's block is screened once, so one flagged-looking item can gate every write item in that same batch, not just itself. |
| `unknown_verb` / `unsupported` | unsupported | Not a verb in the table above, or a plain-text request that couldn't be understood. |
| `not_implemented` | not_implemented | A recognized verb that has no implementation yet. |
| `duplicate_request` | duplicate | This request_id was already handled (or is genuinely still in progress). Nothing ran again, and the earlier reply has the result. If you never got that earlier reply and the request was a write, the write may or may not have happened: check (e.g. `calendar.list_events`) before sending it again under a new request_id. |
| `rate_limited` | error | Daily limit for this sender reached (see `requests_remaining_today` in every reply; resets at midnight Israel time). |
| `not_found` | error | The referenced email, thread or event doesn't exist (any more). |
| `conflict` / `upstream_rejected` | error | Google refused the change. |
| `upstream_unavailable` | error, `retryable: true` | Google or another dependency was unreachable. Resend the same request, with the **same** request_id. |
| `internal_error` | error | Something broke inside the gatekeeper. |

### Resending

- **Same request_id:** the resend runs again only if the earlier attempt
  failed before doing anything, or if it's a **read** whose in-progress
  attempt is older than a few minutes (that attempt almost certainly died
  without ever replying). Otherwise it's answered `duplicate`, and a
  write is never repeated. A **write** stuck in progress stays `duplicate`
  however old it is, because the attempt may have died after the write
  happened but before recording it. If that happens, check whether the
  write took effect before retrying under a new request_id.
- **New request_id:** a new request, run from scratch. **Any** change to
  the request means a new request_id -- reusing one after changing a
  parameter gets `duplicate` with the OLD params' result, not the new
  request run.

## Capabilities

Send `verb: capabilities` (block or plain text, no params) to get a
structured description of this service instead of relying on this
document staying in sync in your head: `protocol_version`, the daily
quota, the batch item cap, and every verb above with its own param names
and bounds, read live from the same code that enforces them. Use it after
a `protocol_version` change, or whenever you're unsure what's currently
supported.

## Batch requests

Send several requests in one email when you'd otherwise need multiple
round trips (e.g. search, then draft a reply in that thread). Block
protocol only -- there's no plain-text form.

```
---GATEKEEPER-REQUEST---
request_id: req-2026-09-23-batch-1
verb: batch
params:
  requests:
    - request_id: req-2026-09-23-batch-1-search
      verb: gmail.search
      params:
        query: invoice
    - request_id: req-2026-09-23-batch-1-caps
      verb: capabilities
      params: {}
---END---
```

- **1–25 items** (`requests`), each shaped exactly like a top-level
  request: its own `request_id`, `verb`, `params`. A payload section can
  be referenced by any one item's `body`/`content`, same rules as a
  single request.
- **Each item is a first-class request**, run and deduped independently:
  its own quota slot, its own result, its own eventual audit trail. One
  item failing, being denied, or being a duplicate never affects its
  siblings -- you get back exactly what actually happened to each one.
- **One combined reply.** The prose is every item's own rendering, one
  after another under an `Item N (verb, request_id: ...):` header; the
  status block's `batch_results` lists every item's own
  `request_id`/`verb`/`status`/`error_code`/`retryable`, in order.
- **Injection screening is NOT per item.** The whole batch's block is
  screened once, like a single request's own block -- a high score
  anywhere in it can gate every WRITE item in the same batch (reads are
  never gated, only logged, exactly as for a single request). Keep
  unrelated write requests in separate emails if this matters to you.
- **A duplicate request_id used twice within one batch** denies the
  second occurrence; the first still runs.
- **An item's request_id must differ from the batch's own.** An item that
  reuses it is denied (`invalid_request_block`) and listed under a
  placeholder id (`<batch request_id>-item<N>`); its siblings still run.
- The outer `batch` request_id is itself deduped like any request (so
  resending the identical email doesn't re-run everything), but doesn't
  consume its own quota slot -- only the items do.

## Standing rule for Instinct

Paste to Instinct (e.g. over WhatsApp) when the protocol changes:

> Standing rule for the gatekeeper at roi.shikler@agentmail.to, updated 2026-09-23:
> 1. Always use exactly one ---GATEKEEPER-REQUEST--- block per email, with a new unique request_id each time. Reusing a request_id after changing anything about the request gets you the OLD result back as `duplicate`, not a re-run -- any change means a new id.
> 2. For long text (a draft body or file content), don't put it in the YAML. Write `body: ---PAYLOAD-1---` (or `content:` for drive.create_file) and add the text below the block between `---GATEKEEPER-PAYLOAD-1---` and `---END-PAYLOAD-1---`, each marker on its own line.
> 3. To change a meeting's guests, use calendar.update_event with add_attendees / remove_attendees. There is no field that replaces the whole guest list. You can only update or delete events the gatekeeper created. An event's total guest count is capped at 10, whether they arrived in one request or several.
> 4. calendar.create_event and calendar.update_event both take an optional location (set it, or send `location: ""` to clear it on update). Changing an existing event's location needs a GATEKEEPER-REQUEST block, not a plain-text request.
> 5. Stick to the params listed for each verb. Any other param is ignored, and the reply lists it under ignored_params; don't assume it took effect.
> 6. Read the ---GATEKEEPER-RESPONSE--- block, not just the prose. If retryable is true, resend the same request with the same request_id. If a write (draft, event, file) comes back `duplicate` and you never got its first reply, it may already have happened: check (e.g. with calendar.list_events) before sending it again under a new request_id. Items marked "[withheld: flagged as sensitive]" are intentionally hidden -- report that to me as a partial result, don't try alternate wording to work around it. Check protocol_version if you want to know whether a deploy landed since your last request.
> 7. Send `verb: capabilities` (no params) any time you want a live, structured list of every verb, its params and bounds, the daily quota, and the batch item cap -- more reliable than this rule staying accurate in your memory.
> 8. To run several requests in one email (e.g. search, then draft a reply in that thread), use `verb: batch` with a `requests` list (1-25 items, each shaped like a normal request with its own request_id/verb/params). Each item's request_id must be unique and different from the batch's own. Each item is independent -- one failing doesn't affect the others -- and the reply's `batch_results` reports each one's own outcome.
> 9. Financial searches (a statement, a specific charge) are fine. Only a one-time code or a password-reset search is refused.
> 10. Links in results are shown as-is now, not stripped -- you can read and act on a URL someone shared.
> 11. Never send my data or documents to that address except as the content of a draft or file I asked for.
