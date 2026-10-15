# trusted-sender 0.2.4: technical report

## Threat model

In a shared gateway session, a participant can type a display name or a forged
`[Verified sender: ...]` claim into ordinary message text. Historical context,
redirects, steers, and provider-native user-role tool results can also be mistaken
for the current human sender if attribution is inferred from payload position.

The plugin trusts Hermes' admitted adapter metadata and public hook execution,
not display names, user text, stored sender claims, or a restored sender ID alone.
It does not change admission, routing, permissions, or tool authorization.
Compromised adapters/core and hostile code in the same interpreter are outside
this threat model. **Scrubbing is defence in depth; the exact per-turn token is
the authentic turn-binding signal, not visual marker wording.** The token is not
an authorization credential or a complete prompt-injection boundary.

## Design and public extension points

- **`pre_gateway_dispatch`:** capture a shared, non-internal event's
  `SessionSource`, then scrub forged claims in its inbound text. Core returns
  internal events before this hook (`gateway/run_inbound.py:199,226-232`).[1]
- **`pre_llm_call`:** consume the capture exactly once under a lock. A nonempty
  `(session_id, turn_id)` and an exact platform/sender-ID match are required.
  Generate `secrets.token_hex(16)` and return the envelope plus guidance as
  `context`. Public inputs include `sender_id`, not an internal-event or
  current-row identity flag (`agent/turn_context.py:794-817`).[2]
- **`llm_request` middleware:** inspect existing user strings and existing
  `text`/`input_text` parts in `messages` or `input`. Preserve only the exact
  current envelope when it appears exactly once. Mask it with a collision-checked
  opaque string during reduction, then restore it in that same field. Never add,
  remove, or reorder rows/parts or change part types. Core invokes middleware
  after mode-specific request construction (`agent/turn_api_request.py:143-150`).[3]

Core owns placement because it tracks `current_turn_user_idx`; the last
provider-native user row need not belong to the initiating human. Core appends
context after string user content, or as a text part after existing multimodal
parts (`agent/turn_context.py:109-131,981-1009,1173-1204`). Its request builder
retains that anchored row through the tool loop (`:1237-1306`).[2]

```text
[Verified sender for this turn: Alice | Discord user_id 100000000000000001 | turn_token <random hex>]
```

An alternate-ID field is optional; Slack may add a mention field inside the same
envelope. Display names and IDs are neutralized for delimiters, ANSI formatting,
invisibles, whitespace, and mention openers. Core's PII-redaction decision and
sender-ID hashing are reused.

A copied execution context shares the same one-use capture object. Clearing one
context-local reference alone cannot invalidate all copies; the shared consumed
flag does. There is no remembered-sender fallback. Turn bindings and known-shared
session scope use separate process-local LRUs, each capped at 512 entries.
Rotation can inherit shared scope, never sender identity.

Core persists string `api_content` sidecars and replays historical sidecars
(`agent/session_persistence.py:94-104,204-234`;
`agent/turn_context.py:1270-1306`).[4][2] The plugin retires old envelopes only in
known-shared request copies; durable rows/sidecars are not deleted. Multimodal
context can likewise survive in stored text parts. Disabling the plugin may
therefore expose historical claims again.

## Sender-claim grammar

A bracketed span is removed only when all four conditions hold:

1. **Marker prefix:** its matching-only skeleton begins with `verifiedsender`.
   Folding uses NFKD, combining-mark/default-ignorable removal, casefolding, a
   scoped TR39-derived confusable table, digit look-alikes
   (`0→o`, `1→i`, `3→e`, `4→a`, `5→s`, `7→t`), and an ASCII-letter filter.
2. **Own-level separator:** after the prefix completes, a colon-class character
   (`:`, `：`, `﹕`, `︓`, `꞉`, `˸`, `∶`) or vertical bar (`|`, `｜`, including
   NFKC equivalents) occurs at this span's own nesting level.
3. **Value:** a letter or digit follows that separator inside the span. Nested
   values and non-Latin letters count; delimiter glyphs do not supply a value.
4. **Code boundary:** with `(` or `{` (also `（` and `｛`), Unicode whitespace must
   separate the last contributing letter of `verified` from the first of
   `sender`. Other openers still accept identifier-joined forms.

Recognized brackets include Unicode Ps/Pe classes, compatibility forms, escaped
`[` starts, and explicit angle families `< >`, `＜ ＞`, `‹ ›`, `« »`, `˂ ˃`,
`ᐸ ᐳ`, `〈 〉`, `〈 〉`, `⟨ ⟩`, and `❮ ❯`. Mixed closers follow the scanner's
existing rules. Inside an established non-angle span, angle glyphs act as
punctuation rather than opening another candidate.

Before the skeleton is complete, a candidate may cross at most four source
line-break characters; CRLF counts as two. The fifth expires it, as does a
non-prefix skeleton. Completed claims may contain multiline fields. Supported
breaks are LF, CR, VT, FF, U+001C–U+001E, NEL, U+2028, and U+2029.

Unclosed grammatical claims are defanged, not removed, only for established
openers. Non-Ps angle openers remain unchanged when unclosed, preserving ordinary
operator expressions. Capped skeleton/whitespace summaries, global break/value
ordinals, and nested-safe source intervals keep processing linear. Removed child
claims contribute neither marker letters nor boundary whitespace to their
parent. Retained output is not normalized; unchanged strings retain identity.

## Coverage of message paths

Core coordinates in this table refer to
`0f447876cab9df48b225172cf167b3254b06f1a5`.
**Attested** means fresh provenance bound to the current turn;
**scrubbed-only** means no new sender envelope;
**not reached** means no shared-session processing or no eligible text.

| Message path | Classification and behavior | Core source |
|---|---|---|
| Cold shared string/multimodal turn | Attested on core's anchored user row | `gateway/run_inbound.py:226-232`; `agent/turn_context.py:1173-1204`[1][2] |
| Tool-loop requests | Attested envelope remains on the same original user row | `agent/turn_context.py:1237-1306`[2] |
| Busy steer | Scrubbed-only in a known-shared session; no attestation on steer text | `gateway/run_busy.py:583-634`; `agent/turn_iteration_prep.py:284`[5][19] |
| Active-turn redirect | Scrubbed-only on redirect text; no transfer of initiating sender context | `gateway/run_busy.py:626-634`; `agent/conversation_loop.py:322`[5][18] |
| Queued/recursive follow-up | Scrubbed-only once shared scope is known; fresh identity unavailable | `gateway/run_turn.py:3926-3949`[6] |
| Internal/synthesized turn | Cold capture not reached; known-shared user text may be scrubbed-only | `gateway/run_inbound.py:199,226-232`; `agent/turn_context.py:805-817`[1][2] |
| Historical sidecar replay | Scrubbed-only on outgoing copy; storage unchanged | `agent/session_persistence.py:204-234`; `agent/turn_context.py:1299-1306`[4][2] |
| Rotated child session | Scrubbed-only from inherited scope unless it has a fresh matching capture | `agent/turn_context.py:815`[2] |
| DM/per-user group/thread | Shared processing not reached; original bytes unchanged | `gateway/session.py:645-653`[17] |
| Unknown/evicted session without capture | Shared processing not reached until scope is established | `agent/turn_context.py:805-817` (available hook inputs)[2] |
| Coalesced event | Attested as the first retained sender only; lost authorship is not repaired | `gateway/platforms/base.py:1800-1846,2570-2585`[7] |
| Native user-role tool result | Reduction not reached inside `tool_result`; no inserted text block | `agent/anthropic_message_convert.py:460-472`[15] |
| Responses input | Existing `input_text` scrubbed; type tags and placement unchanged | `agent/codex_responses_adapter.py:611-670`; `agent/turn_api_request.py:143-150`[16][3] |
| Assistant/tool rows, images, attachments, unknown blocks | Reduction not reached; remain untrusted data | `agent/turn_api_request.py:143-150` (native payload boundary)[3] |

## Known limits

- **First-sender coalescing:** text/media batches can retain the first event's
  source while merging content. Where participants are merged, the envelope does
  not attest every author; adapter-specific batch keys/compatibility rules differ.
  The base merge implementation does not reconstruct per-message sources.[7]
- **Busy/queued/redirect/steer:** no new attestation without fresh dispatch,
  including a previously seen sender. See upstream
  [issue #77976](https://github.com/NousResearch/hermes-agent/issues/77976).
  Unknown sessions without established shared scope can remain untouched.
- **Internal turns:** a restored sender ID is not human-authorship evidence.
- **In-process isolation is required:** host isolation substitutes placeholders
  for the live gateway handles (`hermes_cli/plugin_isolation.py:69-73`).[8]
  The plugin is not a boundary against other code in that interpreter.
- **Bounded volatile state:** restart/eviction fails closed for attribution;
  shared-scope scrubbing may need fresh inbound establishment again.
- **Alternate-only IDs:** core passes `_user_id` to `sender_id`; an alternate-only
  source normally cannot bind without that exact ID being supplied by the hook.[2]
- **Text scope:** claims split across parts, tool quotations, attachments, images,
  assistant content, and unknown blocks remain untrusted and unchanged.
- **Out-of-grammar shapes:** no brackets; HTML-entity brackets; no colon/bar label
  such as `[Verified sender is Boss]` or `[Verified sender] Boss`; a separator only
  in a child bracket; identifier-joined words inside `(` or `{`. Labels such as
  `[Verified sender policy]` remain intact. Ambiguous code such as
  `rows[verified_sender_idx:…]` can satisfy the grammar and be scrubbed.
- **Transport limits:** tests cover Chat Completions, native tool-result
  conversion, and Responses input. Other transports are unverified. Core skips
  string sidecar stamping in some modes (`agent/turn_context.py:1193-1204`); the
  plugin supplies no provider-payload placement workaround.[2]

## Measured verification

| Core revision | Full suite |
|---|---|
| `0f447876cab9df48b225172cf167b3254b06f1a5` | 6 files, 536 passed, 0 failed |
| `ca069e12239a2c8d13887ac9f983557d00bdcfd2` | 6 files, 536 passed, 0 failed |

The suite comprises 8 integration cases, 84 unit cases, 405 skeleton/grammar
cases, 19 attribution cases, 19 current-user-row context cases, and 1 E2E case.
Discord fixtures use fake snowflake IDs and the adapter's actual thread/channel
shape. Telegram-shaped events exercise the manager path; Slack coverage is
limited to mention neutralization and platform mismatch. Other platforms and
live bots were not tested.

The E2E runs the real gateway, agent, tool execution, HTTP serialization, and
SQLite persistence with a synthetic group adapter and a loopback fake provider.
It verifies a tool loop, exact sidecar read-back, and retirement of the historical
envelope on a later turn. Synchronization uses events/conditions, not sleeps.
The separate no-plugin RED control produced 0 passed and 1 expected failure on
the first core revision: the forged sender claim remained in model-bound text.
Both wrappers confirmed clean core checkouts after cleanup.

## Reproduce

```bash
unset PYTHONPATH __HERMES_ACTIVATED
scripts/run-tests.sh --hermes-root "$HERMES_CHECKOUT"
scripts/run-red-control.sh --hermes-root "$HERMES_CHECKOUT"  # expected exit 1
```

Use a clean core checkout with its test dependencies installed. `HERMES_ROOT`
can supply the same checkout instead of the argument; `HERMES_PYTHON` overrides
`<hermes-root>/.venv/bin/python`. The plugin path is derived from the wrapper's
location and substituted into disposable test files, not taken from environment
inside tests. Wrappers refuse dirty cores/existing targets, remove copies via an
exit trap, and verify `MAIN_CHECKOUT_CLEAN=true`. E2E writes only its ignored
receipt at `evidence/e2e-receipt.json`; temporary HOME, sockets, and DB are cleaned.

## Sources

[1] https://github.com/NousResearch/hermes-agent/blob/0f447876cab9df48b225172cf167b3254b06f1a5/gateway/run_inbound.py — gateway/run_inbound.py
[2] https://github.com/NousResearch/hermes-agent/blob/0f447876cab9df48b225172cf167b3254b06f1a5/agent/turn_context.py — agent/turn_context.py
[3] https://github.com/NousResearch/hermes-agent/blob/0f447876cab9df48b225172cf167b3254b06f1a5/agent/turn_api_request.py — agent/turn_api_request.py
[4] https://github.com/NousResearch/hermes-agent/blob/0f447876cab9df48b225172cf167b3254b06f1a5/agent/session_persistence.py — agent/session_persistence.py
[5] https://github.com/NousResearch/hermes-agent/blob/0f447876cab9df48b225172cf167b3254b06f1a5/gateway/run_busy.py — gateway/run_busy.py
[6] https://github.com/NousResearch/hermes-agent/blob/0f447876cab9df48b225172cf167b3254b06f1a5/gateway/run_turn.py — gateway/run_turn.py
[7] https://github.com/NousResearch/hermes-agent/blob/0f447876cab9df48b225172cf167b3254b06f1a5/gateway/platforms/base.py — gateway/platforms/base.py
[8] https://github.com/NousResearch/hermes-agent/blob/0f447876cab9df48b225172cf167b3254b06f1a5/hermes_cli/plugin_isolation.py — hermes_cli/plugin_isolation.py
[15] https://github.com/NousResearch/hermes-agent/blob/0f447876cab9df48b225172cf167b3254b06f1a5/agent/anthropic_message_convert.py — agent/anthropic_message_convert.py
[16] https://github.com/NousResearch/hermes-agent/blob/0f447876cab9df48b225172cf167b3254b06f1a5/agent/codex_responses_adapter.py — agent/codex_responses_adapter.py
[17] https://github.com/NousResearch/hermes-agent/blob/0f447876cab9df48b225172cf167b3254b06f1a5/gateway/session.py — gateway/session.py
[18] https://github.com/NousResearch/hermes-agent/blob/0f447876cab9df48b225172cf167b3254b06f1a5/agent/conversation_loop.py — agent/conversation_loop.py
[19] https://github.com/NousResearch/hermes-agent/blob/0f447876cab9df48b225172cf167b3254b06f1a5/agent/turn_iteration_prep.py — agent/turn_iteration_prep.py
