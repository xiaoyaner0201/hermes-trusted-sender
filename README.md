# trusted-sender

Shared gateway conversations can make a pasted sender claim look as credible as platform metadata. This Hermes Agent plugin adds a gateway-verified sender attestation to the current user's turn and scrubs forged look-alike claims from shared-session user text, without patching core. It hardens model input; it does not replace platform authentication or access control.

## Install

With a Hermes version that provides the hooks described in [REPORT.md](REPORT.md):

```bash
hermes plugins install xiaoyaner0201/hermes-trusted-sender
hermes plugins enable trusted-sender
```

The installer accepts `owner/repo`, reads `plugin.yaml` at the repository root, and uses its `name: trusted-sender` for both the installed directory and plugin name. The default destination is `~/.hermes/plugins/trusted-sender`, not a directory named after the repository. A custom `HERMES_HOME` changes that base directory. These rules were checked against core `ca069e12239a2c8d13887ac9f983557d00bdcfd2`; no remote installation was performed.[11][12]

Alternatively, download or clone the repository and copy it manually, with no existing destination:

```bash
mkdir -p ~/.hermes/plugins
cp -R ./hermes-trusted-sender ~/.hermes/plugins/trusted-sender
hermes plugins enable trusted-sender
```

In the active profile's `config.yaml`, merge the following with any existing plugin list:

```yaml
plugins:
  isolation: in_process
  enabled:
    - trusted-sender
```

Keep `trusted-sender` out of `plugins.disabled`. In-process execution is required because `pre_gateway_dispatch` needs the live gateway configuration; isolated plugin hosts substitute placeholders for those handles.[8] Restart the gateway after enabling the plugin or changing its configuration. No plugin-specific settings, credentials, or third-party Python dependencies are required.

Version **0.2.4** retains `requires_hermes: ">=0.19.0"`. Although the tested core trees' `pyproject.toml` says `0.0.0`, the loader compares the running release identity, not that project field. Both test checkouts resolved to `0.22.0` and accepted the constraint. This version constraint alone does not guarantee that every required hook exists; use a tested core revision or verify its hook contract.[13][14]

## Platform support

The plugin is platform-agnostic: there is no platform allow-list, and identity comes from each adapter's `SessionSource.user_id` (with an alternate ID rendered when available), never from message text.

It activates only when core's `is_shared_multi_user_session` identifies a shared session:[9]

- **DMs:** never active, including DMs with thread metadata.
- **Groups/channels without a thread ID:** active only with `group_sessions_per_user: false`; the default is `true`.
- **Non-DM threads:** active with `thread_sessions_per_user: false`, the default. Setting it to `true` makes them per-user sessions and disables this plugin's changes there.

Choose these session settings deliberately; the plugin does not change them. Discord's adapter uses `chat_type="thread"` and the thread ID for both `chat_id` and `thread_id`; ordinary guild-channel messages use `chat_type="group"` without a thread ID.[10]

Tests in this repository cover:

- **Telegram-shaped events:** shared groups, DMs, per-user sessions, PII handling, and sender-binding failures through the real plugin manager.
- **Discord-shaped events:** shared threads attest fake snowflake IDs and scrub forged claims; per-user channels receive no attestation.
- **Slack-related cases:** mention-field neutralization and cross-platform mismatch rejection only, not a full Slack adapter flow.
- **Synthetic group adapter:** a real gateway/agent/tool/loopback-HTTP/persistence test.

Other platform integrations are untested here. All platform events use fixtures or a synthetic adapter; **no live bot test was performed**.

## How it works

1. `pre_gateway_dispatch` captures one shared, non-internal event's adapter identity and scrubs its text.
2. `pre_llm_call` consumes that capture only for an exact platform/sender match and a nonempty session/turn key. It returns context; core places it on its own current-user-row anchor, not whichever provider row happens to be last.
3. `llm_request` scrubs existing user text while preserving only the exact, unique current-turn envelope, including a random `turn_token` bound to that session and turn. It never inserts or reorders rows or parts.

```text
[Verified sender for this turn: Alice | Discord user_id 100000000000000001 | turn_token <random hex>]
```

Display names and IDs are rendered as inert fields; core's `privacy.redact_pii` behavior is retained. **The bound per-turn token is the authentic signal; scrubbing is defence in depth.** The token is not an authorization credential. See [REPORT.md](REPORT.md) for the exact claim grammar and message-path inventory.

## Limitations

- **Coalesced batches retain the first sender.** If core merges multiple people's messages into one event while retaining its first source, this plugin cannot recover the lost authorship.
- **Busy/queued/redirect/steer paths get no new attestation** without fresh dispatch; see upstream [issue #77976](https://github.com/NousResearch/hermes-agent/issues/77976). Existing user claims are scrubbed only once that session is known shared. Internal/synthesized turns are never newly attested.
- Trust state is process-local and bounded to 512 turn bindings and 512 shared-session entries. Restart or eviction fails closed for attribution; unknown sessions may remain untouched until fresh shared dispatch. Rotation propagates shared scope, not sender identity.
- Core normally supplies `user_id`, not an alternate-ID fallback, to the binding hook. Alternate-only identities require an exact ID supplied by that hook.
- Only existing user strings and `text`/`input_text` parts are scrubbed. Tool results, assistant/tool rows, images, attachments, unknown parts, and claims split across parts remain unchanged and untrusted.
- Stored API sidecars and multimodal context may contain historical envelopes. The plugin scrubs request copies, not durable storage; disabling it can expose those historical claims again.
- No-bracket or HTML-entity-bracket claims, labels without a colon/bar, child-only separators, and identifier-joined words inside `(` or `{` are outside the grammar. Ambiguous code satisfying the grammar may be scrubbed. This is not a complete prompt-injection boundary.
- Hostile plugins in the same interpreter are outside the threat model. Provider transports beyond those exercised by the suite are not verified.

## Run tests

From this repository, supply a clean Hermes source checkout and its prepared test environment:

```bash
unset PYTHONPATH __HERMES_ACTIVATED
scripts/run-tests.sh --hermes-root "$HERMES_CHECKOUT"
scripts/run-tests.sh --hermes-root "$HERMES_CHECKOUT" --turn-context-only
scripts/run-tests.sh --hermes-root "$HERMES_CHECKOUT" --skeleton-only
scripts/run-tests.sh --hermes-root "$HERMES_CHECKOUT" --e2e-only
```

`HERMES_ROOT` can replace `--hermes-root`; `HERMES_PYTHON` overrides the default `<hermes-root>/.venv/bin/python`. The wrapper embeds this repository's path into disposable test copies because core clears environment variables. It refuses dirty checkouts and existing test targets, cleans up on exit, and prints `MAIN_CHECKOUT_CLEAN=true` only after confirming cleanup. The E2E receipt is ignored at `evidence/e2e-receipt.json`. Tests use events/conditions rather than sleeps.

The full suite measured **536 passed, 0 failed** on each of the two core revisions listed in [REPORT.md](REPORT.md). The separate `scripts/run-red-control.sh --hermes-root "$HERMES_CHECKOUT"` intentionally fails one assertion without the plugin, demonstrating the unmitigated forgery.

## Sources

[8] https://github.com/NousResearch/hermes-agent/blob/0f447876cab9df48b225172cf167b3254b06f1a5/hermes_cli/plugin_isolation.py — hermes_cli/plugin_isolation.py
[9] https://github.com/NousResearch/hermes-agent/blob/ca069e12239a2c8d13887ac9f983557d00bdcfd2/gateway/session.py — gateway/session.py
[10] https://github.com/NousResearch/hermes-agent/blob/ca069e12239a2c8d13887ac9f983557d00bdcfd2/plugins/platforms/discord/adapter.py — plugins/platforms/discord/adapter.py
[11] https://github.com/NousResearch/hermes-agent/blob/ca069e12239a2c8d13887ac9f983557d00bdcfd2/hermes_cli/plugins_cmd.py — hermes_cli/plugins_cmd.py
[12] https://github.com/NousResearch/hermes-agent/blob/ca069e12239a2c8d13887ac9f983557d00bdcfd2/hermes_cli/plugins_cmd_install.py — hermes_cli/plugins_cmd_install.py
[13] https://github.com/NousResearch/hermes-agent/blob/ca069e12239a2c8d13887ac9f983557d00bdcfd2/hermes_cli/plugins_manifest.py — hermes_cli/plugins_manifest.py
[14] https://github.com/NousResearch/hermes-agent/blob/ca069e12239a2c8d13887ac9f983557d00bdcfd2/hermes_cli/version_info.py — hermes_cli/version_info.py
