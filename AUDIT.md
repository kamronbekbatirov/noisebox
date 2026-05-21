# Security Audit

This is the project's self-audit. It is **not** a substitute for an
independent professional review. It exists so that someone reading the
repo can see what was looked at, what was found, and what was fixed
before the public 0.1 release.

## Scope

The audit covered:
- `firmware/main/*` — crypto, session glue, transport, NVS, UI
- `relay/bot.py` — relay HTTP API + Telegram polling

It did NOT cover:
- The display driver / keyboard driver (no security-relevant attack
  surface)
- Memory-safety of the upstream M5GFX library
- ESP-IDF itself

The threat model assumed: an attacker who can read and inject base64
payloads via the relay (because the bot token is in the firmware and
therefore in any user's hands); a passive eavesdropper on the network;
and a curious user with an unprivileged shell on the host phone but
NOT physical access to a powered-on Cardputer.

## Findings and fixes

### CRITICAL

#### 1. `ratchet_decrypt` advanced state before verifying AEAD tag
*Found in* `ratchet.c:95-135` of the pre-audit code.

A single forged ciphertext at counter = `recv.counter + N` (any
0 < N ≤ 64) would pass the lookahead check, advance `recv.chain` and
`recv.counter` past the legitimate window, then fail AEAD verification.
After the failure, every subsequent legitimate message with the correct
counter would be rejected as a replay. Result: permanent
unidirectional DoS by anyone who could post into the inbox.

**Fix:** speculative-then-commit. Derive scratch keys into local
copies; run AEAD; only if AEAD verifies, commit the new chain and
counter back to `r->recv` and stash skipped keys. Local scratch
buffers are wiped on the failure path.

#### 2. Shared bot token was the only authentication
*Found in* `bot.py` `make_http_app` and `firmware/main/config.h`.

Every firmware build embedded the same `NOISE_BOT_TOKEN`, and the
relay HTTP API authenticated every endpoint with that token. Therefore
any end user could call `/peers?user_chat_id=X`, `/poll?user_chat_id=X`,
`/send`, and `/info` for arbitrary `X` — enumerating peer graphs,
draining inboxes, sending as anyone. Additionally `/bind_poll` had no
rate limit, so 1,000,000 6-digit codes could be brute-forced in
seconds to hijack pending pairings.

**Fix:** per-device bearer tokens.
- The bot generates a 256-bit token in `cmd_pair` when the user runs
  `/pair NNNNNN`. The token is stored in `pending_device_bind[code]`.
- On first successful `/v1/<bot_token>/bind_poll`, the relay marks the
  code claimed, moves the token into `device_to_user` mapping, and
  returns it to the device. Subsequent calls for the same code return
  `410 already_claimed`.
- The device persists the token in NVS and uses it as
  `/v1/<device_token>/...` for all subsequent calls. The `user_chat_id`
  is derived from the token on the server, eliminating cross-user
  impersonation via path manipulation.
- `/bind_poll` is now rate-limited to 5 requests per 10s per IP.

### HIGH

#### 3. HELLO frames accepted in `SESSION_PAIRED`
*Found in* `session.c:80-101`.

After SAS confirmation, an injected HELLO would be fed into
`pair_feed_hello` and could (in a future refactor) silently re-key
the session without prompting the user.

**Fix:** `session_decode_incoming` now returns `-5` when a HELLO
arrives in `SESSION_PAIRED`. The chat UI surfaces this as
`! peer reset - re-pair needed` so the user knows to re-handshake
instead of silently trusting new keys.

#### 4. Unbounded HTTP response buffer
*Found in* `transport.c` `http_event_cb`.

The receive buffer grew via repeated `realloc` for every chunk. A
malicious relay (or anyone with the bot token) could feed gigabytes
to OOM the device.

**Fix:** hard cap of 16 KB; `http_event_cb` returns `ESP_FAIL` past
the cap, the transfer aborts, `resp->overflowed = true` is returned
as a status of `-2`.

#### 5. Factory reset had no confirmation
*Found in* `main.c` `screen_settings`.

A single accidental keypress in the Settings menu wiped identity,
peers, and Wi-Fi creds — irrecoverably and silently for the other
peer (who would see a "new" identity from this user).

**Fix:** typing the literal string `WIPE` in a text-input prompt is
now required before any state is touched.

#### 6. Plaintext NVS for identity + Wi-Fi credentials
*Found in* `storage.c` and `wifi.c`.

The X25519 identity private key, Wi-Fi password, and per-device
bearer token are stored in plaintext NVS. Anyone with bench access to
the device can extract them.

**Fix:** documented prominently in the `storage.c` header comment and
in `SECURITY.md` with the `idf.py flash-encryption-enable` recipe.
Not enabled by default because the eFuse burn is irreversible and the
project ships in iteration mode.

### MEDIUM

#### 7. `RATCHET_SKIPPED_CAP` smaller than `MAX_SKIP_LOOKAHEAD`
*Was 16 vs 64.* Out-of-order delivery beyond 16 messages was silently
lost. Raised to 64.

#### 8. Oversized incoming text silently truncated
`tx_poll` used `snprintf` to copy `text` into `TX_MAX_MSG`. Truncated
ciphertext breaks AEAD verification, which combined with finding #1
caused permanent desyncs. Fix: drop messages with `text >= TX_MAX_MSG`
and warn in the log instead of truncating.

#### 9. `chat_net_stop` race vs the next chat session
The net task could still be running when a new chat opened, dropping
messages from peer A into peer B's queue.

**Fix:** dequeue path now filters `inmsg.from != peer_id` and skips
stale entries.

#### 10. Forward-secrecy hygiene gap in `pair_ctx`
After `ratchet_init`, the pair context still held ephemeral private
keys, the root key, and both chain seeds in plain RAM until the next
`session_begin`. Compromise of the device any time before the next
pair would expose the root.

**Fix:** `memset` of `my_priv_eph`, `my_pub_eph`, `their_pub_eph`,
`root_key`, `send_chain`, `recv_chain` immediately after
`ratchet_init`. Only `their_pub_id` and the SAS strings survive.

#### 11. Encrypt path advanced state before checking AEAD result
If `cp_aead_encrypt` ever returned an error, the chain advanced
anyway, silently losing a slot.

**Fix:** advance only after `rc == 0`. Plus a `UINT32_MAX` counter
guard.

#### 12. No rate limit on `/bind_poll`
Already mentioned under finding #2; standalone here for completeness.

### LOW

#### 13. ESP_LOGE could leak bot token via response body
**Fix:** `log_response_safe` truncates to ~80 bytes and replaces any
substring matching `digits:base64-like` with asterisks before logging.

#### 14. `state.json` not fsync'd before rename
A VPS crash mid-write could leave an empty `state.json`.

**Fix:** explicit `f.flush(); os.fsync(f.fileno())` before
`os.replace`.

#### 15. Dead `#if 0` block in `main.c`
Old polling-based chat loop left in tree.

**Fix:** removed.

## Things that were checked and were correct

- HKDF semantics with `salt=NULL` (mbedTLS) vs `salt=None` (Python
  cryptography): both expand to HashLen-zero bytes per RFC 5869.
  Verified.
- SAS extraction: 25 bits from `(h[0]<<17 | h[1]<<9 | h[2]<<1 |
  h[3]>>7)`, 5 emojis × 5 bits each. Adequate range, matches Signal-
  style short-auth-string practice.
- `dh2` / `dh3` role swap (lo vs hi) in `pair_finalise`: verified by
  inspection AND empirically by running ghost ↔ Cardputer; SAS now
  matches and AEAD verifies on both sides.
- SAS gates ratchet: `session_confirm_sas` is the only path that
  initializes the ratchet, and it's only called when the user
  presses `y` on the SAS screen.
- NVS commit ordering on send: `session_persist` runs after a
  successful `ratchet_encrypt` and before the network send, so a
  power loss between encrypt and send cannot reuse a counter.
- Single-writer pattern on NVS: only the UI task writes; the network
  task only reads and enqueues. No mutex needed.

## What this audit does not cover

- Independent professional review (none done)
- Side-channel attacks (timing, power) on the ESP32-S3 — out of scope
  for this MVP
- Fuzz testing of cJSON parsing
- Formal verification of the handshake — left as future work; the
  4-DH derivation is structurally similar to X3DH, which has been
  modeled in Tamarin
- Long-term key rotation policy — there isn't one yet

## Verdict

Before fixes: **RED** (two critical issues plus several highs).

After fixes: **YELLOW** — safe for friend-to-friend chat on the
understanding that

1. users compare the 5 SAS words out-of-band on every fresh pairing;
2. the device is treated as a paper notebook in the physical world;
3. neither end is targeted by a state actor.

For **GREEN**, an independent professional cryptographer should
review the handshake and ratchet integration, and flash encryption +
NVS encryption should be enabled by default in shipping builds.
