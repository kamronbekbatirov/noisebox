# Security Model

This document describes what NoiseBox protects against, what it does
not, and how to report problems.

## What is protected

**Message confidentiality** against:
- Passive eavesdroppers on the Wi-Fi link
- Passive eavesdroppers on the path to the relay (TLS to
  `your-relay-domain`)
- The relay operator themselves (the relay only sees base64 ciphertext
  and metadata; never plaintext)
- Telegram and any intermediate TLS terminator on Telegram's side
- Government-style passive collectors of Telegram traffic

**Message authenticity** against:
- Substitution of message bodies (every message has an AEAD tag bound
  to a per-message key)
- Replay of past messages (per-direction counter, AAD-bound)

**Forward secrecy** against:
- Compromise of the device tomorrow doesn't reveal messages from
  yesterday. The chain ratchet derives a fresh message key per send,
  wipes the previous chain. Compromised state recovers no past
  ciphertexts.

**Active MITM at the relay** is detected (but not prevented
automatically) by the **5-word SAS** comparison. Users must compare the
five words on the two screens *out-of-band over a channel they trust*
(phone call, in-person, anything that isn't this same relay). If words
match, no MITM. If they don't, abort.

## What is NOT protected

### Metadata
- The relay and Telegram both see **who messages whom and when**, and
  the **size of each message** (modulo base64+TLS padding).
- The relay sees which device tokens map to which Telegram user_ids.
- Telegram knows the public Telegram identity of both users.
- If you don't trust your relay operator with knowing your contact
  graph, run your own.

### Physical attack on a powered-on device
- There is no PIN, no biometric, no auto-lock. Picking up an
  unattended unlocked Cardputer reveals every chat history and the
  device's long-term identity key.

### Physical attack with chip-off
- Without flash encryption (default), reading the SPI flash chip yields
  the X25519 identity private key in plaintext. The attacker can then
  impersonate the device against all established peers until each peer
  re-handshakes.
- **Mitigation:** enable flash encryption (one-time eFuse burn) and
  NVS encryption. See `firmware/main/storage.c` top comment for the
  required `idf.py` invocations. Not done by default because the eFuse
  burn is irreversible and the project's user might still be iterating
  on builds.

### Post-quantum adversaries
- X25519 is broken by a sufficiently large quantum computer (Shor's
  algorithm). Captured ciphertexts today could be decrypted in 10-30
  years if quantum cryptography matures and someone bothers.
- **Not in scope for an MVP.** Post-quantum migration (Kyber/Dilithium)
  is a 1.0 question.

### A compromised Telegram client
- If Telegram itself is malicious (its app installed on your phone),
  it can read everything because Business Mode literally is the bot
  acting as your account. NoiseBox doesn't try to defend the host phone.
- This is the same trust model as Signal (you have to trust the OS).

### Skipping the SAS comparison
- If the user just smashes `y` without comparing the five words, an
  active MITM at the relay (the relay operator, or anyone who got into
  the VPS) can substitute keys in the HELLO exchange and read
  everything from then on. The five words exist precisely to make
  this attack visible. Don't skip them.

### A malicious relay operator
- The relay operator can see Telegram `user_chat_id`s, the
  who-talks-to-whom contact graph, message timestamps, and ciphertext
  sizes. They cannot see plaintext.
- They CAN attempt an active MITM during the handshake. SAS detects
  this. If the SAS words on the two Cardputers don't match, abort.
- If you don't trust the relay operator with the metadata, **run your
  own relay** — it's a one-command Docker deploy (`relay/`).

### Shared `RELAY_ID`
- Each relay publishes a `RELAY_ID` (e.g. `nb_a1b2c3d4e5f67890`). This
  is a **non-secret identifier**, intentionally safe to share alongside
  the relay host: it only gates the `/bind_poll` endpoint, not the
  Telegram bot API. Leaking it does NOT compromise the underlying
  Telegram bot.
- A leaked `RELAY_ID` allows attempting to brute-force pending 6-digit
  pair codes (the only writable thing on `/bind_poll`). This is
  rate-limited to 5 req / 10 s per IP. A botnet could conceivably
  guess specific codes within the 10-minute TTL window, but each
  successful claim still scopes the resulting device_token to a
  specific `user_chat_id` (the one that ran `/pair NNNNNN`), so the
  worst outcome is a single user's pair being hijacked — not the bot.
- The relay's `BOT_TOKEN` is what authenticates calls to Telegram's
  Bot API and is therefore the actual secret. It **stays on the VPS
  only** — not in firmware, not in flasher, not shared with users.

### Group chats
- 1:1 only. No groups in this codebase.

### Voice, video, files
- Text only. Adding files would require careful chunking + relay-side
  size limits we haven't designed.

## Reporting a vulnerability

If you find a security issue, please:

1. **Don't open a public GitHub issue** for cryptographic flaws —
   describe them in a private channel first.
2. Email: see the `Author` field in `COPYRIGHT` and find a contact via
   the GitHub profile, or open a GitHub Security Advisory on this repo
   (Security tab → Report a vulnerability) which keeps the disclosure
   private.
3. Expect a reply within ~7 days. The project is maintained by one
   person; I'm slow but I do read.

I will publicly credit you in the fix commit and in `AUDIT.md`, unless
you ask to remain anonymous.

## Past audits

- `AUDIT.md` — internal self-audit + fixes. No professional review yet.

## Things you can audit yourself

- The crypto primitives are stock mbedTLS — no homegrown math.
- `pairing.c` is the most consequential file: read it next to `bot.py`
  `_handle_pairnoise` and `peer_ghost.py` `Session.finalise`, all three
  must agree on the canonical `ikm` for handshake correctness.
- `ratchet.c` `ratchet_decrypt` does speculative-then-commit
  decryption; verify it does NOT advance state when AEAD fails.
- `session.c` `session_decode_incoming` returns -5 for HELLOs received
  in `SESSION_PAIRED`; check that this surfaces to the user as a
  warning rather than silently re-keying.
- `bot.py` `make_http_app` — every device-facing endpoint must call
  `device_auth(request)`; `/health` and `/_admin/issue_token` are the
  only `admin_auth` callers (bot_token); `/bind_poll` uses
  `relay_id_auth` (public `RELAY_ID`).
