# NoiseBox relay

A dumb base64 forwarder between two M5Cardputer-Adv devices, with
Telegram Business Mode as the carrier. The relay **never** sees
plaintext: every payload it forwards is opaque base64. See the top-level
[`README.md`](../README.md) and [`SECURITY.md`](../SECURITY.md) for the
full picture and threat model.

## What it does

- Polls Telegram for `business_message` updates (so the bot can read &
  send on behalf of a user who connected it via *Telegram for Business
  → Chatbots*).
- DM commands `/pair NNNNNN`, `/pairnoise`, `/accept`, `/reject`,
  `/unpair`, `/status` to bind devices, agree on peers, and tear down
  peering.
- Exposes an HTTP API consumed by the Cardputer firmware:
  - `/v1/<bot_token>/bind_poll` — claim a 6-digit pair code in exchange
    for a per-device bearer token (rate-limited 5 req/10 s/IP).
  - `/v1/<device_token>/peers|send|poll|info` — device-scoped endpoints
    authenticated by the per-device bearer token issued at bind time.
- Persists state to `state.json` via `flush+fsync+os.replace` so it
  survives restarts and VPS crashes.

## Quick deploy

The full step-by-step (Caddy, systemd, Let's Encrypt) is in the
top-level [`README.md`](../README.md). The TL;DR:

```bash
adduser --system --group --home /opt/cardputer-relay cardputer
cd /opt/cardputer-relay && git clone https://github.com/<you>/noisebox .
chown -R cardputer:cardputer /opt/cardputer-relay
sudo -u cardputer python3 -m venv venv
sudo -u cardputer ./venv/bin/pip install -r relay/requirements.txt
cp relay/.env.example .env && nano .env   # paste BOT_TOKEN
chmod 600 .env && chown cardputer:cardputer .env
cp relay/cardputer-relay.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now cardputer-relay
journalctl -u cardputer-relay -f
```

Put Caddy in front for TLS termination (see the top-level README for
the Caddyfile snippet).

## Local development

```bash
python3 -m venv venv && . venv/bin/activate
pip install -r requirements.txt
export BOT_TOKEN=...               # token from @BotFather
python -u bot.py                   # listens on 127.0.0.1:8081
```

For end-to-end testing without a second Cardputer, see
[`peer_ghost.py`](peer_ghost.py) — a software-only counterpart that
implements the same wire protocol as the firmware (4-DH X3DH-lite
handshake, symmetric chain ratchet, ChaCha20-Poly1305 AEAD).

```bash
export BOT_TOKEN=...
export NOISE_RELAY_URL=https://your-relay-domain.example.com
# Requires NOISE_TEST_ADMIN=1 set in the relay's .env.
python -u peer_ghost.py <ghost_user_chat_id> <cardputer_user_chat_id> --yes
```

The `--yes` flag auto-confirms the SAS comparison for unattended runs.
Don't use it against a real peer — that's the entire point of SAS.

## What the relay sees, and what it doesn't

| Visible to the relay        | Not visible to the relay              |
|-----------------------------|---------------------------------------|
| Telegram `user_chat_id`s    | Plaintext of any message              |
| `peer_user_id` mappings     | Long-term X25519 identity keys        |
| Per-message size & timestamp| Ratchet state                         |
| Per-device bearer tokens    | SAS verification words (only on-device)|

If you don't trust your relay operator with knowing your contact graph,
run your own — it's < 200 lines of aiohttp.
