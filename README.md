# NoiseBox

End-to-end encrypted messenger between two **M5Cardputer-Adv** devices,
with Telegram Business Mode as the transport.

```
┌──────────────┐     base64 ciphertext     ┌──────────────┐
│  Cardputer   │ ◀──── via Telegram ────▶ │  Cardputer   │
│   (Alice)    │                            │    (Bob)     │
└──────┬───────┘                            └───────┬──────┘
       │  HTTPS                                     │  HTTPS
       ▼                                            ▼
┌──────────────────────────────────────────────────────────┐
│            NoiseBox relay (your VPS)                     │
│   aiohttp + Caddy + Let's Encrypt + systemd              │
│   never sees plaintext, only opaque base64               │
└──────────────────────────────────────────────────────────┘
                            │
                            ▼  Bot API
                  ┌──────────────────┐
                  │   Telegram       │
                  └──────────────────┘
```

The relay never decrypts anything: only the two Cardputers hold the
ratchet keys derived from an in-person SAS-verified X25519 handshake.

---

## Status

**MVP. Released after a self-audit, has not been reviewed by an
independent professional cryptographer.** Use it with friends, not for
anything you'd risk a court case over. See
[`SECURITY.md`](SECURITY.md) and [`AUDIT.md`](AUDIT.md) for the threat
model and the audit findings (and the fixes that were shipped).

## Why

Telegram chats are not end-to-end encrypted by default. Only "secret
chats" are E2E, and only between Telegram clients. If you want to chat
between two physical *gadgets you actually carry* and not give Telegram's
server the plaintext, you have to roll something. NoiseBox is that
something: a tiny keyboard-computer mailbox where the screen is the only
place plaintext exists.

## How it works

1. Each Cardputer holds a long-term **X25519 identity** key (created on
   first boot, persisted in NVS).
2. To talk to a friend, both users **connect the same bot** to their
   Telegram account via *Telegram for Business → Chatbots*. The bot can
   now read & send on their behalf, but only opaque base64.
3. One side types `/pairnoise` in the regular Telegram chat with the
   other. Both get a DM from the bot asking to `/accept`. After both
   accept, the bot remembers them as peers.
4. Each user selects the peer on their Cardputer. The two devices run a
   **4-DH X3DH-lite handshake** over the relay; both screens display the
   same five SAS words (`DOG CAT FOX BEAR LION`-style).  The users
   compare words **out loud over a voice channel they trust** (phone
   call, in person, video). If words match, there's no MITM.
5. From that point, every message rides a **symmetric chain ratchet**
   (HKDF chain step per message) and is AEAD-encrypted with
   ChaCha20-Poly1305. Ratchet state persists in NVS so chats survive
   reboots without re-handshake.

## Hardware

- **M5Cardputer-Adv** (ESP32-S3FN8, 8 MB flash, 240x135 LCD, 56-key
  TCA8418 keyboard).  No PSRAM.
- Standard official one, no mods needed.
- USB-C cable for flashing.
- (Optional but recommended) An SD card slot is on the device but
  unused by NoiseBox today.

## Software prerequisites

### For the firmware
- Windows / macOS / Linux
- **ESP-IDF v5.4.2** (other 5.4.x should work, untested)
- Python 3.11 (auto-installed by Espressif's installer)

### For the relay
- Any small VPS (1 vCPU, 512 MB RAM is plenty)
- Python 3.10+
- Caddy 2 (TLS termination, auto Let's Encrypt)
- A domain pointing at the VPS
- A Telegram bot via [@BotFather](https://t.me/BotFather) with
  **Business Mode enabled** (`/mybots` → bot → Bot Settings →
  Business Mode → Turn on)

## Quick start

### 1. Create the bot

In Telegram, talk to [@BotFather](https://t.me/BotFather):
- `/newbot` and follow prompts (pick a username ending in `_bot`)
- Copy the issued token (looks like `1234567890:ABC...`)
- `/mybots` → choose your bot → **Bot Settings** → **Business Mode** →
  **Turn on**

### 2. Deploy the relay on your VPS

```bash
# As root, one-time:
adduser --system --group --home /opt/cardputer-relay cardputer
cd /opt/cardputer-relay
git clone https://github.com/<YOU>/noisebox .
chown -R cardputer:cardputer /opt/cardputer-relay

# venv + deps
sudo -u cardputer python3 -m venv venv
sudo -u cardputer ./venv/bin/pip install -r relay/requirements.txt

# env (paste your bot token)
cp relay/.env.example /opt/cardputer-relay/.env
nano /opt/cardputer-relay/.env
chmod 600 /opt/cardputer-relay/.env
chown cardputer:cardputer /opt/cardputer-relay/.env

# systemd
cp relay/cardputer-relay.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now cardputer-relay
journalctl -u cardputer-relay -f
```

Caddy block (append to `/etc/caddy/Caddyfile`, edit hostname):

```Caddyfile
noisebox.your-domain.example.com {
    @long_poll path_regexp ^/v1/[^/]+/poll$
    reverse_proxy @long_poll localhost:8081 {
        transport http {
            read_timeout 65s
        }
    }
    reverse_proxy localhost:8081
}
```

Then:
```bash
caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
systemctl reload caddy
```

Smoke-test:
```bash
TOKEN=$(. /opt/cardputer-relay/.env; echo $BOT_TOKEN)
curl -sS https://noisebox.your-domain.example.com/v1/$TOKEN/health
# {"ok": true, "ts": ...}
```

### 3. Build and flash the firmware

In a path WITHOUT spaces (M5GFX's CMake doesn't like spaces):

```powershell
# Get a fresh copy in a clean path
git clone https://github.com/<YOU>/noisebox C:\noisebox

# Fill in config.h
cd C:\noisebox\firmware\main
copy config.h.example config.h
notepad config.h
# Set NOISE_BOT_TOKEN  = your bot token from BotFather
# Set NOISE_RELAY_HOST = noisebox.your-domain.example.com
```

Open the **ESP-IDF 5.4.2 PowerShell** shortcut from the Start Menu, then:

```powershell
cd C:\noisebox\firmware
idf.py set-target esp32s3
idf.py build
idf.py -p COM3 flash monitor
```

(`COM3` may differ for you — check Device Manager. The Cardputer
exposes itself as "USB Serial Device".)

### 4. Connect the bot to each user's Telegram account

This is the step that makes the whole "Telegram as a dumb pipe" pattern
work. Every user who wants to chat over NoiseBox has to grant their
bot — the one they (or you) created in @BotFather with **Business
Mode** turned on — permission to read and send on their behalf, through
**Telegram for Business → Chat Automation / Chatbots**. The bot only
ever sees opaque base64; it cannot read NoiseBox plaintext. But the
permission has to be granted for the carrier to work at all.

> Since the Bot API 10.0 update (May 2026), **regular Telegram users
> without a Premium subscription** can add Secretary Bots to Chat
> Automation, granting the bot permission to read and send messages on
> their behalf in DMs. Premium is no longer required on either side.

In the Telegram client, DM the bot once and send `/start`. The bot
replies with platform-specific instructions; reproduced here for
reference:

**On iOS:**
1. `Settings` → tap your profile name at the top
2. `Edit` (top-right) → `Chat automation`
3. `Add bot` → search for your bot's username (e.g. `@noisebox_bot`)
   and pick it
4. Enable **both** toggles:
   - ✅ **Reply to messages**
   - ✅ **Access messages**
5. Tap `Done`.

**On Android:**
1. `Settings` → `My Account` → `Telegram for Business`
2. `Chatbots` → `Add bot` → search for your bot's username and pick it
3. Enable **both** toggles:
   - ✅ **Reply to messages**
   - ✅ **Access messages**
4. Tap the checkmark / `Done`.

The bot should now message you `✓ Business mode connected. Now /pair
NNNNNN to bind a device.` If it doesn't, double-check that both
toggles are on and that the bot has **Business Mode** enabled in
@BotFather (`/mybots` → bot → Bot Settings → Business Mode).

You can remove the bot from Chat Automation any time; your `/pair`
binding and peer list survive on the relay and re-attach automatically
when you re-add the bot.

### 5. Bind a Cardputer to your account

On power-on the Cardputer:
1. Runs the **Wi-Fi picker** — choose your network, type the password,
   it saves to NVS so next boot is automatic.
2. Shows **Bind to your account** with a 6-digit code.
3. DM your bot in Telegram: `/pair NNNNNN` (the code shown). The bot
   replies `✓ Code bound. Device is now linked to you.` The Cardputer
   claims a per-device bearer token from the relay and stores it.

If the screen shows `code expired - regenerating` repeatedly, your
device is being rate-limited (5 req/10 s per IP) — wait ~10 seconds
and the next code should bind.

### 6. Pair two users for a chat

Both users repeat steps 4 and 5 on their own Telegram accounts and
their own Cardputers. Then:

1. In your *normal Telegram chat with the friend*, one of you types
   `/pairnoise`.
2. Both of you receive a DM from the bot:
   `📡 NoiseBox pair request from @<friend>. Reply /accept or /reject.`
3. Both reply `/accept` in that DM.
4. On each Cardputer, open the peer list → pick the friend → handshake
   runs → five SAS words appear on both screens
   (e.g. `DOG FOX BEAR LION PANDA`).
5. **Phone your friend on a separate channel and compare the words.**
   *Identical on both screens* = the relay didn't substitute keys
   (no MITM). Press `y` to confirm. Pressing `n` aborts. **Don't
   skip this step** — it's the only thing standing between you and a
   compromised bot token or relay operator. See `SECURITY.md`.
6. Type and chat. Backtick (`` ` ``) is "back" on most screens.

### 7. Day-to-day commands

Sent as a DM to the bot:

| Command           | Effect                                                            |
|-------------------|-------------------------------------------------------------------|
| `/start`          | The full onboarding text shown above.                             |
| `/pair NNNNNN`    | Bind a Cardputer's 6-digit code to your Telegram account.         |
| `/peers`          | List your current NoiseBox peers.                                 |
| `/unpeer @user`   | Remove one peer (or `/unpair @user` — alias).                     |
| `/unbind`         | Detach the currently-bound Cardputer from your account.           |
| `/status`         | Show business-connection status and bound device.                 |
| `/accept`         | Confirm an incoming `/pairnoise` request.                         |
| `/reject`         | Decline an incoming `/pairnoise` request.                         |

Sent in a regular Telegram chat with someone:

| Command         | Effect                                                              |
|-----------------|---------------------------------------------------------------------|
| `/pairnoise`    | Propose a NoiseBox peering to whoever you're chatting with.         |

## Keyboard cheat sheet

| Key            | Effect                                       |
|----------------|----------------------------------------------|
| `;`            | menu cursor up                               |
| `.`            | menu cursor down                             |
| `,` `/`        | left / right                                 |
| `enter`        | confirm / send                               |
| `` ` ``        | back / cancel                                |
| `Aa` + key     | shift (uppercase / `@`/`#`/`$`/etc.)         |
| `Fn` + key     | arrows (`;` → up), esc (`` ` ``), del        |

## Project layout

```
firmware/           ESP-IDF v5.4.2 project for the Cardputer
  main/
    crypto.c            X25519 / ChaCha20-Poly1305 / HKDF wrappers
    pairing.c           4-DH X3DH-lite handshake + SAS transcript
    ratchet.c           symmetric chain ratchet
    session.c           glue: handshake state + ratchet + persistence
    storage.c           NVS layout (identity, peers, device token)
    transport.c         HTTPS client to relay
    wifi.c              station + scan + creds in NVS
    display.cpp         M5GFX wrapper, 8x16 bitmap font renderer
    keyboard.c          TCA8418 I2C driver + keymap
    ui.c                title / menu / text input / spinner primitives
    main.c              top-level FSM and per-screen logic
relay/
  bot.py              aiohttp app: Telegram polling + device HTTP API
  peer_ghost.py       test client: simulates a second Cardputer
  cardputer-relay.service  systemd unit
docs/
  m5_keyboard_reference/  the upstream M5 keymap we ported from
```

## Threat model (one-paragraph version, full in SECURITY.md)

We protect message contents against passive eavesdroppers (Wi-Fi,
ISP), against the relay operator (us), and against Telegram. We
require users to compare the 5 SAS words out-of-band to defend
against an active MITM at the relay. We do NOT hide metadata: the
relay and Telegram both see who exchanges messages and when. We do
NOT defend against an adversary with physical access to a powered-on
unlocked Cardputer (no PIN yet). We do NOT defend against quantum
adversaries (no post-quantum). Flash encryption is supported but
**off by default** — enabling it requires a one-time eFuse burn. See
`SECURITY.md`.

## Contributing

Pull requests welcome — see [`CONTRIBUTING.md`](CONTRIBUTING.md).
Please keep all contributions under AGPL-3.0; the project requires a
basic contributor agreement if it would block future relicensing.

## License

[**AGPL-3.0-or-later**](LICENSE). If you run a public service based on
this code, you must publish your modifications. See
[`COPYRIGHT`](COPYRIGHT) for the long form and `THIRD_PARTY.md` for
upstream attributions.

## Acknowledgments

- [M5Stack](https://github.com/m5stack) for the Cardputer-Adv hardware
  and the open-source M5GFX library + reference firmware whose keymap
  we ported.
- [Daniel Hepper](https://github.com/dhepper/font8x8) for the public
  domain 8x8 font.
- [Trevor Perrin](https://noiseprotocol.org/) and [Moxie
  Marlinspike](https://signal.org/docs/) — NoiseBox borrows ideas
  (transcript-based SAS, symmetric chain ratchet) directly from the
  Noise Protocol Framework and the Signal Protocol whitepapers.
- The Telegram team for shipping Business Mode API support without
  Premium gating — it's what makes the "Telegram as a dumb pipe"
  pattern realistic.
