<h1 align="center">
  <img src="docs/brand/noisebox-mark-paper.png#gh-dark-mode-only" alt="" height="72" align="absmiddle" />
  <img src="docs/brand/noisebox-mark-ink.png#gh-light-mode-only"  alt="" height="72" align="absmiddle" />
  &nbsp;noisebox
</h1>

<p align="center">
  End-to-end encrypted messenger between two
  <strong>M5Cardputer-Adv</strong> devices,
  with Telegram Business Mode as the transport.
</p>

```
┌──────────────┐     base64 ciphertext     ┌──────────────┐
│  Cardputer   │ ◀──── via Telegram ────▶ │  Cardputer   │
│   (Alice)    │                            │    (Bob)     │
└──────┬───────┘                            └───────┬──────┘
       │  HTTPS                                     │  HTTPS
       ▼                                            ▼
┌──────────────────────────────────────────────────────────┐
│            NoiseBox relay (your VPS)                     │
│   aiohttp + Caddy + Let's Encrypt + Docker Compose       │
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
between two physical *gadgets you actually carry* and not give
Telegram's server the plaintext, you have to roll something. NoiseBox
is that something: a tiny keyboard-computer mailbox where the screen is
the only place plaintext exists.

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
   **4-DH X3DH-lite handshake** over the relay; both screens display
   the same five SAS words. The users compare words **out loud over a
   voice channel they trust** (phone call, in person, video). If words
   match, there's no MITM.
5. From that point, every message rides a **symmetric chain ratchet**
   (HKDF chain step per message) and is AEAD-encrypted with
   ChaCha20-Poly1305. Ratchet state persists in NVS so chats survive
   reboots without re-handshake.

> Since the **Bot API 10.0** update (May 2026), regular Telegram users
> without a Premium subscription can add Secretary Bots to Chat
> Automation. Premium is no longer required on either side.

## Try the demo (no server required)

If you just want to see NoiseBox work with a friend, you can borrow my
hosted relay + bot. Both of you flash your Cardputer with these
values (the [web flasher](https://kamronbekbatirov.github.io/noisebox/flash/)
has the fields right at the top of the page):

| Field | Value |
|---|---|
| **Bot in Telegram** | [`@noisebox_bot`](https://t.me/noisebox_bot) |
| **Relay host** | `cardputer.my-bots.uz` |
| **Relay ID** | `nb_606cf2042f9c1bdd` |

Then follow the **Quick start** below from step 4 onward (skip the
"Create the bot" and "Deploy the relay" steps — they're already done).

**What I see as the demo relay operator:** Telegram user IDs and
timestamps of who chats with whom, plus message sizes. I do NOT see
plaintext — that stays on your Cardputers. I MAY substitute keys
during your handshake (MITM), so the 5-word SAS comparison over a
separate channel (phone/voice) is non-optional for the demo.

**For anything sensitive, run your own relay** — `Quick start` →
section 2 below. It's a one-command Docker deploy.

## Hardware

- **M5Cardputer-Adv** (ESP32-S3FN8, 8 MB flash, 240×135 LCD, 56-key
  TCA8418 keyboard). Standard official unit, no mods needed.
- USB-C cable for flashing.

## Quick start

The fastest path: **one** of you sets up the bot + relay, then both of
you flash + bind. About 10 minutes total.

### 1. Create the bot

In Telegram, talk to [@BotFather](https://t.me/BotFather):
- `/newbot` and follow prompts (pick a username ending in `_bot`)
- Copy the issued token (looks like `1234567890:ABC...`)
- `/mybots` → choose your bot → **Bot Settings** → **Business Mode** →
  **Turn on**

### 2. Deploy the relay (Docker, recommended)

On any small VPS (1 vCPU / 512 MB / Docker installed). Pick a domain
or sub-domain pointing at the server's public IP:

```bash
git clone https://github.com/kamronbekbatirov/noisebox /opt/noisebox
cd /opt/noisebox/relay

cp .env.example .env
nano .env       # BOT_TOKEN, RELAY_ID, DOMAIN

cp Caddyfile.example Caddyfile
docker compose up -d
docker compose logs -f relay
```

Caddy automatically obtains a Let's Encrypt certificate on first run.

Three values matter in `.env`:

- **`BOT_TOKEN`** — the Telegram bot token from @BotFather. **Stays on
  this server only.** Don't put it in firmware, don't share with users.
- **`RELAY_ID`** — public-ish identifier of this relay. Friends who use
  your relay need this on their Cardputer (alongside `DOMAIN`). It is
  *not* a Telegram secret — leaking it is roughly equivalent to leaking
  your domain. Generate with `nb_$(openssl rand -hex 8)`.
- **`DOMAIN`** — your public hostname; DNS must point at this server.

Smoke-test:

```bash
TOKEN=$(grep ^BOT_TOKEN= .env | cut -d= -f2)
curl -sS https://relay.yours.example/v1/$TOKEN/health
# {"ok": true, "ts": ...}
```

<details>
<summary><strong>Manual systemd deploy</strong> (without Docker)</summary>

See [`relay/README.md`](relay/README.md) for the bare-VPS path with
`adduser`, `pip`, `systemd`, and `Caddyfile`.
</details>

### 3. Flash the firmware

#### Option A — Web Serial flasher (zero install)

1. Plug Cardputer into your laptop with USB-C.
2. Open <https://kamronbekbatirov.github.io/noisebox/flash/> in Chrome
   or Edge (Safari + Firefox don't support Web Serial).
3. **(Optional but recommended)** Fill in **Relay ID** + **Relay host**
   in the form — the page writes them straight into the device's NVS,
   so first boot skips the on-device setup screen and jumps directly
   to the bind code. (Use the demo values above to try with my relay,
   or your own from `.env` if you deployed one.)
4. Click **Connect**, pick the Cardputer's serial port, click **Flash
   latest**.

Done. ESP-IDF not required.

#### Option B — Local build

If you want to modify the firmware, you'll need
[ESP-IDF v5.4.2](https://docs.espressif.com/projects/esp-idf/en/v5.4.2/esp32s3/get-started/index.html)
installed.

```powershell
git clone https://github.com/kamronbekbatirov/noisebox C:\noisebox
cd C:\noisebox\firmware
# Optional: pre-fill a default relay ID / host so you don't have to
# type them on every fresh device. Otherwise leave config.h as-is and
# enter them on first boot (or via the web flasher's form).
copy main\config.h.example main\config.h

idf.py set-target esp32s3
idf.py build
idf.py -p COM3 flash       # adjust COMx
```

### 4. On the device: first-boot setup

Plug in, wait for the boot splash → **press enter**. Then:

1. **Wi-Fi** — pick a network, enter password.
2. **Relay setup** — type the relay's ID and domain (the relay
   operator hands you both). Saved to NVS, won't be asked again.
   **Skipped automatically** if you pre-filled them in the web flasher.
3. **Bind to your account** — device shows a 6-digit code. DM the bot
   in Telegram: `/pair NNNNNN`. The bot replies *"Code bound."*

### 5. Connect the bot to your Telegram account

The device can't relay messages until the bot has permission to read
and send DMs on your behalf. Add it once per Telegram account:

| Platform | Where |
|---|---|
| **iOS** | `Settings` → tap your name → `Edit` (top-right) → `Chat automation` → `Add bot` → pick your bot → enable both **Reply to messages** and **Access messages** |
| **Android** | `Settings` → `Telegram for Business` → `Chatbots` → `Add bot` → pick your bot → enable both toggles |

The bot will message you `✓ Business mode connected.` once permissions
are granted.

### 6. Pair two users for a chat

Both users repeat steps 3-5 with their own Cardputers. Then:

1. In your *normal Telegram chat* with the friend, one of you types
   `/pairnoise`.
2. Both receive a DM from the bot. Both reply `/accept`.
3. On each Cardputer: open the peer list → pick the friend →
   handshake runs → five SAS words appear.
4. **Phone your friend on a separate channel and compare the words.**
   *Identical on both screens* = the relay didn't substitute keys (no
   MITM). Press `y` to confirm. Pressing `n` aborts. **Don't skip this
   step** — it's the only thing standing between you and a compromised
   relay operator. See `SECURITY.md`.
5. Type and chat. Backtick (`` ` ``) is "back" on most screens.

## Day-to-day bot commands

DM to the bot:

| Command | Effect |
|---|---|
| `/start` | Onboarding text |
| `/pair NNNNNN` | Bind a Cardputer's 6-digit code to your account |
| `/peers` | List current NoiseBox peers |
| `/unpeer @user` | Remove one peer |
| `/devices` | List all Cardputers bound to your account (last-seen time) |
| `/unbind [N \| all]` | Detach one bound Cardputer (or all of them) |
| `/status` | Show business-connection status and bound device |
| `/accept`, `/reject` | Respond to incoming `/pairnoise` requests |

Sent in a regular chat with someone:

| Command | Effect |
|---|---|
| `/pairnoise` | Propose a NoiseBox peering to whoever you're chatting with |

## Keyboard cheat sheet

| Key | Effect |
|---|---|
| `;` `.` | menu cursor up / down |
| `,` `/` | left / right |
| `enter` | confirm / send |
| `` ` `` | back / cancel |
| `Aa` + key | shift (uppercase / `@`/`#`/`$`/etc.) |
| `Fn` + key | arrows (`;` → up), esc (`` ` ``), del |

## Project layout

```
firmware/           ESP-IDF v5.4.2 project for the Cardputer
  main/
    crypto.c            X25519 / ChaCha20-Poly1305 / HKDF wrappers
    pairing.c           4-DH X3DH-lite handshake + SAS transcript
    ratchet.c           symmetric chain ratchet
    session.c           glue: handshake state + ratchet + persistence
    storage.c           NVS layout (identity, peers, relay config)
    transport.c         HTTPS client to relay
    wifi.c              station + scan + creds in NVS
    display.cpp         M5GFX wrapper, 8x16 bitmap font renderer
    keyboard.c          TCA8418 I2C driver + keymap
    ui.c                splash, title / menu / text input / spinner
    main.c              top-level FSM and per-screen logic
relay/
  bot.py              aiohttp app: Telegram polling + device HTTP API
  Dockerfile          one-command relay image
  docker-compose.yml  relay + caddy + Let's Encrypt
  Caddyfile.example   TLS termination for the Docker stack
  peer_ghost.py       test client: simulates a second Cardputer
docs/                 source for the GitHub Pages site
  index.html          https://kamronbekbatirov.github.io/noisebox/
  flash/index.html    web serial flasher (esptool-js + NVS encoder)
  firmware/           mirrored release binaries served same-origin
  brand/              ink + paper PNG logos
  m5_keyboard_reference/  upstream M5 keymap we ported from
.github/
  workflows/          CI: builds firmware, publishes release, mirrors
                      binaries to docs/firmware/ on every tag
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
