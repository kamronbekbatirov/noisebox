# Third-party components

NoiseBox bundles, ports, or depends on the following third-party code.
Each is governed by its own upstream license; this file is the
attribution required by those licenses.

## Bundled / vendored

### M5GFX

- **What:** C++ graphics library by M5Stack. The Cardputer-Adv LCD
  driver in `firmware/main/display.cpp` calls into M5GFX directly via
  the ESP-IDF component manager (`firmware/main/idf_component.yml`).
- **License:** MIT
- **Upstream:** https://github.com/m5stack/M5GFX
- **Copyright:** © M5Stack Technology Co., Ltd.

### M5Cardputer-UserDemo keymap

- **What:** the layout of the 56-key TCA8418 matrix, the modifier
  detection logic, and the Fn-layer table in `firmware/main/keyboard.c`
  are a C port of the matching `keyboard.cpp` / `keymap.h` from the
  M5Cardputer-UserDemo project's `CardputerADV` branch. The original
  files are preserved verbatim under `docs/m5_keyboard_reference/`
  for reference and to satisfy the MIT preserve-notice requirement.
- **License:** MIT
- **Upstream:** https://github.com/m5stack/M5Cardputer-UserDemo
  (branch `CardputerADV`, path `main/hal/keyboard/`)
- **Copyright:** © 2025 M5Stack Technology Co., Ltd.

### font8x8

- **What:** the bitmap font in `firmware/main/font8x16.c` was
  auto-generated from `font8x8_basic.h` by Daniel Hepper, with each
  row doubled to make 8×16 glyphs.
- **License:** Public Domain
- **Upstream:** https://github.com/dhepper/font8x8
- **Attribution:** Daniel Hepper, based on a font from "Marcel Sondaar
  / International Business Machines" (public domain VGA fonts)

## Build-time dependencies (not bundled, fetched at build)

### ESP-IDF

- **What:** the build framework, FreeRTOS, mbedTLS, ESP-LCD, ESP-TLS,
  ESP-HTTP-Client, NVS, and Wi-Fi stacks.
- **License:** Apache-2.0 (with parts under other compatible licenses;
  see `LICENSE` files in the ESP-IDF tree)
- **Upstream:** https://github.com/espressif/esp-idf
- **Copyright:** © 2015-present Espressif Systems

### cJSON

- **What:** the C JSON parser used by `transport.c`. Pulled in as an
  ESP-IDF component.
- **License:** MIT
- **Upstream:** https://github.com/DaveGamble/cJSON

## Runtime dependencies of the relay (`relay/`)

### aiohttp

- **License:** Apache-2.0
- **Upstream:** https://github.com/aio-libs/aiohttp

### Python cryptography

- **License:** Apache-2.0 OR BSD-3-Clause (dual)
- **Upstream:** https://github.com/pyca/cryptography
- **Used by:** `peer_ghost.py` only. The relay itself does no crypto.

### requests

- **License:** Apache-2.0
- **Upstream:** https://github.com/psf/requests
- **Used by:** `peer_ghost.py` only.

### Caddy

- **License:** Apache-2.0
- **Upstream:** https://github.com/caddyserver/caddy
- **Role:** TLS termination + Let's Encrypt issuance in front of the
  relay. Not bundled, installed via the user's package manager.

---

## AGPL-3.0 and these licenses

AGPL-3.0 is compatible with all of the above (Apache-2.0, MIT, BSD,
Public Domain). When you redistribute NoiseBox, you must keep this
attribution file intact. M5GFX-licensed code, the M5 keymap port, and
the font8x8 glyphs retain their original licenses; the AGPL covers
only the NoiseBox-original parts of the codebase.
