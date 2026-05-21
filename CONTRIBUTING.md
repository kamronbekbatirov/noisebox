# Contributing

Thank you for considering a contribution. NoiseBox is a small project
maintained by one person — please read this before you spend time on a
change, because the licensing and review process have some specifics.

## License of contributions

By submitting a pull request you agree that your contribution is
licensed under **AGPL-3.0-or-later**, the same license as the project.

If your change is non-trivial (more than a few lines of fix), please
also note in the PR whether you'd be OK with the maintainer
re-licensing your code in the future (for example, dual-licensing
under a commercial license alongside AGPL-3.0). You can answer "no"
and your contribution still gets accepted under AGPL.

## What's in scope

Good first contributions:
- Bug fixes with a clear reproducer
- Better documentation (especially better threat-model writing,
  better setup steps)
- Build cleanups, missing log lines, smaller binaries
- Additional keyboard layouts, additional fonts
- Translations of UI strings
- Robustness fixes (timeouts, retry logic, edge cases)

Things to discuss in an issue *before* opening a PR:
- New cryptographic primitives or changes to the handshake protocol.
  Crypto changes need careful threat-model review; an unreviewed crypto
  patch will be closed regardless of code quality.
- Changes to the wire format (the `magic` bytes, the JSON shape).
  These break compatibility with deployed devices.
- New screens or major UI restructuring.
- Adding group chat, voice, files, video, or other features that grow
  the threat surface.

Out of scope for this repo:
- Vulnerabilities reported as public GitHub issues — see SECURITY.md.

## Code style

- C: GNU/Linux style with 4-space indent. `clang-format` would be
  great but we don't have one checked in yet. Match the surrounding
  code.
- C++: only in `display.cpp`; keep the C++ surface as small as
  possible.
- Python: PEP 8, type hints on public functions, prefer the standard
  library.
- Commits: imperative subject ("fix ratchet skip", not "fixed ratchet
  skip"). Reference an issue if any.

## Local development loop

### Firmware
```
idf.py set-target esp32s3   # once
idf.py build                # ~30s incremental
idf.py -p COM3 flash        # ~10s
idf.py -p COM3 monitor      # serial log
```

### Relay
```
cd relay
python3 -m venv venv && . venv/bin/activate
pip install -r requirements.txt
export BOT_TOKEN=...
python -u bot.py
```

### Ghost peer (for testing without a second Cardputer)
```
# On the relay, set NOISE_TEST_ADMIN=1 in .env and restart cardputer-relay.
# Then locally:
export BOT_TOKEN=...
python -u peer_ghost.py <ghost_user_chat_id> <cardputer_user_chat_id> --yes
```

The `--yes` flag auto-confirms SAS for unattended runs. Don't use it
in any real chat — that's the entire point of SAS.

## Reporting non-security bugs

GitHub issues, with:
- Cardputer or relay or ghost?
- What you ran
- What you expected
- What you saw (serial log paste is gold)
- A minimal diff to reproduce if possible

## Reporting security bugs

See `SECURITY.md`. **Do not file a public issue** for a cryptographic
flaw or anything that could be exploited against an existing user.

## A note on style of review

This is a hobby project. Reviews may take a week. PRs that ignore
prior code style or that show no awareness of the threat model will
be closed with a pointer to the docs. PRs that ship a clean test
case and a clear "here's what changed and why" usually merge in a
day.
