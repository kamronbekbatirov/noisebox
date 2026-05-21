# SPDX-License-Identifier: AGPL-3.0-or-later
# NoiseBox -- end-to-end encrypted Cardputer messenger.
# Copyright (C) 2026 Kamronbek B. See LICENSE for the full text.

"""
Cardputer secure messenger - VPS relay bot.

User flow:
  1) Owner enables Business Mode for the bot in @BotFather.
  2) Each user adds the bot via Telegram Settings -> Telegram for Business
     -> Chatbots, granting 'Reply' + 'Access messages'.
  3) Each user binds their Cardputer to their account:
        Cardputer shows a 6-digit code on first boot.
        User DMs the bot:  /pair NNNNNN
     Bot stores: code -> user_chat_id; Cardputer polls /v1/bind_poll
     and learns its owner's user_chat_id.
  4) Two users start a Noise channel by:
        - typing  /pairnoise  in their normal Telegram chat with each other
        - both getting an /accept prompt in DM from this bot
        - both replying  /accept  (or /accept @peer if multiple pending)
     Bot then stores them as mutual peers. Cardputers fetch the peer list
     and run their X25519 handshake + SAS confirmation over /send + /poll.

HTTP API (all under /v1/<bot_token>/):
    GET  /health
        -> {"ok": true, "ts": ...}

    GET  /peers?user_chat_id=<int>
        -> {"ok": true, "peers": [{"user_id":..., "first_name":..., ...}, ...]}

    POST /send
        body: {"user_chat_id": <int>, "peer_user_id": <int>, "text": <str>}
        -> {"ok": true, "delivered_to_inbox": <int>}
        Sends `text` from user_chat_id's business connection to peer_user_id.
        Mirrors a copy into peer's inbox immediately (Telegram does NOT echo
        business-initiated sends back to the bot).

    GET  /poll?user_chat_id=<int>&after=<int>&timeout=<sec 0..50>
        -> {"ok": true, "messages": [{"id":N,"from":<int>,"text":...,"ts":...}], "head_id": ...}

    GET  /info?user_chat_id=<int>
        -> diagnostic dump.

    GET  /bind_poll?code=<6 digits>
        -> {"ok": true, "bound": true, "user_chat_id": <int>}     - success
        -> {"ok": true, "bound": false}                            - still pending
        -> {"ok": false, "error": "expired"}                       - too late

State persisted to STATE_FILE (JSON). Survives systemd restarts.
Inboxes are intentionally ephemeral - long-poll clients catch up by
re-reading on reconnect; missed messages while relay is offline are
expected to be re-delivered via Telegram's business_message stream on
restart (offset is persisted too).
"""

from __future__ import annotations

import asyncio
import hmac
import json
import logging
import os
import secrets
import sys
import time
from collections import defaultdict, deque
from typing import Deque, Dict, List, Optional, Tuple

import aiohttp
from aiohttp import web

API = "https://api.telegram.org/bot{token}/{method}"

log = logging.getLogger("relay")

MAX_QUEUE_PER_USER = 256
POLL_MAX_TIMEOUT_S = 50
STATE_FILE = os.environ.get("STATE_FILE", "state.json")
PENDING_PAIR_TTL_S = 3600          # 1 hour to /accept
PENDING_DEVICE_BIND_TTL_S = 600    # 10 minutes for Cardputer to claim a code


def now_ts() -> int:
    return int(time.time())


# --------------------------------------------------------------------- inbox --

class UserInbox:
    def __init__(self):
        self.head_id: int = 0
        self.messages: Deque[dict] = deque(maxlen=MAX_QUEUE_PER_USER)
        self.event = asyncio.Event()

    def push(self, from_user_id: int, text: str):
        self.head_id += 1
        self.messages.append({
            "id": self.head_id,
            "from": from_user_id,
            "text": text,
            "ts": now_ts(),
        })
        self.event.set()

    def fetch_after(self, after: int) -> List[dict]:
        return [m for m in self.messages if m["id"] > after]


# --------------------------------------------------------------------- relay --

class Relay:
    def __init__(self, token: str):
        self.token = token
        self.session: Optional[aiohttp.ClientSession] = None

        # Telegram-side state
        self.user_to_conn: Dict[int, str] = {}
        self.conn_to_user: Dict[str, int] = {}

        # Peers: user_id -> {peer_user_id -> peer_info dict}
        self.peers: Dict[int, Dict[int, dict]] = defaultdict(dict)

        # Pending pair requests: (min_id, max_id) -> {a, b, a_info, b_info,
        # accepted_by(set), created_at, expires_at}
        self.pending_pair: Dict[Tuple[int, int], dict] = {}

        # Device-binding codes: code(str) -> {user_chat_id, expires_at, claimed,
        #                                      device_token}
        # device_token is generated when the user runs /pair NNNNNN; the
        # Cardputer claims it via /v1/<bot_token>/bind_poll and persists it
        # in NVS. Subsequent device API calls use the device_token directly
        # (not the bot_token).
        self.pending_device_bind: Dict[str, dict] = {}
        self.user_to_device_code: Dict[int, str] = {}

        # device_token -> user_chat_id (active bindings). Loaded from state
        # on startup.
        self.device_to_user: Dict[str, int] = {}

        # device_token -> unix-ts of the last authenticated API hit. Lets
        # /devices show "last seen N minutes ago" so the user can tell
        # which token corresponds to a Cardputer that's actually around.
        self.device_last_seen: Dict[str, int] = {}

        # IP rate limit for unauthenticated /bind_poll calls. Maps IP to
        # (window_start_ts, count). Reset every 10 seconds.
        self.bind_rl: Dict[str, Tuple[int, int]] = {}

        # Inboxes (ephemeral)
        self.inboxes: Dict[int, UserInbox] = {}

        self.offset = 0
        self._load_state()

    # --- persistence ---

    def _load_state(self):
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                st = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return
        self.user_to_conn = {int(k): v for k, v in st.get("user_to_conn", {}).items()}
        self.conn_to_user = {k: int(v) for k, v in st.get("conn_to_user", {}).items()}
        for k, v in st.get("peers", {}).items():
            self.peers[int(k)] = {int(pk): pv for pk, pv in v.items()}
        for k, v in st.get("pending_pair", {}).items():
            a, b = (int(x) for x in k.split(","))
            v["accepted_by"] = set(v.get("accepted_by", []))
            self.pending_pair[(a, b)] = v
        self.pending_device_bind = st.get("pending_device_bind", {}) or {}
        self.user_to_device_code = {int(k): v for k, v in st.get("user_to_device_code", {}).items()}
        self.device_to_user      = {k: int(v) for k, v in st.get("device_to_user", {}).items()}
        self.device_last_seen    = {k: int(v) for k, v in st.get("device_last_seen", {}).items()}
        self.offset = int(st.get("offset", 0))
        log.info(
            "loaded state: users=%d peers_entries=%d pending_pairs=%d offset=%d",
            len(self.user_to_conn),
            sum(len(p) for p in self.peers.values()),
            len(self.pending_pair),
            self.offset,
        )

    def _save_state(self):
        tmp = STATE_FILE + ".tmp"
        st = self._snapshot_state()
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(st, f, separators=(",", ":"))
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, STATE_FILE)

    def _snapshot_state(self) -> dict:
        st = {
            "user_to_conn": self.user_to_conn,
            "conn_to_user": self.conn_to_user,
            "peers": {
                str(k): {str(pk): pv for pk, pv in v.items()}
                for k, v in self.peers.items()
            },
            "pending_pair": {
                f"{k[0]},{k[1]}": {**v, "accepted_by": sorted(v["accepted_by"])}
                for k, v in self.pending_pair.items()
            },
            "pending_device_bind": self.pending_device_bind,
            "user_to_device_code": self.user_to_device_code,
            "device_to_user":      self.device_to_user,
            "device_last_seen":    self.device_last_seen,
            "offset": self.offset,
        }
        return st

    # --- helpers ---

    def get_inbox(self, user_chat_id: int) -> UserInbox:
        ib = self.inboxes.get(user_chat_id)
        if ib is None:
            ib = UserInbox()
            self.inboxes[user_chat_id] = ib
        return ib

    @staticmethod
    def pair_key(a: int, b: int) -> Tuple[int, int]:
        return (min(a, b), max(a, b))

    def is_peer(self, owner: int, peer: int) -> bool:
        return peer in self.peers.get(owner, {})

    @staticmethod
    def display_name(info: dict) -> str:
        fn = (info or {}).get("first_name", "") or ""
        ln = (info or {}).get("last_name", "") or ""
        un = (info or {}).get("username", "") or ""
        name = (fn + " " + ln).strip() or "Unknown"
        if un:
            name += f" (@{un})"
        return name

    def prune_pending(self):
        """Drop expired pending pairs and device codes."""
        t = now_ts()
        expired = [k for k, v in self.pending_pair.items() if v.get("expires_at", 0) < t]
        for k in expired:
            self.pending_pair.pop(k, None)
        expired_codes = [c for c, v in self.pending_device_bind.items() if v.get("expires_at", 0) < t]
        for c in expired_codes:
            self.pending_device_bind.pop(c, None)
        if expired or expired_codes:
            self._save_state()

    # --- Telegram HTTP helpers ---

    async def call(self, method: str, **params):
        url = API.format(token=self.token, method=method)
        async with self.session.post(
            url, json=params, timeout=aiohttp.ClientTimeout(total=65)
        ) as r:
            data = await r.json()
            if not data.get("ok"):
                log.warning("api %s error: %s", method, data)
            return data

    async def tg_send(self, chat_id: int, text: str, **extra):
        return await self.call("sendMessage", chat_id=chat_id, text=text, **extra)

    async def tg_send_as_business(self, business_connection_id: str,
                                  chat_id: int, text: str):
        return await self.call(
            "sendMessage",
            business_connection_id=business_connection_id,
            chat_id=chat_id, text=text,
        )

    async def fetch_user_info(self, chat_id: int) -> dict:
        """One-shot getChat to grab first_name/last_name/username.

        Used when a /pairnoise event is delivered from one user's business
        connection but doesn't carry the owner's display name in the
        payload (Telegram only embeds the SENDER's user info, not the
        owner's). Calling getChat fills the blanks so the on-device peer
        list shows real names instead of bare numeric IDs.
        """
        r = await self.call("getChat", chat_id=chat_id)
        if not r.get("ok"):
            return {"user_id": chat_id}
        c = r.get("result", {}) or {}
        return {
            "user_id": chat_id,
            "first_name": c.get("first_name", ""),
            "last_name":  c.get("last_name",  ""),
            "username":   c.get("username",   ""),
        }

    @staticmethod
    def _info_is_thin(info: dict) -> bool:
        """True if a peer-info dict has nothing displayable beyond ID."""
        return not (
            (info.get("first_name") or "").strip()
            or (info.get("last_name") or "").strip()
            or (info.get("username") or "").strip()
        )

    # --- DM commands ---

    async def cmd_start(self, chat_id: int):
        await self.tg_send(chat_id, (
            "Hi! NoiseBox - end-to-end encrypted text between two Cardputers,\n"
            "carried by Telegram. The bot only sees base64 garbage; only the\n"
            "devices can read messages.\n\n"
            "STEP 1.  Connect me to your Telegram account (one-time).\n\n"
            "   iOS:\n"
            "     Settings -> My Profile -> Edit (top-right) ->\n"
            "     Chat automation -> add @noisebox_bot ->\n"
            "     enable 'Reply to messages' and 'Access messages'\n\n"
            "   Android:\n"
            "     Settings -> My Account -> Telegram for Business ->\n"
            "     Chatbots -> add @noisebox_bot ->\n"
            "     enable 'Reply to messages' and 'Access messages'\n\n"
            "STEP 2.  Bind your Cardputer to you (one-time per device).\n"
            "     Power on the device; it shows a 6-digit code.\n"
            "     Send here:   /pair NNNNNN\n\n"
            "STEP 3.  Connect with a friend (one-time per friend).\n"
            "     In your normal Telegram chat with the friend, one of you\n"
            "     types     /pairnoise\n"
            "     I will DM each of you. Reply  /accept  to confirm.\n"
            "     Then the friend shows up on your Cardputer.\n\n"
            "FAQ:\n"
            " - If you remove the bot from Chatbots and re-add it later,\n"
            "   your /pair binding and peers are kept.\n"
            " - To swap Cardputers: on the new device, go Settings ->\n"
            "   'Unbind device', power-cycle, then /pair the new code.\n\n"
            "Commands: /peers, /unpeer @user, /unbind, /status."
        ))

    async def cmd_pair(self, chat_id: int, arg: str):
        code = arg.strip()
        if not (code.isdigit() and len(code) == 6):
            await self.tg_send(chat_id,
                "Usage: /pair NNNNNN (the 6-digit code shown on your Cardputer).")
            return
        # Clear any previous code for this user
        old = self.user_to_device_code.get(chat_id)
        if old and old in self.pending_device_bind:
            if self.pending_device_bind[old].get("user_chat_id") == chat_id:
                self.pending_device_bind.pop(old, None)
        # Pre-generate the per-device bearer token. The Cardputer fetches
        # it on its next /bind_poll and stores it in NVS; subsequent device
        # API calls present THIS token (not the shared bot_token).
        device_token = secrets.token_urlsafe(32)
        self.pending_device_bind[code] = {
            "user_chat_id": chat_id,
            "expires_at": now_ts() + PENDING_DEVICE_BIND_TTL_S,
            "claimed": False,
            "device_token": device_token,
        }
        self.user_to_device_code[chat_id] = code
        self._save_state()
        await self.tg_send(chat_id,
            f"✓ Code {code} bound. The Cardputer should pick this up shortly.\n"
            f"(Code expires in 10 minutes if the device doesn't claim it.)")

    async def cmd_peers(self, chat_id: int):
        peers = self.peers.get(chat_id, {})
        if not peers:
            await self.tg_send(chat_id,
                "No peers yet. Type /pairnoise in a Telegram chat with a friend.")
            return
        lines = ["Your peers:"]
        for peer_id, info in peers.items():
            lines.append(f"  • {self.display_name(info)}  [id={peer_id}]")
        await self.tg_send(chat_id, "\n".join(lines))

    async def cmd_unpeer(self, chat_id: int, arg: str):
        peer_id = self._resolve_peer(chat_id, arg, prefer="established")
        if peer_id is None:
            await self.tg_send(chat_id, "Couldn't find that peer. Use /peers to list.")
            return

        # Capture info about both sides BEFORE we delete so we can DM the
        # other party with a friendly notice.
        my_info  = self.peers.get(peer_id, {}).get(chat_id)
        their_info = self.peers.get(chat_id, {}).get(peer_id)

        self.peers.get(chat_id, {}).pop(peer_id, None)
        self.peers.get(peer_id, {}).pop(chat_id, None)
        self._save_state()

        await self.tg_send(chat_id,
            f"Removed {self.display_name(their_info)}.\n"
            "They've been notified that the secure channel is closed.")

        # Notify the other side. They may have the bot blocked or not /start'd,
        # so we wrap in try/except.
        try:
            await self.tg_send(peer_id,
                f"{self.display_name(my_info)} closed the NoiseBox channel "
                f"with you.\n"
                f"Your Cardputer can no longer reach them until you both "
                f"/pairnoise again.")
        except Exception:
            pass

    async def cmd_unpair(self, chat_id: int, arg: str):
        # alias for /unpeer - "unpair" is what users actually look for
        return await self.cmd_unpeer(chat_id, arg)

    # ---- /devices and /unbind -------------------------------------------

    def _devices_for(self, chat_id: int):
        """All active device_tokens for `chat_id`, freshest first.
        Returns a list of (token, last_seen_ts) tuples."""
        out = [(tok, self.device_last_seen.get(tok, 0))
               for tok, uid in self.device_to_user.items()
               if uid == chat_id]
        # Most-recently-seen first; never-seen sinks to the bottom.
        out.sort(key=lambda x: -x[1])
        return out

    @staticmethod
    def _format_last_seen(ts: int) -> str:
        if not ts:
            return "never seen"
        age = now_ts() - ts
        if age < 0:    return "just now"
        if age < 60:   return f"{age}s ago"
        if age < 3600: return f"{age // 60}m ago"
        if age < 86400:return f"{age // 3600}h ago"
        return f"{age // 86400}d ago"

    async def cmd_devices(self, chat_id: int):
        devices = self._devices_for(chat_id)
        pending = self.user_to_device_code.get(chat_id)
        lines = []
        if devices:
            lines.append("Bound Cardputers:")
            for i, (tok, ts) in enumerate(devices, 1):
                lines.append(f"  {i}. id {tok[:8]}…   last seen {self._format_last_seen(ts)}")
        else:
            lines.append("No Cardputers are bound to your account.")
        if pending:
            lines.append("")
            lines.append(f"Pending pair code: {pending} "
                         "(/pair NNNNNN to claim from a device)")
        if devices:
            lines.append("")
            lines.append("/unbind N      detach Cardputer N (e.g. /unbind 1)")
            lines.append("/unbind all    detach every Cardputer at once")
        await self.tg_send(chat_id, "\n".join(lines))

    async def cmd_unbind(self, chat_id: int, arg: str = ""):
        """Detach a bound Cardputer (or all of them).

        No arg + 1 device  → unbinds that single one (matches old UX).
        No arg + multi     → shows the list, asks for an index.
        '/unbind N'        → unbinds the Nth device (1-based, freshest first).
        '/unbind all'      → unbinds every device the user owns.
        Pending pair codes are always cleared as a side-effect.
        """
        arg = arg.strip().lower()
        devices = self._devices_for(chat_id)

        # Clear any in-flight /pair NNNNNN no matter what — the user is
        # changing their setup.
        pending_code = self.user_to_device_code.pop(chat_id, None)
        if pending_code:
            self.pending_device_bind.pop(pending_code, None)

        if not devices:
            self._save_state()
            msg = "No Cardputers were bound."
            if pending_code:
                msg += f"\nCleared pending pair code {pending_code}."
            msg += "\n/pair NNNNNN to add one."
            await self.tg_send(chat_id, msg)
            return

        # Pick the target device(s).
        targets = []
        if arg == "all":
            targets = list(range(len(devices)))
        elif arg == "":
            if len(devices) == 1:
                targets = [0]
            else:
                self._save_state()
                await self.cmd_devices(chat_id)
                return
        elif arg.isdigit():
            n = int(arg)
            if 1 <= n <= len(devices):
                targets = [n - 1]
        else:
            # Allow short-hash prefix as a convenience.
            matches = [i for i, (tok, _) in enumerate(devices)
                       if tok.startswith(arg)]
            if len(matches) == 1:
                targets = matches

        if not targets:
            self._save_state()
            await self.tg_send(chat_id,
                f"Could not match '{arg}'. /devices to list, then "
                f"/unbind N (1-{len(devices)}) or /unbind all.")
            return

        removed = []
        for i in targets:
            tok, _ = devices[i]
            self.device_to_user.pop(tok, None)
            self.device_last_seen.pop(tok, None)
            removed.append(f"{i+1} ({tok[:8]}…)")
        self._save_state()

        if len(removed) == 1:
            body = f"Detached Cardputer {removed[0]}."
        else:
            body = f"Detached {len(removed)} Cardputers:\n  " + "\n  ".join(removed)
        body += ("\n\nEach detached device will hit auth-failed on its "
                 "next request. The user sees a Connection failed menu "
                 "with Retry / Settings / Reboot.")
        await self.tg_send(chat_id, body)

    async def cmd_status(self, chat_id: int):
        pendings = [k for k in self.pending_pair if chat_id in k]
        await self.tg_send(chat_id, json.dumps({
            "chat_id": chat_id,
            "business_connection": self.user_to_conn.get(chat_id),
            "device_code": self.user_to_device_code.get(chat_id),
            "device_claimed": (self.pending_device_bind.get(self.user_to_device_code.get(chat_id), {}) or {}).get("claimed", False),
            "peers": len(self.peers.get(chat_id, {})),
            "pending_pairs": len(pendings),
        }, indent=2))

    async def cmd_accept(self, chat_id: int, arg: str):
        peer_id = self._resolve_peer(chat_id, arg, prefer="pending")
        if peer_id is None:
            pendings = [k for k in self.pending_pair if chat_id in k]
            if not pendings:
                await self.tg_send(chat_id, "No pending pair requests.")
                return
            if arg:
                await self.tg_send(chat_id, f"No pending pair with '{arg}'.")
                return
            lines = ["Multiple pending pair requests, choose one:"]
            for k in pendings:
                other = k[0] if k[0] != chat_id else k[1]
                p = self.pending_pair[k]
                other_info = p["a_info"] if p["a"] == other else p["b_info"]
                un = other_info.get("username")
                handle = f"@{un}" if un else str(other)
                lines.append(f"  /accept {handle}  →  {self.display_name(other_info)}")
            await self.tg_send(chat_id, "\n".join(lines))
            return

        key = self.pair_key(chat_id, peer_id)
        p = self.pending_pair.get(key)
        if not p:
            await self.tg_send(chat_id, "No such pending pair.")
            return
        p["accepted_by"].add(chat_id)
        if len(p["accepted_by"]) == 2:
            a, b = p["a"], p["b"]
            a_info, b_info = p["a_info"], p["b_info"]
            self.peers[a][b] = {**b_info, "established_at": now_ts()}
            self.peers[b][a] = {**a_info, "established_at": now_ts()}
            del self.pending_pair[key]
            self._save_state()
            try:
                await self.tg_send(a, f"✓ Secure channel established with {self.display_name(b_info)}.")
            except Exception: pass
            try:
                await self.tg_send(b, f"✓ Secure channel established with {self.display_name(a_info)}.")
            except Exception: pass
        else:
            self._save_state()
            other = key[0] if key[0] != chat_id else key[1]
            other_info = p["a_info"] if p["a"] == other else p["b_info"]
            await self.tg_send(chat_id, f"Got it. Waiting for {self.display_name(other_info)} to /accept.")

    async def cmd_reject(self, chat_id: int, arg: str):
        peer_id = self._resolve_peer(chat_id, arg, prefer="pending")
        if peer_id is None:
            await self.tg_send(chat_id, "No matching pending pair.")
            return
        key = self.pair_key(chat_id, peer_id)
        p = self.pending_pair.pop(key, None)
        if not p:
            await self.tg_send(chat_id, "No such pending pair.")
            return
        self._save_state()
        await self.tg_send(chat_id, "Rejected.")
        other = key[0] if key[0] != chat_id else key[1]
        try:
            await self.tg_send(other, "The other side rejected the pair request.")
        except Exception:
            pass

    def _resolve_peer(self, chat_id: int, arg: str, prefer: str) -> Optional[int]:
        """Resolve @username or numeric id to a peer user_id.

        `prefer` chooses which set to search first: 'pending' or 'established'.
        With no arg and exactly one match in the preferred set, that one wins.
        """
        arg = arg.strip()

        pending_others = []
        for k in self.pending_pair:
            if chat_id in k:
                other = k[0] if k[0] != chat_id else k[1]
                p = self.pending_pair[k]
                info = p["a_info"] if p["a"] == other else p["b_info"]
                pending_others.append((other, info))
        established = list(self.peers.get(chat_id, {}).items())

        scopes = [pending_others, established] if prefer == "pending" else [established, pending_others]

        if not arg:
            # Single match in any preferred scope?
            for s in scopes:
                if len(s) == 1:
                    return s[0][0]
            return None

        if arg.startswith("@"):
            uname = arg[1:].lower()
            for s in scopes:
                for pid, info in s:
                    if (info.get("username") or "").lower() == uname:
                        return pid
            return None

        try:
            n = int(arg)
        except ValueError:
            return None
        # Confirm it's actually a peer of ours (pending or established).
        for s in scopes:
            for pid, _ in s:
                if pid == n:
                    return n
        return None

    # --- update dispatch ---

    async def handle_dm_message(self, msg: dict):
        chat = msg.get("chat", {}) or {}
        if chat.get("type") != "private":
            return
        chat_id = chat.get("id")
        text = msg.get("text", "")
        if not chat_id or not text:
            return
        cmd, _, rest = text.partition(" ")
        cmd = cmd.lower()
        if cmd in ("/start", "/help"):
            await self.cmd_start(chat_id)
        elif cmd == "/pair":
            await self.cmd_pair(chat_id, rest)
        elif cmd == "/peers":
            await self.cmd_peers(chat_id)
        elif cmd == "/unpeer" or cmd == "/unpair":
            await self.cmd_unpeer(chat_id, rest)
        elif cmd == "/status":
            await self.cmd_status(chat_id)
        elif cmd == "/devices":
            await self.cmd_devices(chat_id)
        elif cmd == "/unbind":
            await self.cmd_unbind(chat_id, rest)
        elif cmd == "/accept":
            await self.cmd_accept(chat_id, rest)
        elif cmd == "/reject":
            await self.cmd_reject(chat_id, rest)
        else:
            await self.tg_send(chat_id,
                "Commands: /start, /pair NNNNNN, /peers, /unpeer USER, "
                "/devices, /unbind, /status, /accept, /reject.")

    async def handle_business_connection(self, bc: dict):
        conn_id = bc["id"]
        user_chat_id = bc["user_chat_id"]
        enabled = bc.get("is_enabled", False)
        rights = bc.get("rights") or {}
        log.info(
            "business_connection %s user_chat=%s enabled=%s rights=%s",
            conn_id, user_chat_id, enabled,
            sorted(k for k, v in rights.items() if v),
        )
        if enabled:
            self.user_to_conn[user_chat_id] = conn_id
            self.conn_to_user[conn_id] = user_chat_id
            try:
                await self.tg_send(user_chat_id,
                    "✓ Business mode connected. "
                    "Now /pair NNNNNN to link your Cardputer, then /pairnoise in any chat to add a friend.")
            except Exception:
                pass
        else:
            old = self.user_to_conn.pop(user_chat_id, None)
            if old:
                self.conn_to_user.pop(old, None)
        self._save_state()

    async def handle_business_message(self, msg: dict):
        conn_id = msg.get("business_connection_id")
        if not conn_id:
            return
        owner = self.conn_to_user.get(conn_id)
        if owner is None:
            return
        text = msg.get("text") or ""
        from_user = msg.get("from", {}) or {}
        chat = msg.get("chat", {}) or {}
        from_id = from_user.get("id")

        # Detect /pairnoise regardless of sender's view (could fire on either side).
        if text.strip() == "/pairnoise":
            await self._handle_pairnoise(owner, from_id, from_user, chat)
            return

        # Drop sender-view echoes (we only act on the receiver's side for queueing).
        if from_id == owner:
            return

        # Drop traffic from non-peers (anti-spam: random contacts of the user
        # shouldn't end up on the Cardputer).
        if not self.is_peer(owner, from_id):
            return

        if text:
            log.info("queue: owner=%s from=%s len=%d", owner, from_id, len(text))
            self.get_inbox(owner).push(from_id, text)

    async def _handle_pairnoise(self, owner: int, from_id: int,
                                from_user: dict, chat: dict):
        if from_id == owner:
            # Owner typed /pairnoise in their chat with a peer.
            peer_id = chat.get("id")
            owner_info = {
                "user_id": owner,
                "first_name": from_user.get("first_name", ""),
                "last_name": from_user.get("last_name", ""),
                "username": from_user.get("username", ""),
            }
            peer_info = {
                "user_id": peer_id,
                "first_name": chat.get("first_name", ""),
                "last_name": chat.get("last_name", ""),
                "username": chat.get("username", ""),
            }
        else:
            # Someone wrote /pairnoise in their chat with owner. The
            # business_message payload only carries the sender's user
            # info, so the owner side starts as a stub and we enrich it
            # via getChat below.
            peer_id = from_id
            peer_info = {
                "user_id": peer_id,
                "first_name": from_user.get("first_name", ""),
                "last_name": from_user.get("last_name", ""),
                "username": from_user.get("username", ""),
            }
            owner_info = await self.fetch_user_info(owner)

        # Belt-and-braces enrich: if either side ended up display-name-less
        # (e.g. chat object came back without first_name on the inline
        # message), pull a fresh copy from getChat now.
        if self._info_is_thin(peer_info):
            peer_info = await self.fetch_user_info(peer_id)
        if self._info_is_thin(owner_info):
            owner_info = await self.fetch_user_info(owner)

        if not peer_id or peer_id == owner:
            return

        # Already linked? Friendly no-op.
        if self.is_peer(owner, peer_id):
            try:
                await self.tg_send(owner,
                    f"Already linked with {self.display_name(peer_info)}.")
            except Exception:
                pass
            return

        key = self.pair_key(owner, peer_id)
        ex = self.pending_pair.get(key)
        if ex and now_ts() < ex.get("expires_at", 0):
            # /pairnoise fires twice for the same message - once on the
            # sender's business connection, once on the receiver's. Don't
            # re-prompt if we already prompted within the last 30 seconds.
            if now_ts() - ex.get("prompted_at", 0) < 30:
                log.info("pairnoise duplicate event suppressed: %s <-> %s", *key)
                return
            ex["prompted_at"] = now_ts()
            self._save_state()
            await self._send_pair_prompts(ex)
            return

        a, b = key
        new = {
            "a": a, "b": b,
            "a_info": owner_info if owner == a else peer_info,
            "b_info": owner_info if owner == b else peer_info,
            "accepted_by": set(),
            "created_at": now_ts(),
            "expires_at": now_ts() + PENDING_PAIR_TTL_S,
            "prompted_at": now_ts(),
        }
        self.pending_pair[key] = new
        self._save_state()
        log.info("pending pair created: %s <-> %s", a, b)
        await self._send_pair_prompts(new)

    async def _send_pair_prompts(self, pending: dict):
        a, b = pending["a"], pending["b"]
        a_info, b_info = pending["a_info"], pending["b_info"]
        for who, peer_info in ((a, b_info), (b, a_info)):
            try:
                await self.tg_send(who,
                    "📡 NoiseBox pair request\n"
                    f"With: {self.display_name(peer_info)}\n"
                    "Reply  /accept  to confirm, or  /reject  to deny.")
            except Exception:
                log.info("could not DM %s for pair prompt", who)

    async def handle_update(self, upd: dict):
        if msg := upd.get("message"):
            await self.handle_dm_message(msg)
            return
        if bc := upd.get("business_connection"):
            await self.handle_business_connection(bc)
            return
        if bm := upd.get("business_message"):
            await self.handle_business_message(bm)
            return
        if ebm := upd.get("edited_business_message"):
            await self.handle_business_message(ebm)
            return

    async def telegram_loop(self):
        allowed = [
            "message", "edited_message",
            "business_connection",
            "business_message", "edited_business_message",
            "deleted_business_messages",
        ]
        log.info("telegram poll loop started")
        last_prune = 0
        while True:
            try:
                data = await self.call(
                    "getUpdates",
                    offset=self.offset, timeout=50,
                    allowed_updates=allowed,
                )
                if data.get("result"):
                    for upd in data["result"]:
                        self.offset = upd["update_id"] + 1
                        try:
                            await self.handle_update(upd)
                        except Exception:
                            log.exception("update %s failed", upd.get("update_id"))
                    self._save_state()
                if now_ts() - last_prune > 60:
                    self.prune_pending()
                    last_prune = now_ts()
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("telegram poll loop error, retrying in 3s")
                await asyncio.sleep(3)


# ----------------------------------------------------------------- HTTP API --

def make_http_app(relay: Relay, bot_token: str) -> web.Application:
    """
    Two auth flavours:

      ADMIN  - "/v1/<bot_token>/{health,bind_poll}". Used only at provisioning
               time (bind_poll) and for monitoring (health). Rate-limited per
               IP because a successful bind_poll returns a device_token.

      DEVICE - "/v1/<device_token>/{peers,send,poll,info}". The device token
               is per-Cardputer, issued by the bot when the user runs /pair
               and claimed by /bind_poll. user_chat_id is derived from the
               token; any user_chat_id field in the body is IGNORED. A
               leaked device_token only scopes to its owner's user_chat_id.
    """
    routes = web.RouteTableDef()

    BIND_RL_WINDOW   = 10   # seconds
    BIND_RL_PER_WIN  = 5    # max bind_poll calls per IP per window

    def rate_limit(request: web.Request) -> Optional[web.Response]:
        ip = request.remote or "-"
        t = now_ts()
        win_start, count = relay.bind_rl.get(ip, (t, 0))
        if t - win_start >= BIND_RL_WINDOW:
            relay.bind_rl[ip] = (t, 1)
            return None
        if count >= BIND_RL_PER_WIN:
            return web.json_response(
                {"ok": False, "error": "rate_limited"}, status=429)
        relay.bind_rl[ip] = (win_start, count + 1)
        return None

    def admin_auth(request: web.Request) -> Optional[web.Response]:
        if not hmac.compare_digest(request.match_info.get("token", ""), bot_token):
            return web.json_response({"ok": False, "error": "auth"}, status=401)
        return None

    def device_auth(request: web.Request):
        """Returns (user_chat_id, None) on success, or (None, error_response).

        Also stamps `device_last_seen[token] = now()` so /devices can
        show users when each of their bound Cardputers last phoned home.
        """
        token = request.match_info.get("token", "")
        user_chat_id = relay.device_to_user.get(token)
        if user_chat_id is None:
            return None, web.json_response(
                {"ok": False, "error": "auth"}, status=401)
        relay.device_last_seen[token] = now_ts()
        return user_chat_id, None

    @routes.get("/v1/{token}/health")
    async def health(request: web.Request):
        # Health is admin-only so this isn't a probe oracle for token guessing.
        if (err := admin_auth(request)) is not None: return err
        return web.json_response({"ok": True, "ts": now_ts()})

    @routes.post("/v1/{token}/_admin/issue_token")
    async def admin_issue_token(request: web.Request):
        """
        TEST ONLY. Issue a device_token for an arbitrary user_chat_id
        without going through /pair. Lets the Python ghost simulate a
        second Cardputer. Disabled by default; set NOISE_TEST_ADMIN=1 in
        the relay environment to enable.
        """
        if os.environ.get("NOISE_TEST_ADMIN") != "1":
            return web.json_response({"ok": False, "error": "disabled"}, status=403)
        if (err := admin_auth(request)) is not None: return err
        try:
            body = await request.json()
            uid = int(body.get("user_chat_id"))
        except Exception:
            return web.json_response({"ok": False, "error": "bad_body"}, status=400)
        token = secrets.token_urlsafe(32)
        relay.device_to_user[token] = uid
        relay._save_state()
        log.info("ADMIN issued test token for user=%s tok=%s..", uid, token[:8])
        return web.json_response({"ok": True, "device_token": token,
                                  "user_chat_id": uid})

    @routes.get("/v1/{token}/bind_poll")
    async def bind_poll(request: web.Request):
        if (err := rate_limit(request)) is not None: return err
        if (err := admin_auth(request)) is not None: return err
        code = request.query.get("code", "")
        if not (code.isdigit() and len(code) == 6):
            return web.json_response({"ok": False, "error": "bad_code"}, status=400)
        entry = relay.pending_device_bind.get(code)
        if entry is None:
            return web.json_response({"ok": True, "bound": False})
        if entry.get("expires_at", 0) < now_ts():
            relay.pending_device_bind.pop(code, None)
            relay._save_state()
            return web.json_response({"ok": False, "error": "expired"}, status=410)
        if entry.get("claimed", False):
            # One claim per code. Legit Cardputer should have stored its
            # token; if it lost it, user must /pair again with a fresh code.
            return web.json_response({"ok": False, "error": "already_claimed"}, status=410)
        # First /bind_poll wins. Issue the token to the device.
        entry["claimed"] = True
        token = entry["device_token"]
        uid   = entry["user_chat_id"]
        relay.device_to_user[token] = uid
        relay.pending_device_bind.pop(code, None)
        relay.user_to_device_code.pop(uid, None)
        relay._save_state()
        log.info("device bound: user=%s token=%s..", uid, token[:8])
        return web.json_response({
            "ok": True, "bound": True,
            "user_chat_id": uid,
            "device_token": token,
        })

    @routes.get("/v1/{token}/peers")
    async def peers(request: web.Request):
        user_chat_id, err = device_auth(request)
        if err is not None: return err
        out = []
        for pid, info in relay.peers.get(user_chat_id, {}).items():
            out.append({
                "user_id": pid,
                "first_name": info.get("first_name", ""),
                "last_name": info.get("last_name", ""),
                "username": info.get("username", ""),
                "established_at": info.get("established_at", 0),
            })
        return web.json_response({"ok": True, "peers": out})

    @routes.post("/v1/{token}/send")
    async def send(request: web.Request):
        user_chat_id, err = device_auth(request)
        if err is not None: return err
        try:
            body = await request.json()
        except Exception:
            return web.json_response({"ok": False, "error": "bad_json"}, status=400)
        peer_user_id = body.get("peer_user_id")
        text = body.get("text")
        if not isinstance(peer_user_id, int) or not isinstance(text, str) or not text:
            return web.json_response({"ok": False, "error": "bad_body"}, status=400)
        if len(text) > 4000:
            return web.json_response({"ok": False, "error": "text_too_long"}, status=400)
        conn = relay.user_to_conn.get(user_chat_id)
        if conn is None:
            return web.json_response({"ok": False, "error": "no_business_connection"}, status=409)
        if not relay.is_peer(user_chat_id, peer_user_id):
            return web.json_response({"ok": False, "error": "not_a_peer"}, status=409)
        result = await relay.tg_send_as_business(conn, peer_user_id, text)
        if not result.get("ok"):
            return web.json_response(
                {"ok": False, "error": "telegram_error", "telegram": result},
                status=502)
        relay.get_inbox(peer_user_id).push(user_chat_id, text)
        return web.json_response({"ok": True, "delivered_to_inbox": peer_user_id})

    @routes.get("/v1/{token}/poll")
    async def poll(request: web.Request):
        user_chat_id, err = device_auth(request)
        if err is not None: return err
        try:
            after = int(request.query.get("after", "0"))
            timeout = float(request.query.get("timeout", "25"))
        except ValueError:
            return web.json_response({"ok": False, "error": "bad_query"}, status=400)
        timeout = max(0.0, min(timeout, POLL_MAX_TIMEOUT_S))
        ib = relay.get_inbox(user_chat_id)
        msgs = ib.fetch_after(after)
        if msgs or timeout == 0:
            return web.json_response({"ok": True, "messages": msgs, "head_id": ib.head_id})
        try:
            await asyncio.wait_for(ib.event.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            pass
        ib.event.clear()
        msgs = ib.fetch_after(after)
        return web.json_response({"ok": True, "messages": msgs, "head_id": ib.head_id})

    @routes.get("/v1/{token}/info")
    async def info(request: web.Request):
        user_chat_id, err = device_auth(request)
        if err is not None: return err
        ib = relay.get_inbox(user_chat_id)
        return web.json_response({
            "ok": True,
            "business_connection": relay.user_to_conn.get(user_chat_id) is not None,
            "peers_count": len(relay.peers.get(user_chat_id, {})),
            "pending_pair_count": sum(1 for k in relay.pending_pair if user_chat_id in k),
            "head_id": ib.head_id,
        })

    app = web.Application()
    app.add_routes(routes)
    return app


# --------------------------------------------------------------------- main --

async def main_async():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    token = os.environ.get("BOT_TOKEN")
    if not token:
        print("BOT_TOKEN env var is required", file=sys.stderr)
        sys.exit(1)
    host = os.environ.get("HTTP_HOST", "127.0.0.1")
    port = int(os.environ.get("HTTP_PORT", "8081"))

    async with aiohttp.ClientSession() as session:
        relay = Relay(token)
        relay.session = session

        app = make_http_app(relay, token)
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, host=host, port=port)
        await site.start()
        log.info("http api listening on http://%s:%d/v1/<token>/...", host, port)

        try:
            await relay.telegram_loop()
        finally:
            await runner.cleanup()


def main():
    try:
        asyncio.run(main_async())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
