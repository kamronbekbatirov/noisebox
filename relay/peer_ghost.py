# SPDX-License-Identifier: AGPL-3.0-or-later
# NoiseBox -- end-to-end encrypted Cardputer messenger.
# Copyright (C) 2026 Kamronbek B. See LICENSE for the full text.

"""
Ghost peer - software-only counterpart of a Cardputer for testing.

Plays the role of the OTHER Cardputer so you can verify the end-to-end
crypto flow without owning a second device.  Implements the exact same
wire protocol as the firmware (session.c + pairing.c + ratchet.c):

  HELLO wire (after base64 decode):
    byte 0      = 0x01            magic = SESSION_MAGIC_HELLO
    byte 1      = 0x01            PAIR_MSG_VERSION
    byte 2      = 0x10            PAIR_MSG_HELLO
    bytes 3..34 = peer pub_id     (X25519, 32 B)
    bytes 35..66= peer pub_eph    (X25519, 32 B)

  CHAT wire:
    byte 0      = 0x02            magic = SESSION_MAGIC_MSG
    bytes 1..4  = BE counter      (ratchet counter)
    bytes 5..n  = ChaCha20-Poly1305 ciphertext (with 4-byte counter as AAD)
    bytes n+1.. = 16-byte tag (already included in ct above)

Run from PowerShell:
    python relay/peer_ghost.py <my_user_chat_id> <peer_user_chat_id>

Where <my_user_chat_id> is the Telegram numeric user id of the account
that *doesn't* have a physical Cardputer (the one we're simulating), and
<peer_user_chat_id> is the Telegram numeric user id of the account that
*does* have a Cardputer bound.  Both must have already completed /pair
with the bot and /pairnoise + /accept on each other.

The relay base URL is taken from the NOISE_RELAY_URL env var, or falls
back to https://localhost:8081 if unset.
"""

import argparse
import base64
import json
import os
import struct
import sys
import time
from pathlib import Path

import requests
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

API_BASE = os.environ.get("NOISE_RELAY_URL", "https://localhost:8081").rstrip("/")

# Wire constants - must match firmware.
SESSION_MAGIC_HELLO = 0x01
SESSION_MAGIC_MSG   = 0x02
PAIR_MSG_VERSION    = 0x01
PAIR_MSG_HELLO_TYPE = 0x10

SAS_WORDS = [
    "DOG","CAT","MOUSE","RABBIT","FOX","BEAR","PANDA","LION",
    "TIGER","HORSE","UNICORN","COW","PIG","FROG","OCTO","FISH",
    "CACTUS","TREE","SUN","APPLE","LEMON","STRAW","WATERM","PIZZA",
    "ROCKET","CAR","ANCHOR","KEY","BELL","GUITAR","DIE","STAR",
]


# ---------- crypto helpers (mirror crypto.c exactly) ----------

def hkdf(salt: bytes, ikm: bytes, info: bytes, length: int) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length,
                salt=salt if salt else None, info=info).derive(ikm)

def x25519_keypair():
    sk = X25519PrivateKey.generate()
    pk = sk.public_key()
    priv = sk.private_bytes_raw()
    pub  = pk.public_bytes_raw()
    return priv, pub, sk

def x25519_shared(priv_bytes: bytes, peer_pub_bytes: bytes) -> bytes:
    sk = X25519PrivateKey.from_private_bytes(priv_bytes)
    pk = X25519PublicKey.from_public_bytes(peer_pub_bytes)
    return sk.exchange(pk)


# ---------- identity persistence ----------

IDENT_FILE = Path(__file__).with_name("ghost_identity.bin")

def load_or_create_identity():
    if IDENT_FILE.exists():
        priv = IDENT_FILE.read_bytes()
        if len(priv) != 32:
            IDENT_FILE.unlink()
        else:
            pub = X25519PrivateKey.from_private_bytes(priv).public_key().public_bytes_raw()
            return priv, pub
    priv, pub, _ = x25519_keypair()
    IDENT_FILE.write_bytes(priv)
    print(f"[ghost] generated new identity, saved to {IDENT_FILE}")
    return priv, pub


# ---------- session state ----------

class Session:
    def __init__(self):
        self.my_priv_id, self.my_pub_id = load_or_create_identity()
        self.my_priv_eph, self.my_pub_eph, _ = x25519_keypair()
        self.peer_pub_id = None
        self.peer_pub_eph = None
        self.root_key = None
        self.send_chain = None
        self.recv_chain = None
        self.send_ctr = 0
        self.recv_ctr = 0
        self.recv_skipped = {}   # counter -> (key, nonce)
        self.ready = False

    def make_hello_b64(self) -> str:
        wire = bytes([SESSION_MAGIC_HELLO, PAIR_MSG_VERSION, PAIR_MSG_HELLO_TYPE])
        wire += self.my_pub_id + self.my_pub_eph
        return base64.b64encode(wire).decode()

    def feed_hello(self, wire: bytes) -> bool:
        if len(wire) < 1 + 66: return False
        if wire[0] != SESSION_MAGIC_HELLO: return False
        if wire[1] != PAIR_MSG_VERSION: return False
        if wire[2] != PAIR_MSG_HELLO_TYPE: return False
        self.peer_pub_id  = wire[3:35]
        self.peer_pub_eph = wire[35:67]
        return True

    def finalise(self):
        # Canonical ikm = lo.id*hi.id || lo.id*hi.eph || lo.eph*hi.id || lo.eph*hi.eph.
        # dh1 and dh4 are symmetric so either ordering works.  dh2 and dh3
        # are asymmetric; swap inputs when we are the hi side.
        i_am_lo = self.my_pub_id < self.peer_pub_id
        dh1 = x25519_shared(self.my_priv_id,  self.peer_pub_id)
        dh4 = x25519_shared(self.my_priv_eph, self.peer_pub_eph)
        if i_am_lo:
            dh2 = x25519_shared(self.my_priv_id,  self.peer_pub_eph)
            dh3 = x25519_shared(self.my_priv_eph, self.peer_pub_id)
        else:
            dh2 = x25519_shared(self.my_priv_eph, self.peer_pub_id)
            dh3 = x25519_shared(self.my_priv_id,  self.peer_pub_eph)
        ikm = dh1 + dh2 + dh3 + dh4
        okm = hkdf(b"", ikm, b"cardputer-v1", 96)
        self.root_key = okm[:32]

        # Lex order already computed above.
        if i_am_lo:
            self.send_chain = okm[32:64]
            self.recv_chain = okm[64:96]
        else:
            self.recv_chain = okm[32:64]
            self.send_chain = okm[64:96]

        # SAS: SHA-256 over (lo_id || lo_eph || hi_id || hi_eph), first 25 bits.
        if i_am_lo:
            transcript = self.my_pub_id + self.my_pub_eph + self.peer_pub_id + self.peer_pub_eph
        else:
            transcript = self.peer_pub_id + self.peer_pub_eph + self.my_pub_id + self.my_pub_eph
        h = hashes.Hash(hashes.SHA256())
        h.update(transcript)
        digest = h.finalize()
        bits = (digest[0] << 17) | (digest[1] << 9) | (digest[2] << 1) | (digest[3] >> 7)
        sas = []
        for i in range(5):
            idx = (bits >> (20 - i * 5)) & 0x1F
            sas.append(SAS_WORDS[idx])
        return sas

    def confirm(self):
        self.ready = True

    # ---- ratchet ----

    def _derive_msg(self, chain):
        okm = hkdf(b"", chain, b"msg", 44)
        return okm[:32], okm[32:44]

    def _advance(self, chain):
        return hkdf(b"", chain, b"chain", 32)

    def encrypt(self, plaintext: str) -> str:
        key, nonce = self._derive_msg(self.send_chain)
        counter = self.send_ctr
        aad = struct.pack(">I", counter)
        ct = ChaCha20Poly1305(key).encrypt(nonce, plaintext.encode("utf-8"), aad)
        # Wire: [4B counter BE][ct + tag]
        packet = bytes([SESSION_MAGIC_MSG]) + aad + ct
        self.send_chain = self._advance(self.send_chain)
        self.send_ctr += 1
        return base64.b64encode(packet).decode()

    def decrypt(self, wire: bytes):
        if wire[0] != SESSION_MAGIC_MSG:
            print(f"[debug] decrypt: bad magic 0x{wire[0]:02x}")
            return None
        if len(wire) < 1 + 4 + 16:
            print(f"[debug] decrypt: short ({len(wire)})")
            return None
        counter = struct.unpack(">I", wire[1:5])[0]
        aad = wire[1:5]
        ct = wire[5:]
        print(f"[debug] decrypt: wire_len={len(wire)} ctr={counter} recv_ctr={self.recv_ctr}")
        print(f"[debug]   recv_chain[0:8]={self.recv_chain[:8].hex()}")
        while self.recv_ctr < counter:
            k, n = self._derive_msg(self.recv_chain)
            self.recv_skipped[self.recv_ctr] = (k, n)
            self.recv_chain = self._advance(self.recv_chain)
            self.recv_ctr += 1
        if counter in self.recv_skipped:
            key, nonce = self.recv_skipped.pop(counter)
        elif counter == self.recv_ctr:
            key, nonce = self._derive_msg(self.recv_chain)
            self.recv_chain = self._advance(self.recv_chain)
            self.recv_ctr += 1
        else:
            print(f"[debug]   counter {counter} already consumed")
            return None
        print(f"[debug]   key[0:8]={key[:8].hex()} nonce={nonce.hex()} ct_len={len(ct)}")
        try:
            pt = ChaCha20Poly1305(key).decrypt(nonce, ct, aad)
            return pt.decode("utf-8", errors="replace")
        except Exception as e:
            print(f"[debug]   AEAD failed: {type(e).__name__}: {e}")
            return None


# ---------- relay HTTP client ----------

def relay_url(token, method, query=None):
    url = f"{API_BASE}/v1/{token}/{method}"
    if query:
        url += "?" + query
    return url


def call(token, method, query=None, body=None, timeout=15):
    url = relay_url(token, method, query)
    if body is None:
        r = requests.get(url, timeout=timeout)
    else:
        r = requests.post(url, json=body, timeout=timeout)
    return r.status_code, r.json() if r.headers.get("content-type","" ).startswith("application/json") else None


def admin_issue_token(bot_token, my_user_chat_id):
    """Ask the relay (with NOISE_TEST_ADMIN=1) for a device_token for us."""
    url = f"{API_BASE}/v1/{bot_token}/_admin/issue_token"
    r = requests.post(url, json={"user_chat_id": my_user_chat_id}, timeout=10)
    if r.status_code != 200:
        raise RuntimeError(
            f"admin_issue_token failed: {r.status_code} {r.text}\n"
            f"Hint: set NOISE_TEST_ADMIN=1 in the relay's systemd env, restart it.")
    j = r.json()
    if not j.get("ok"):
        raise RuntimeError(f"admin_issue_token: {j}")
    return j["device_token"]


def tx_send(device_token, peer_id, text):
    body = {"peer_user_id": peer_id, "text": text}
    sc, j = call(device_token, "send", body=body)
    if sc != 200 or not j or not j.get("ok"):
        print(f"[ghost] /send failed: {sc} {j}", file=sys.stderr)
        return False
    return True


def tx_poll(device_token, after, timeout=25):
    q = f"after={after}&timeout={timeout}"
    sc, j = call(device_token, "poll", query=q, timeout=timeout + 5)
    if sc != 200 or not j or not j.get("ok"):
        return []
    return j.get("messages", [])


# ---------- input helpers (non-blocking-ish) ----------

def prompt(text):
    sys.stdout.write(text)
    sys.stdout.flush()


# ---------- main loop ----------

def run(bot_token, my_id, peer_id, auto_yes=False, echo_reply=False):
    sess = Session()
    print(f"[ghost] my pub_id = {sess.my_pub_id.hex()[:16]}...")

    # Mint a device_token for our user_chat_id via the relay's admin
    # endpoint (gated by NOISE_TEST_ADMIN=1 in the relay's env).
    device_token = admin_issue_token(bot_token, my_id)
    print(f"[ghost] device_token issued ({device_token[:8]}...)")

    # Skip any HELLOs queued from previous test runs.
    sc, info = call(device_token, "info")
    if sc == 200 and info and info.get("ok"):
        after = int(info.get("head_id", 0))
        print(f"[ghost] starting at relay head_id={after} (ignoring backlog)")
    else:
        after = 0
        print(f"[ghost] /info failed, starting at 0")
    print(f"[ghost] re-handshake on the Cardputer (esc back to peers, reselect),")
    print(f"[ghost] then I'll pick up your fresh HELLO from {peer_id}...")

    # Stage 1: wait for the peer's HELLO.
    while not sess.peer_pub_id:
        msgs = tx_poll(device_token, after, timeout=20)
        for m in msgs:
            after = max(after, m["id"])
            if m["from"] != peer_id:
                continue
            try:
                wire = base64.b64decode(m["text"])
            except Exception:
                continue
            if not wire or wire[0] != SESSION_MAGIC_HELLO:
                continue
            if sess.feed_hello(wire):
                print(f"[ghost] received HELLO from peer (pub_id={wire[3:35].hex()[:16]}...)")
                break
        if not sess.peer_pub_id:
            print("[ghost] no HELLO yet, still waiting...")

    # Stage 2: send our HELLO.
    print("[ghost] sending our HELLO...")
    if not tx_send(device_token, peer_id, sess.make_hello_b64()):
        print("[ghost] failed to send HELLO; abort")
        return

    # Stage 3: derive keys + SAS.
    sas = sess.finalise()
    print()
    print("====================================")
    print(" SAS — check this on the Cardputer:")
    print("    " + " ".join(sas))
    print("====================================")
    print()
    if auto_yes:
        print("[ghost] auto-confirming SAS (--yes). Verify on Cardputer manually.")
    else:
        ans = input("Match? [y/N] ").strip().lower()
        if ans != "y":
            print("[ghost] SAS rejected, exiting")
            return
    sess.confirm()
    print("[ghost] channel established. Type messages; ctrl-c to quit.")
    if echo_reply:
        print("[ghost] echo_reply mode: every incoming msg gets an auto-reply.")
    print()

    # Stage 4: chat loop. Poll on a thread? Keep it simple: alternate.
    # Use short timeouts so we can interleave input.
    import threading, queue
    out_q = queue.Queue()

    def reader():
        while True:
            line = sys.stdin.readline()
            if not line:
                break
            out_q.put(line.rstrip("\n"))

    threading.Thread(target=reader, daemon=True).start()

    while True:
        # Send any queued outgoing.
        while not out_q.empty():
            line = out_q.get_nowait()
            if not line:
                continue
            ct_b64 = sess.encrypt(line)
            if tx_send(device_token, peer_id, ct_b64):
                print(f"  > {line}")
            else:
                print(f"  ! send failed")

        # Poll incoming.
        msgs = tx_poll(device_token, after, timeout=2)
        for m in msgs:
            after = max(after, m["id"])
            if m["from"] != peer_id:
                continue
            try:
                wire = base64.b64decode(m["text"])
            except Exception:
                continue
            if not wire:
                continue
            if wire[0] == SESSION_MAGIC_HELLO:
                # Peer rebooted/re-handshook on their side. Reset our
                # session and run the handshake again so we stay in sync.
                print(f"[ghost] peer sent a fresh HELLO - re-handshaking")
                sess = Session()
                sess.feed_hello(wire)
                if not tx_send(device_token, peer_id, sess.make_hello_b64()):
                    print("[ghost] failed to send HELLO reply")
                    continue
                sas2 = sess.finalise()
                print()
                print("====================================")
                print(" SAS (new handshake):")
                print("    " + " ".join(sas2))
                print("====================================")
                if auto_yes:
                    print("[ghost] auto-confirming new SAS")
                sess.confirm()
                continue
            pt = sess.decrypt(wire)
            if pt is None:
                print(f"  ! couldn't decrypt msg #{m['id']}")
            else:
                ts_str = time.strftime("%H:%M:%S")
                print(f"  [{ts_str}] cardputer: {pt}", flush=True)
                if echo_reply:
                    reply = f"echo: {pt[:40]}"
                    ct_b64 = sess.encrypt(reply)
                    if tx_send(device_token, peer_id, ct_b64):
                        print(f"  [{ts_str}] ghost   > {reply}", flush=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("my_user_chat_id",  type=int,
                    help="Telegram user_chat_id of the ghost (the account without a Cardputer)")
    ap.add_argument("peer_user_chat_id", type=int,
                    help="Telegram user_chat_id of the peer (the Cardputer-owning account)")
    ap.add_argument("--token", default=os.environ.get("BOT_TOKEN", ""),
                    help="bot token (default: $BOT_TOKEN env)")
    ap.add_argument("--yes", action="store_true",
                    help="auto-confirm SAS instead of prompting on stdin")
    ap.add_argument("--echo", action="store_true",
                    help="auto-echo every incoming message back")
    args = ap.parse_args()
    if not args.token:
        print("BOT_TOKEN env var required (or --token)", file=sys.stderr)
        sys.exit(2)
    run(args.token, args.my_user_chat_id, args.peer_user_chat_id,
        auto_yes=args.yes, echo_reply=args.echo)


if __name__ == "__main__":
    main()
