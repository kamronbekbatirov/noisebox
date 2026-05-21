// SPDX-License-Identifier: AGPL-3.0-or-later
// NoiseBox -- end-to-end encrypted Cardputer messenger.
// Copyright (C) 2026 Kamronbek B. See LICENSE for the full text.

// Pair + ratchet glue, wire-formatted as base64 over the relay's /send.

#include "session.h"

#include <string.h>
#include <stdlib.h>

#include "esp_log.h"

#include "base64.h"
#include "crypto.h"
#include "pairing.h"
#include "ratchet.h"
#include "sas.h"
#include "storage.h"

static const char *TAG = "sess";

static session_state_t s_state = SESSION_IDLE;
static pair_ctx_t      s_pair;
static ratchet_t       s_ratchet;
static int64_t         s_peer_id = 0;

int session_begin(int64_t peer_user_id) {
    memset(&s_pair, 0, sizeof(s_pair));
    memset(&s_ratchet, 0, sizeof(s_ratchet));
    s_peer_id = peer_user_id;
    int rc = pair_init(&s_pair);
    if (rc != 0) { ESP_LOGE(TAG, "pair_init: %d", rc); return rc; }
    s_state = SESSION_PAIRING;
    return 0;
}

int session_make_hello_b64(char *out, size_t cap) {
    uint8_t wire[1 + PAIR_MSG_SIZE];
    wire[0] = SESSION_MAGIC_HELLO;
    pair_make_hello(&s_pair, wire + 1);
    int n = b64_encode(wire, sizeof(wire), out, cap);
    return n > 0 ? 0 : -1;
}

int session_feed_hello_b64(const char *b64) {
    uint8_t wire[1 + PAIR_MSG_SIZE + 4];
    int n = b64_decode(b64, strlen(b64), wire, sizeof(wire));
    if (n < 1 || wire[0] != SESSION_MAGIC_HELLO) return -1;
    return pair_feed_hello(&s_pair, wire + 1, n - 1);
}

bool session_both_hellos(void) {
    return s_pair.got_their_hello;
}

int session_finalise(const char **out_sas_words) {
    int rc = pair_finalise(&s_pair);
    if (rc != 0) return rc;
    for (int i = 0; i < SAS_EMOJI_COUNT; i++) out_sas_words[i] = s_pair.sas_emoji[i];
    return 0;
}

int session_confirm_sas(void) {
    ratchet_init(&s_ratchet, s_pair.send_chain, s_pair.recv_chain);
    // Forward-secrecy hygiene: erase everything the ratchet won't need.
    // We keep s_pair.their_pub_id for persistence and the SAS strings for
    // display, but wipe the ephemerals, chain seeds, and root key.
    memset(s_pair.my_priv_eph,  0, sizeof(s_pair.my_priv_eph));
    memset(s_pair.my_pub_eph,   0, sizeof(s_pair.my_pub_eph));
    memset(s_pair.their_pub_eph,0, sizeof(s_pair.their_pub_eph));
    memset(s_pair.root_key,     0, sizeof(s_pair.root_key));
    memset(s_pair.send_chain,   0, sizeof(s_pair.send_chain));
    memset(s_pair.recv_chain,   0, sizeof(s_pair.recv_chain));
    s_state = SESSION_PAIRED;
    return 0;
}

int session_encrypt_b64(const char *text, char *out, size_t cap) {
    if (s_state != SESSION_PAIRED) return -1;
    size_t plen = strlen(text);
    if (plen > SESSION_MAX_PLAINTEXT) plen = SESSION_MAX_PLAINTEXT;
    uint8_t packet[1 + 4 + SESSION_MAX_PLAINTEXT + 16];
    packet[0] = SESSION_MAGIC_MSG;
    int n = ratchet_encrypt(&s_ratchet,
                            (const uint8_t *)text, plen,
                            packet + 1, sizeof(packet) - 1);
    if (n < 0) return -2;
    int b64n = b64_encode(packet, n + 1, out, cap);
    return b64n > 0 ? 0 : -3;
}

int session_decode_incoming(const char *b64, char *out_text, size_t cap) {
    uint8_t packet[1 + 4 + SESSION_MAX_PLAINTEXT + 16 + 8];
    int n = b64_decode(b64, strlen(b64), packet, sizeof(packet));
    if (n < 1) return -1;
    if (packet[0] == SESSION_MAGIC_HELLO) {
        // Once we are PAIRED, a fresh HELLO from the wire is either the
        // peer rebooting or an attacker trying to substitute keys without
        // a new SAS comparison. Refuse with a clear error so the caller
        // can surface it to the user instead of silently re-keying.
        if (s_state == SESSION_PAIRED) return -5;
        if (n < 1 + PAIR_MSG_SIZE) return -2;
        int rc = pair_feed_hello(&s_pair, packet + 1, n - 1);
        return rc < 0 ? rc : 2;
    }
    if (packet[0] == SESSION_MAGIC_MSG) {
        if (s_state != SESSION_PAIRED) return -3;
        uint8_t pt[SESSION_MAX_PLAINTEXT + 1];
        int plen = ratchet_decrypt(&s_ratchet, packet + 1, n - 1,
                                   pt, sizeof(pt) - 1);
        if (plen < 0) return -4;
        if ((size_t)plen >= cap) plen = cap - 1;
        memcpy(out_text, pt, plen);
        out_text[plen] = 0;
        return 1;
    }
    return 0;
}

session_state_t session_state(void) { return s_state; }

int session_resume(int64_t peer_user_id) {
    peer_state_t st;
    if (storage_load_peer(peer_user_id, &st) != 0) return -1;
    memset(&s_pair,    0, sizeof(s_pair));
    memset(&s_ratchet, 0, sizeof(s_ratchet));
    memcpy(s_pair.their_pub_id, st.peer_pub_id, CP_X25519_KEY_LEN);
    s_pair.got_their_hello = true;   // we already paired in a past life
    memcpy(s_ratchet.send.chain, st.send_chain, 32);
    memcpy(s_ratchet.recv.chain, st.recv_chain, 32);
    s_ratchet.send.counter = st.send_ctr;
    s_ratchet.recv.counter = st.recv_ctr;
    s_peer_id = peer_user_id;
    s_state   = SESSION_PAIRED;
    return 0;
}

// Read-only: where did we leave off in the peer's inbox? Returns 0 if no
// saved state, otherwise the stored last_seen_msg_id.
uint32_t session_last_seen(int64_t peer_user_id) {
    peer_state_t st;
    if (storage_load_peer(peer_user_id, &st) != 0) return 0;
    return st.last_seen_msg_id;
}

int session_persist(int64_t peer_user_id, uint32_t last_seen_msg_id) {
    if (s_state != SESSION_PAIRED) return -1;
    peer_state_t st;
    memset(&st, 0, sizeof(st));
    memcpy(st.send_chain, s_ratchet.send.chain, 32);
    memcpy(st.recv_chain, s_ratchet.recv.chain, 32);
    st.send_ctr = s_ratchet.send.counter;
    st.recv_ctr = s_ratchet.recv.counter;
    st.last_seen_msg_id = last_seen_msg_id;
    memcpy(st.peer_pub_id, s_pair.their_pub_id, CP_X25519_KEY_LEN);
    return storage_save_peer(peer_user_id, &st);
}
