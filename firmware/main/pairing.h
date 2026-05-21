// SPDX-License-Identifier: AGPL-3.0-or-later
// NoiseBox -- end-to-end encrypted Cardputer messenger.
// Copyright (C) 2026 Kamronbek B. See LICENSE for the full text.

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "crypto.h"
#include "sas.h"

#ifdef __cplusplus
extern "C" {
#endif

// V1 pairing protocol (simplified X3DH-style, no prekeys).
//
// Both sides hold a long-term X25519 identity (priv_id, pub_id). On pairing
// they additionally generate a fresh ephemeral X25519 pair (priv_eph, pub_eph).
//
// Wire format of a pairing message (after b64 decode):
//   byte 0      : version = 0x01
//   byte 1      : msg type (0x10 = HELLO)
//   bytes 2..33 : sender pub_id    (32 B)
//   bytes 34..65: sender pub_eph   (32 B)
//
// After both sides have exchanged HELLOs, they each compute four DHs and
// derive a 32-byte root key + a 32-byte sending chain key per direction
// (see ratchet.h). SAS is derived from SHA-256(transcript) where transcript
// is the canonical concatenation of:
//      pub_id_lo || pub_eph_lo || pub_id_hi || pub_eph_hi
// (lo/hi = lexicographic order, so both sides agree without role state).
//
// Both users compare the 5 emoji aloud. If they match, the pairing is
// confirmed and the keys are stored to NVS.

#define PAIR_MSG_VERSION   0x01
#define PAIR_MSG_HELLO     0x10
#define PAIR_MSG_SIZE      66

typedef struct {
    uint8_t my_priv_id [CP_X25519_KEY_LEN];
    uint8_t my_pub_id  [CP_X25519_KEY_LEN];
    uint8_t my_priv_eph[CP_X25519_KEY_LEN];
    uint8_t my_pub_eph [CP_X25519_KEY_LEN];

    uint8_t their_pub_id [CP_X25519_KEY_LEN];
    uint8_t their_pub_eph[CP_X25519_KEY_LEN];
    bool    got_their_hello;

    // Derived after exchange.
    uint8_t root_key  [32];
    uint8_t send_chain[32];
    uint8_t recv_chain[32];
    const char *sas_emoji[SAS_EMOJI_COUNT];
} pair_ctx_t;

// Initialise context: loads identity from storage (or creates one if absent)
// and generates a fresh ephemeral. Returns 0 on success.
int pair_init(pair_ctx_t *p);

// Serialise our HELLO into out (must be >= PAIR_MSG_SIZE).
void pair_make_hello(const pair_ctx_t *p, uint8_t out[PAIR_MSG_SIZE]);

// Feed a peer HELLO into the context. Returns 0 on success, <0 on
// malformed message, +1 if we already had their HELLO (ignore).
int pair_feed_hello(pair_ctx_t *p, const uint8_t *msg, size_t len);

// Once both sides have HELLO, derive keys and SAS. Returns 0 on success.
int pair_finalise(pair_ctx_t *p);

#ifdef __cplusplus
}
#endif
