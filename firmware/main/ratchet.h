// SPDX-License-Identifier: AGPL-3.0-or-later
// NoiseBox -- end-to-end encrypted Cardputer messenger.
// Copyright (C) 2026 Kamronbek B. See LICENSE for the full text.

#pragma once

#include <stddef.h>
#include <stdint.h>

#include "crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

// Symmetric chain ratchet (Signal's chain step, without the DH ratchet).
// Each direction has its own 32-byte chain key and a 32-bit counter.
//
//   message_key_i = HKDF(chain_i, info="msg", L=44)  // 32 key + 12 nonce
//   chain_{i+1}   = HKDF(chain_i, info="chain", L=32)
//
// After deriving message_key_i, chain_i is wiped. Forward secrecy: an
// attacker who captures the device after message N cannot read messages
// 0..N-1, only N onwards.
//
// Replay protection: receiver advances its chain on every successful decrypt
// and tracks the last accepted counter. Out-of-order delivery up to a small
// window is handled by skipping ahead in the chain and caching skipped keys
// in a small array (RATCHET_SKIPPED_CAP).

// Must match MAX_SKIP_LOOKAHEAD in ratchet.c so out-of-order deliveries
// within the lookahead window aren't silently evicted.
#define RATCHET_SKIPPED_CAP 64

typedef struct {
    uint8_t  chain[32];
    uint32_t counter;
} ratchet_dir_t;

typedef struct {
    uint32_t counter;
    uint8_t  key[CP_CHACHA_KEY_LEN];
    uint8_t  nonce[CP_CHACHA_NONCE_LEN];
} ratchet_skipped_t;

typedef struct {
    ratchet_dir_t send;
    ratchet_dir_t recv;
    ratchet_skipped_t skipped[RATCHET_SKIPPED_CAP];
    int skipped_count;
} ratchet_t;

void ratchet_init(ratchet_t *r,
                  const uint8_t send_chain[32],
                  const uint8_t recv_chain[32]);

// Encrypt plaintext. Output layout:
//   [4-byte BE counter][ciphertext][16-byte tag]
// Returns total output length, or <0 on error.
int ratchet_encrypt(ratchet_t *r,
                    const uint8_t *pt, size_t pt_len,
                    uint8_t *out, size_t out_cap);

// Decrypt a packet produced by ratchet_encrypt. Returns plaintext length, or
// <0 on error (auth fail / replay / too far ahead).
int ratchet_decrypt(ratchet_t *r,
                    const uint8_t *packet, size_t packet_len,
                    uint8_t *out_pt, size_t out_cap);

#ifdef __cplusplus
}
#endif
