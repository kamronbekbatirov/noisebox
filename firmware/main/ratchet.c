// SPDX-License-Identifier: AGPL-3.0-or-later
// NoiseBox -- end-to-end encrypted Cardputer messenger.
// Copyright (C) 2026 Kamronbek B. See LICENSE for the full text.

#include "ratchet.h"

#include <string.h>

#define MAX_SKIP_LOOKAHEAD 64

static void derive_msg_keys(const uint8_t chain[32],
                            uint8_t out_key[CP_CHACHA_KEY_LEN],
                            uint8_t out_nonce[CP_CHACHA_NONCE_LEN]) {
    uint8_t okm[CP_CHACHA_KEY_LEN + CP_CHACHA_NONCE_LEN];
    cp_hkdf(NULL, 0, chain, 32, (const uint8_t *)"msg", 3,
            okm, sizeof(okm));
    memcpy(out_key,   okm,                       CP_CHACHA_KEY_LEN);
    memcpy(out_nonce, okm + CP_CHACHA_KEY_LEN,   CP_CHACHA_NONCE_LEN);
}

static void advance_chain(uint8_t chain[32]) {
    uint8_t next[32];
    cp_hkdf(NULL, 0, chain, 32, (const uint8_t *)"chain", 5, next, 32);
    memcpy(chain, next, 32);
}

void ratchet_init(ratchet_t *r,
                  const uint8_t send_chain[32],
                  const uint8_t recv_chain[32]) {
    memset(r, 0, sizeof(*r));
    memcpy(r->send.chain, send_chain, 32);
    memcpy(r->recv.chain, recv_chain, 32);
}

int ratchet_encrypt(ratchet_t *r,
                    const uint8_t *pt, size_t pt_len,
                    uint8_t *out, size_t out_cap) {
    size_t total = 4 + pt_len + CP_POLY_TAG_LEN;
    if (out_cap < total) return -1;
    if (r->send.counter == UINT32_MAX) return -3;  // counter exhausted

    uint8_t key[CP_CHACHA_KEY_LEN], nonce[CP_CHACHA_NONCE_LEN];
    derive_msg_keys(r->send.chain, key, nonce);

    uint32_t ctr = r->send.counter;
    out[0] = (ctr >> 24) & 0xFF;
    out[1] = (ctr >> 16) & 0xFF;
    out[2] = (ctr >>  8) & 0xFF;
    out[3] = (ctr      ) & 0xFF;

    // AAD = the 4-byte counter prefix - binds the counter into the tag.
    int rc = cp_aead_encrypt(key, nonce, out, 4, pt, pt_len, out + 4);
    memset(key,   0, sizeof(key));
    memset(nonce, 0, sizeof(nonce));
    if (rc != 0) return -2;        // AEAD failed - DO NOT advance state

    advance_chain(r->send.chain);
    r->send.counter++;
    return (int)total;
}

// Stash a derived (key,nonce,counter) tuple as a skipped message key, evicting
// the oldest if we are full.
static void stash_skipped(ratchet_t *r, uint32_t counter,
                          const uint8_t key[CP_CHACHA_KEY_LEN],
                          const uint8_t nonce[CP_CHACHA_NONCE_LEN]) {
    if (r->skipped_count == RATCHET_SKIPPED_CAP) {
        memmove(&r->skipped[0], &r->skipped[1],
                sizeof(r->skipped[0]) * (RATCHET_SKIPPED_CAP - 1));
        r->skipped_count--;
    }
    ratchet_skipped_t *s = &r->skipped[r->skipped_count++];
    s->counter = counter;
    memcpy(s->key,   key,   CP_CHACHA_KEY_LEN);
    memcpy(s->nonce, nonce, CP_CHACHA_NONCE_LEN);
}

static int try_skipped(ratchet_t *r, uint32_t want_ctr,
                       const uint8_t *aad, size_t aad_len,
                       const uint8_t *ct, size_t ct_len,
                       uint8_t *out_pt) {
    for (int i = 0; i < r->skipped_count; i++) {
        if (r->skipped[i].counter == want_ctr) {
            int rc = cp_aead_decrypt(r->skipped[i].key, r->skipped[i].nonce,
                                     aad, aad_len, ct, ct_len, out_pt);
            if (rc == 0) {
                // Consume.
                memmove(&r->skipped[i], &r->skipped[i + 1],
                        sizeof(r->skipped[0]) * (r->skipped_count - i - 1));
                r->skipped_count--;
                return (int)(ct_len - CP_POLY_TAG_LEN);
            }
            return -10;
        }
    }
    return -11;
}

int ratchet_decrypt(ratchet_t *r,
                    const uint8_t *packet, size_t packet_len,
                    uint8_t *out_pt, size_t out_cap) {
    if (packet_len < 4 + CP_POLY_TAG_LEN) return -1;
    uint32_t their_ctr = ((uint32_t)packet[0] << 24) | ((uint32_t)packet[1] << 16)
                       | ((uint32_t)packet[2] << 8)  | ((uint32_t)packet[3]);
    const uint8_t *ct = packet + 4;
    size_t ct_len = packet_len - 4;
    if (out_cap + CP_POLY_TAG_LEN < ct_len) return -2;

    // Try stashed skipped keys first (these were already committed by an
    // earlier successful decrypt path).
    int rc = try_skipped(r, their_ctr, packet, 4, ct, ct_len, out_pt);
    if (rc >= 0) return rc;

    if (their_ctr < r->recv.counter) return -3;                   // replay
    if (their_ctr - r->recv.counter > MAX_SKIP_LOOKAHEAD) return -4;

    // SECURITY: derive into a SCRATCH copy of the chain state. We only
    // commit the advance (and persist the skipped keys) if the AEAD tag
    // verifies. Otherwise a single forged packet would permanently
    // desync the receiver by bumping the chain past legitimate messages.
    uint32_t scratch_ctr = r->recv.counter;
    uint8_t  scratch_chain[32];
    memcpy(scratch_chain, r->recv.chain, 32);

    // Walk forward to `their_ctr - 1`, remembering keys for the slots we
    // jumped over so we can stash them on success.
    uint8_t skip_keys[MAX_SKIP_LOOKAHEAD][CP_CHACHA_KEY_LEN];
    uint8_t skip_nons[MAX_SKIP_LOOKAHEAD][CP_CHACHA_NONCE_LEN];
    int     skip_n = 0;
    while (scratch_ctr < their_ctr) {
        derive_msg_keys(scratch_chain,
                        skip_keys[skip_n], skip_nons[skip_n]);
        advance_chain(scratch_chain);
        scratch_ctr++;
        skip_n++;
    }

    // Now derive the message key for `their_ctr` and try to decrypt.
    uint8_t key[CP_CHACHA_KEY_LEN], nonce[CP_CHACHA_NONCE_LEN];
    derive_msg_keys(scratch_chain, key, nonce);
    int drc = cp_aead_decrypt(key, nonce, packet, 4, ct, ct_len, out_pt);
    if (drc != 0) {
        // AEAD failed -> packet was forged or corrupted. Wipe scratch and
        // leave receiver state UNCHANGED.
        memset(key, 0, sizeof(key));
        memset(nonce, 0, sizeof(nonce));
        memset(scratch_chain, 0, sizeof(scratch_chain));
        memset(skip_keys, 0, sizeof(skip_keys));
        memset(skip_nons, 0, sizeof(skip_nons));
        return -5;
    }

    // AEAD OK -> commit. Persist the skipped keys so future out-of-order
    // deliveries of the messages we jumped over still decrypt.
    for (int i = 0; i < skip_n; i++) {
        stash_skipped(r, r->recv.counter + i, skip_keys[i], skip_nons[i]);
    }
    advance_chain(scratch_chain);   // step past the just-decrypted slot
    memcpy(r->recv.chain, scratch_chain, 32);
    r->recv.counter = scratch_ctr + 1;

    memset(key, 0, sizeof(key));
    memset(nonce, 0, sizeof(nonce));
    memset(scratch_chain, 0, sizeof(scratch_chain));
    memset(skip_keys, 0, sizeof(skip_keys));
    memset(skip_nons, 0, sizeof(skip_nons));
    return (int)(ct_len - CP_POLY_TAG_LEN);
}
