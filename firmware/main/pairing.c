// SPDX-License-Identifier: AGPL-3.0-or-later
// NoiseBox -- end-to-end encrypted Cardputer messenger.
// Copyright (C) 2026 Kamronbek B. See LICENSE for the full text.

#include "pairing.h"

#include <string.h>

#include "esp_log.h"
#include "storage.h"

static const char *TAG = "pair";

int pair_init(pair_ctx_t *p) {
    memset(p, 0, sizeof(*p));

    // Load or create long-term identity.
    if (storage_load_identity(p->my_priv_id, p->my_pub_id) != 0) {
        int rc = cp_x25519_keypair(p->my_priv_id, p->my_pub_id);
        if (rc) {
            ESP_LOGE(TAG, "identity keygen failed: %d", rc);
            return rc;
        }
        rc = storage_save_identity(p->my_priv_id, p->my_pub_id);
        if (rc) {
            ESP_LOGE(TAG, "identity save failed: %d", rc);
            return rc;
        }
        ESP_LOGI(TAG, "fresh identity generated");
    } else {
        ESP_LOGI(TAG, "identity loaded from NVS");
    }

    int rc = cp_x25519_keypair(p->my_priv_eph, p->my_pub_eph);
    if (rc) {
        ESP_LOGE(TAG, "ephemeral keygen failed: %d", rc);
        return rc;
    }
    return 0;
}

void pair_make_hello(const pair_ctx_t *p, uint8_t out[PAIR_MSG_SIZE]) {
    out[0] = PAIR_MSG_VERSION;
    out[1] = PAIR_MSG_HELLO;
    memcpy(out + 2,  p->my_pub_id,  CP_X25519_KEY_LEN);
    memcpy(out + 34, p->my_pub_eph, CP_X25519_KEY_LEN);
}

int pair_feed_hello(pair_ctx_t *p, const uint8_t *msg, size_t len) {
    if (len < PAIR_MSG_SIZE) return -1;
    if (msg[0] != PAIR_MSG_VERSION) return -2;
    if (msg[1] != PAIR_MSG_HELLO)   return -3;
    if (p->got_their_hello) return 1;
    memcpy(p->their_pub_id,  msg + 2,  CP_X25519_KEY_LEN);
    memcpy(p->their_pub_eph, msg + 34, CP_X25519_KEY_LEN);
    p->got_their_hello = true;
    return 0;
}

// Lexicographic compare of 32-byte keys, big-endian byte order.
static int cmp32(const uint8_t *a, const uint8_t *b) {
    return memcmp(a, b, CP_X25519_KEY_LEN);
}

int pair_finalise(pair_ctx_t *p) {
    if (!p->got_their_hello) return -1;

    // Four ECDH outputs - mirrors X3DH (id<->eph mixed).
    uint8_t dh1[CP_X25519_KEY_LEN]; // id_a   * id_b
    uint8_t dh2[CP_X25519_KEY_LEN]; // id_a   * eph_b
    uint8_t dh3[CP_X25519_KEY_LEN]; // eph_a  * id_b
    uint8_t dh4[CP_X25519_KEY_LEN]; // eph_a  * eph_b

    // dh2 / dh3 are asymmetric ECDHs (lo.id*hi.eph vs lo.eph*hi.id), so we
    // swap inputs based on role so that both sides arrive at the same ikm.
    bool i_am_lo = cmp32(p->my_pub_id, p->their_pub_id) < 0;
    int rc = 0;
    rc |= cp_x25519_shared(p->my_priv_id,  p->their_pub_id,  dh1);
    rc |= cp_x25519_shared(p->my_priv_eph, p->their_pub_eph, dh4);
    if (i_am_lo) {
        rc |= cp_x25519_shared(p->my_priv_id,  p->their_pub_eph, dh2);
        rc |= cp_x25519_shared(p->my_priv_eph, p->their_pub_id,  dh3);
    } else {
        // We are hi. dh2 = lo.id*hi.eph -> from our side that's my.eph*their.id.
        // dh3 = lo.eph*hi.id -> from our side my.id*their.eph.
        rc |= cp_x25519_shared(p->my_priv_eph, p->their_pub_id,  dh2);
        rc |= cp_x25519_shared(p->my_priv_id,  p->their_pub_eph, dh3);
    }
    if (rc) return -2;

    // Derive root + chain keys. HKDF(salt=0, ikm=dh1||dh2||dh3||dh4,
    // info="cardputer-v1") -> 96 bytes split into root, send, recv.
    uint8_t ikm[4 * CP_X25519_KEY_LEN];
    memcpy(ikm + 0,                       dh1, CP_X25519_KEY_LEN);
    memcpy(ikm + CP_X25519_KEY_LEN,       dh2, CP_X25519_KEY_LEN);
    memcpy(ikm + 2 * CP_X25519_KEY_LEN,   dh3, CP_X25519_KEY_LEN);
    memcpy(ikm + 3 * CP_X25519_KEY_LEN,   dh4, CP_X25519_KEY_LEN);

    uint8_t okm[96];
    rc = cp_hkdf(NULL, 0, ikm, sizeof(ikm),
                 (const uint8_t *)"cardputer-v1", 12,
                 okm, sizeof(okm));
    if (rc) return -3;
    memcpy(p->root_key, okm, 32);

    // Direction-dependent chain split: whoever has the lexicographically
    // smaller pub_id uses okm[32..64] as their send chain.
    if (i_am_lo) {
        memcpy(p->send_chain, okm + 32, 32);
        memcpy(p->recv_chain, okm + 64, 32);
    } else {
        memcpy(p->recv_chain, okm + 32, 32);
        memcpy(p->send_chain, okm + 64, 32);
    }

    // SAS transcript: lex-sorted (pub_id || pub_eph) pairs.
    uint8_t transcript[4 * CP_X25519_KEY_LEN];
    const uint8_t *lo_id, *lo_eph, *hi_id, *hi_eph;
    if (i_am_lo) {
        lo_id = p->my_pub_id;     lo_eph = p->my_pub_eph;
        hi_id = p->their_pub_id;  hi_eph = p->their_pub_eph;
    } else {
        lo_id = p->their_pub_id;  lo_eph = p->their_pub_eph;
        hi_id = p->my_pub_id;     hi_eph = p->my_pub_eph;
    }
    memcpy(transcript + 0,  lo_id,  CP_X25519_KEY_LEN);
    memcpy(transcript + 32, lo_eph, CP_X25519_KEY_LEN);
    memcpy(transcript + 64, hi_id,  CP_X25519_KEY_LEN);
    memcpy(transcript + 96, hi_eph, CP_X25519_KEY_LEN);
    sas_compute(transcript, sizeof(transcript), p->sas_emoji);

    return 0;
}
