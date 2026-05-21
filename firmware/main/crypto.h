// SPDX-License-Identifier: AGPL-3.0-or-later
// NoiseBox -- end-to-end encrypted Cardputer messenger.
// Copyright (C) 2026 Kamronbek B. See LICENSE for the full text.

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CP_X25519_KEY_LEN   32
#define CP_SHA256_LEN       32
#define CP_CHACHA_KEY_LEN   32
#define CP_CHACHA_NONCE_LEN 12
#define CP_POLY_TAG_LEN     16

// X25519. Returns 0 on success.
int  cp_x25519_keypair(uint8_t priv[CP_X25519_KEY_LEN], uint8_t pub[CP_X25519_KEY_LEN]);
int  cp_x25519_shared (const uint8_t priv[CP_X25519_KEY_LEN],
                       const uint8_t their_pub[CP_X25519_KEY_LEN],
                       uint8_t       shared[CP_X25519_KEY_LEN]);

// SHA-256.
void cp_sha256(const uint8_t *data, size_t len, uint8_t out[CP_SHA256_LEN]);

// HKDF-SHA256.  Returns 0 on success.
int  cp_hkdf(const uint8_t *salt,    size_t salt_len,
             const uint8_t *ikm,     size_t ikm_len,
             const uint8_t *info,    size_t info_len,
             uint8_t       *out,     size_t out_len);

// ChaCha20-Poly1305 AEAD. AAD may be NULL.
// Encrypt: out gets ciphertext (pt_len bytes) followed by 16-byte tag.
// Decrypt: ct includes the trailing 16-byte tag; ct_len is total length.
int cp_aead_encrypt(const uint8_t key[CP_CHACHA_KEY_LEN],
                    const uint8_t nonce[CP_CHACHA_NONCE_LEN],
                    const uint8_t *aad, size_t aad_len,
                    const uint8_t *pt,  size_t pt_len,
                    uint8_t       *out);
int cp_aead_decrypt(const uint8_t key[CP_CHACHA_KEY_LEN],
                    const uint8_t nonce[CP_CHACHA_NONCE_LEN],
                    const uint8_t *aad, size_t aad_len,
                    const uint8_t *ct,  size_t ct_len,
                    uint8_t       *out_pt);

// Hardware RNG (esp_fill_random under the hood).
void cp_random(void *buf, size_t len);

// Constant-time memcmp; returns 0 on equal.
int  cp_ct_memcmp(const void *a, const void *b, size_t len);

#ifdef __cplusplus
}
#endif
