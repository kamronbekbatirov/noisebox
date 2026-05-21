// SPDX-License-Identifier: AGPL-3.0-or-later
// NoiseBox -- end-to-end encrypted Cardputer messenger.
// Copyright (C) 2026 Kamronbek B. See LICENSE for the full text.

#include "crypto.h"

#include <string.h>

#include "esp_random.h"
#include "mbedtls/chachapoly.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/ecp.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/md.h"
#include "mbedtls/sha256.h"

static int rng_cb(void *ctx, unsigned char *out, size_t len) {
    (void)ctx;
    esp_fill_random(out, len);
    return 0;
}

void cp_random(void *buf, size_t len) {
    esp_fill_random(buf, len);
}

void cp_sha256(const uint8_t *data, size_t len, uint8_t out[CP_SHA256_LEN]) {
    mbedtls_sha256(data, len, out, 0);
}

int cp_hkdf(const uint8_t *salt, size_t salt_len,
            const uint8_t *ikm,  size_t ikm_len,
            const uint8_t *info, size_t info_len,
            uint8_t *out, size_t out_len) {
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    return mbedtls_hkdf(md, salt, salt_len, ikm, ikm_len, info, info_len, out, out_len);
}

int cp_x25519_keypair(uint8_t priv[CP_X25519_KEY_LEN], uint8_t pub[CP_X25519_KEY_LEN]) {
    mbedtls_ecdh_context ctx;
    mbedtls_ecdh_init(&ctx);
    int rc = mbedtls_ecdh_setup(&ctx, MBEDTLS_ECP_DP_CURVE25519);
    if (rc) goto out;

    rc = mbedtls_ecdh_gen_public(&ctx.MBEDTLS_PRIVATE(ctx).MBEDTLS_PRIVATE(mbed_ecdh).MBEDTLS_PRIVATE(grp),
                                 &ctx.MBEDTLS_PRIVATE(ctx).MBEDTLS_PRIVATE(mbed_ecdh).MBEDTLS_PRIVATE(d),
                                 &ctx.MBEDTLS_PRIVATE(ctx).MBEDTLS_PRIVATE(mbed_ecdh).MBEDTLS_PRIVATE(Q),
                                 rng_cb, NULL);
    if (rc) goto out;

    rc = mbedtls_mpi_write_binary_le(
        &ctx.MBEDTLS_PRIVATE(ctx).MBEDTLS_PRIVATE(mbed_ecdh).MBEDTLS_PRIVATE(d),
        priv, CP_X25519_KEY_LEN);
    if (rc) goto out;
    rc = mbedtls_mpi_write_binary_le(
        &ctx.MBEDTLS_PRIVATE(ctx).MBEDTLS_PRIVATE(mbed_ecdh).MBEDTLS_PRIVATE(Q).MBEDTLS_PRIVATE(X),
        pub, CP_X25519_KEY_LEN);

out:
    mbedtls_ecdh_free(&ctx);
    return rc;
}

int cp_x25519_shared(const uint8_t priv[CP_X25519_KEY_LEN],
                     const uint8_t their_pub[CP_X25519_KEY_LEN],
                     uint8_t shared[CP_X25519_KEY_LEN]) {
    mbedtls_ecp_group grp;
    mbedtls_mpi d, z;
    mbedtls_ecp_point Q;

    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_mpi_init(&z);
    mbedtls_ecp_point_init(&Q);

    int rc = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_CURVE25519);
    if (rc) goto out;

    rc = mbedtls_mpi_read_binary_le(&d, priv, CP_X25519_KEY_LEN);
    if (rc) goto out;
    rc = mbedtls_mpi_read_binary_le(&Q.MBEDTLS_PRIVATE(X), their_pub, CP_X25519_KEY_LEN);
    if (rc) goto out;
    rc = mbedtls_mpi_lset(&Q.MBEDTLS_PRIVATE(Z), 1);
    if (rc) goto out;

    rc = mbedtls_ecdh_compute_shared(&grp, &z, &Q, &d, rng_cb, NULL);
    if (rc) goto out;

    rc = mbedtls_mpi_write_binary_le(&z, shared, CP_X25519_KEY_LEN);

out:
    mbedtls_ecp_point_free(&Q);
    mbedtls_mpi_free(&z);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_group_free(&grp);
    return rc;
}

int cp_aead_encrypt(const uint8_t key[CP_CHACHA_KEY_LEN],
                    const uint8_t nonce[CP_CHACHA_NONCE_LEN],
                    const uint8_t *aad, size_t aad_len,
                    const uint8_t *pt, size_t pt_len,
                    uint8_t *out) {
    mbedtls_chachapoly_context ctx;
    mbedtls_chachapoly_init(&ctx);
    int rc = mbedtls_chachapoly_setkey(&ctx, key);
    if (rc) goto out;
    rc = mbedtls_chachapoly_encrypt_and_tag(&ctx, pt_len, nonce,
                                            aad, aad_len,
                                            pt, out,
                                            out + pt_len);
out:
    mbedtls_chachapoly_free(&ctx);
    return rc;
}

int cp_aead_decrypt(const uint8_t key[CP_CHACHA_KEY_LEN],
                    const uint8_t nonce[CP_CHACHA_NONCE_LEN],
                    const uint8_t *aad, size_t aad_len,
                    const uint8_t *ct, size_t ct_len,
                    uint8_t *out_pt) {
    if (ct_len < CP_POLY_TAG_LEN) return -1;
    size_t pt_len = ct_len - CP_POLY_TAG_LEN;

    mbedtls_chachapoly_context ctx;
    mbedtls_chachapoly_init(&ctx);
    int rc = mbedtls_chachapoly_setkey(&ctx, key);
    if (rc) goto out;
    rc = mbedtls_chachapoly_auth_decrypt(&ctx, pt_len, nonce,
                                         aad, aad_len,
                                         ct + pt_len,  // tag
                                         ct, out_pt);
out:
    mbedtls_chachapoly_free(&ctx);
    return rc;
}

int cp_ct_memcmp(const void *a, const void *b, size_t len) {
    const uint8_t *pa = a, *pb = b;
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) diff |= pa[i] ^ pb[i];
    return diff;
}
