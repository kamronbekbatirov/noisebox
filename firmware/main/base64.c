// SPDX-License-Identifier: AGPL-3.0-or-later
// NoiseBox -- end-to-end encrypted Cardputer messenger.
// Copyright (C) 2026 Kamronbek B. See LICENSE for the full text.

#include "base64.h"

#include "mbedtls/base64.h"

int b64_encode(const uint8_t *in, size_t in_len, char *out, size_t out_cap) {
    size_t olen = 0;
    int rc = mbedtls_base64_encode((unsigned char *)out, out_cap, &olen, in, in_len);
    if (rc != 0) return -1;
    return (int)olen;
}

int b64_decode(const char *in, size_t in_len, uint8_t *out, size_t out_cap) {
    size_t olen = 0;
    int rc = mbedtls_base64_decode(out, out_cap, &olen, (const unsigned char *)in, in_len);
    if (rc != 0) return -1;
    return (int)olen;
}
