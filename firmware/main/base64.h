// SPDX-License-Identifier: AGPL-3.0-or-later
// NoiseBox -- end-to-end encrypted Cardputer messenger.
// Copyright (C) 2026 Kamronbek B. See LICENSE for the full text.

#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Base64 (no padding stripping; standard alphabet).
// Writes a NUL terminator if out_cap permits.
// Returns number of bytes written (excluding NUL) on success, -1 on overflow.
int b64_encode(const uint8_t *in, size_t in_len, char *out, size_t out_cap);

// Returns number of decoded bytes, -1 on error.
int b64_decode(const char *in, size_t in_len, uint8_t *out, size_t out_cap);

#ifdef __cplusplus
}
#endif
