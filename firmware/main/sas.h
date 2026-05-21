// SPDX-License-Identifier: AGPL-3.0-or-later
// NoiseBox -- end-to-end encrypted Cardputer messenger.
// Copyright (C) 2026 Kamronbek B. See LICENSE for the full text.

#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// SAS: Short Authentication String. We derive 25 bits from a hash of the
// handshake transcript and map them to 5 emoji from a 32-entry alphabet.
// Both devices, given the same transcript, produce the same 5 emoji.
// User compares them aloud or in person - if they match, no MITM.
//
// out_emoji must hold 5 NUL-terminated UTF-8 strings; emoji are returned
// as pointers into a static table (do not free).
#define SAS_EMOJI_COUNT 5

void sas_compute(const uint8_t *transcript, size_t transcript_len,
                 const char *out_emoji[SAS_EMOJI_COUNT]);

#ifdef __cplusplus
}
#endif
