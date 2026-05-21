// SPDX-License-Identifier: AGPL-3.0-or-later
// NoiseBox -- end-to-end encrypted Cardputer messenger.
// Copyright (C) 2026 Kamronbek B. See LICENSE for the full text.

#pragma once
#include <stdint.h>

// 8x16 monospace bitmap font for printable ASCII (0x20..0x7E).
// Each glyph is 16 bytes, one byte per row (MSB = leftmost pixel).
extern const uint8_t font8x16[95][16];
