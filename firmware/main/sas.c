// SPDX-License-Identifier: AGPL-3.0-or-later
// NoiseBox -- end-to-end encrypted Cardputer messenger.
// Copyright (C) 2026 Kamronbek B. See LICENSE for the full text.

#include "sas.h"

#include <stdint.h>
#include <string.h>

#include "crypto.h"

// 32 visually distinctive emoji - one per 5-bit index. Picked to be easy to
// name aloud over the phone and hard to confuse with each other.
const char *const SAS_ALPHABET[32] = {
    "\xF0\x9F\x90\xB6", // 0  dog
    "\xF0\x9F\x90\xB1", // 1  cat
    "\xF0\x9F\x90\xAD", // 2  mouse
    "\xF0\x9F\x90\xB0", // 3  rabbit
    "\xF0\x9F\xA6\x8A", // 4  fox
    "\xF0\x9F\x90\xBB", // 5  bear
    "\xF0\x9F\x90\xBC", // 6  panda
    "\xF0\x9F\xA6\x81", // 7  lion
    "\xF0\x9F\x90\xAF", // 8  tiger
    "\xF0\x9F\x90\xB4", // 9  horse
    "\xF0\x9F\xA6\x84", // 10 unicorn
    "\xF0\x9F\x90\xAE", // 11 cow
    "\xF0\x9F\x90\xB7", // 12 pig
    "\xF0\x9F\x90\xB8", // 13 frog
    "\xF0\x9F\x90\x99", // 14 octopus
    "\xF0\x9F\x90\xA0", // 15 fish
    "\xF0\x9F\x8C\xB5", // 16 cactus
    "\xF0\x9F\x8C\xB3", // 17 tree
    "\xF0\x9F\x8C\xBB", // 18 sunflower
    "\xF0\x9F\x8D\x8E", // 19 apple
    "\xF0\x9F\x8D\x8B", // 20 lemon
    "\xF0\x9F\x8D\x93", // 21 strawberry
    "\xF0\x9F\x8D\x89", // 22 watermelon
    "\xF0\x9F\x8D\x95", // 23 pizza
    "\xF0\x9F\x9A\x80", // 24 rocket
    "\xF0\x9F\x9A\x97", // 25 car
    "\xE2\x9A\x93",     // 26 anchor
    "\xF0\x9F\x94\x91", // 27 key
    "\xF0\x9F\x94\x94", // 28 bell
    "\xF0\x9F\x8E\xB8", // 29 guitar
    "\xF0\x9F\x8E\xB2", // 30 die
    "\xF0\x9F\x8C\x9F", // 31 star
};

void sas_compute(const uint8_t *transcript, size_t transcript_len,
                 const char *out_emoji[SAS_EMOJI_COUNT]) {
    uint8_t h[CP_SHA256_LEN];
    cp_sha256(transcript, transcript_len, h);

    // First 25 bits of h, 5 bits per emoji index.
    uint32_t bits = ((uint32_t)h[0] << 17) | ((uint32_t)h[1] << 9)
                  | ((uint32_t)h[2] << 1)  | ((uint32_t)h[3] >> 7);
    for (int i = 0; i < SAS_EMOJI_COUNT; i++) {
        uint32_t idx = (bits >> (20 - i * 5)) & 0x1F;
        out_emoji[i] = SAS_ALPHABET[idx];
    }
}
