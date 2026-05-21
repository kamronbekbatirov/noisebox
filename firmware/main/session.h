// SPDX-License-Identifier: AGPL-3.0-or-later
// NoiseBox -- end-to-end encrypted Cardputer messenger.
// Copyright (C) 2026 Kamronbek B. See LICENSE for the full text.

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "pairing.h"
#include "ratchet.h"

#ifdef __cplusplus
extern "C" {
#endif

// Wire protocol within the (base64-decoded) "text" field that we put into
// the relay's /send body:
//
//   byte 0 magic = 0x01  -> pairing HELLO (followed by PAIR_MSG_SIZE bytes)
//   byte 0 magic = 0x02  -> chat message  (followed by ratchet packet)
//
// The relay never inspects this - it just relays the base64 string.
#define SESSION_MAGIC_HELLO  0x01
#define SESSION_MAGIC_MSG    0x02

#define SESSION_MAX_PLAINTEXT  500
#define SESSION_MAX_CIPHER     560   // worst-case base64 of largest msg

typedef enum {
    SESSION_IDLE = 0,
    SESSION_PAIRING,
    SESSION_PAIRED,
} session_state_t;

// Begin a new pairing session with the given peer. Loads/creates identity.
int  session_begin(int64_t peer_user_id);

// Build our pair HELLO into the given buffer; returns base64 string (NUL
// terminated) in `out` (size at least 128 bytes). Returns 0 on success.
int  session_make_hello_b64(char *out, size_t cap);

// Feed an incoming base64-wrapped pairing HELLO from the peer.
// Returns 0 if accepted, <0 on error.
int  session_feed_hello_b64(const char *b64);

// True once both HELLOs are exchanged.
bool session_both_hellos(void);

// After both HELLOs: compute root key + chain + SAS. SAS pointer is into
// static table (do not free).  Returns 0 on success.
int  session_finalise(const char **out_sas_words /* SAS_EMOJI_COUNT */);

// Confirm SAS (user pressed Y). Initialises ratchet for chat.
int  session_confirm_sas(void);

// Encrypt `text` and produce base64 ciphertext ready for tx_send().
// Returns 0 on success.
int  session_encrypt_b64(const char *text, char *out, size_t cap);

// Decode a base64-wrapped incoming message. If it's a chat message,
// fills `out_text` (size cap) and returns 1.
// If it's a hello (during pairing), feeds it and returns 2.
// Returns 0 if unknown / not for us, <0 on error.
int  session_decode_incoming(const char *b64, char *out_text, size_t cap);

session_state_t session_state(void);

// Try to restore an existing chat session for the given peer from NVS.
// Returns 0 if a saved session was found and is now active (chat-ready, no
// handshake required); <0 if not (the caller should run handshake).
int  session_resume(int64_t peer_user_id);

// Persist current ratchet state for the given peer. Call after each encrypt
// or decrypt to keep on-disk state in sync.
int  session_persist(int64_t peer_user_id, uint32_t last_seen_msg_id);

// Look up the last_seen_msg_id we persisted for this peer (0 if no record).
uint32_t session_last_seen(int64_t peer_user_id);

#ifdef __cplusplus
}
#endif
