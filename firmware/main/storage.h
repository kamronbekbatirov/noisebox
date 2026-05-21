// SPDX-License-Identifier: AGPL-3.0-or-later
// NoiseBox -- end-to-end encrypted Cardputer messenger.
// Copyright (C) 2026 Kamronbek B. See LICENSE for the full text.

#pragma once

#include <stdint.h>
#include "crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

// Long-term X25519 identity (this device's "you" key).
int storage_load_identity(uint8_t priv[CP_X25519_KEY_LEN],
                          uint8_t pub [CP_X25519_KEY_LEN]);
int storage_save_identity(const uint8_t priv[CP_X25519_KEY_LEN],
                          const uint8_t pub [CP_X25519_KEY_LEN]);

// Per-device bearer token issued by the relay at bind time. Used as the
// URL-path token for all device-scoped API calls. `out` cap >= 80.
int storage_load_device_token(char *out, size_t cap);
int storage_save_device_token(const char *token);
int storage_clear_device_token(void);

// Relay configuration entered by the user on first boot ("Relay setup"
// screen). Lets us ship a single signed binary that any user can flash
// without rebuilding firmware. Both `out` caps should be at least 128.
int storage_load_relay_token(char *out, size_t cap);
int storage_save_relay_token(const char *token);
int storage_load_relay_host (char *out, size_t cap);
int storage_save_relay_host (const char *host);

// Per-peer ratchet state (survives reboots so we don't lose history nor
// double-encrypt counters across power-ups).
typedef struct __attribute__((packed)) {
    uint8_t  peer_pub_id[CP_X25519_KEY_LEN];
    uint8_t  send_chain [32];
    uint8_t  recv_chain [32];
    uint32_t send_ctr;
    uint32_t recv_ctr;
    uint32_t last_seen_msg_id;     // last relay inbox id we've processed
    uint32_t reserved;
} peer_state_t;

int storage_load_peer  (int64_t peer_user_id, peer_state_t *out);
int storage_save_peer  (int64_t peer_user_id, const peer_state_t *in);
int storage_forget_peer(int64_t peer_user_id);

// Whole-device reset helpers.
int storage_forget_binding(void);   // clears user_chat_id key
int storage_forget_all    (void);   // forget everything (full nvs wipe)

#ifdef __cplusplus
}
#endif
