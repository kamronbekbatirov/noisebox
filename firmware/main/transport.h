// SPDX-License-Identifier: AGPL-3.0-or-later
// NoiseBox -- end-to-end encrypted Cardputer messenger.
// Copyright (C) 2026 Kamronbek B. See LICENSE for the full text.

#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TX_MAX_PEERS    8
#define TX_PEER_NAME    33
#define TX_MAX_MSG      512

typedef struct {
    int64_t user_id;
    char    name[TX_PEER_NAME];
} tx_peer_t;

typedef struct {
    uint32_t id;
    int64_t  from;
    int64_t  ts;
    char     text[TX_MAX_MSG];
} tx_msg_t;

// One-time init. `relay_id` is the public identifier of the relay; only
// /bind_poll uses it at provisioning time. After /pair, everything else
// uses the per-device token from `tx_set_device_token`.
void tx_init(const char *host, const char *relay_id);
void tx_set_device_token(const char *device_token);

// GET /v1/<relay_id>/bind_poll?code=NNNNNN
//   0  -> bound: *out_user_chat_id and `out_device_token` (>=80B) populated
//   1  -> not bound yet
//  <0  -> expired / claimed / transport error
int  tx_bind_poll(const char *code, int64_t *out_user_chat_id,
                  char *out_device_token, size_t token_cap);

// GET /v1/<device_token>/peers
int  tx_get_peers(tx_peer_t *out, int cap);

// GET /v1/<device_token>/info -> head_id of the inbox.
int  tx_get_head_id(uint32_t *out_head_id);

// POST /v1/<device_token>/send  body: {"peer_user_id":B,"text":"..."}
int  tx_send(int64_t peer_user_id, const char *text);

// GET /v1/<device_token>/poll?after=N&timeout=T
int  tx_poll(uint32_t *after_inout, tx_msg_t *out, int cap, int timeout_s);

#ifdef __cplusplus
}
#endif
