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

#define WIFI_SSID_MAX  33
#define WIFI_PASS_MAX  65

typedef struct {
    char ssid[WIFI_SSID_MAX];
    int  rssi;          // dBm
    int  authmode;      // wifi_auth_mode_t
} wifi_ap_t;

// Initialise Wi-Fi stack (event loop, netif, station mode). Idempotent.
int  wifi_stack_init(void);

// Connect with explicit credentials. Returns 0 on success, <0 on timeout/auth.
int  wifi_connect(const char *ssid, const char *password, int timeout_ms);
void wifi_disconnect(void);
bool wifi_is_connected(void);

// Active scan; fills up to `cap` aps into `out`. Returns number found.
int  wifi_scan(wifi_ap_t *out, int cap, int timeout_ms);

// NVS-backed credential storage.
int  wifi_load_saved(char *ssid_out, size_t ssid_cap,
                     char *pass_out, size_t pass_cap);
int  wifi_save(const char *ssid, const char *password);
int  wifi_clear_saved(void);

#ifdef __cplusplus
}
#endif
