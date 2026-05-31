// SPDX-License-Identifier: AGPL-3.0-or-later
// NoiseBox -- end-to-end encrypted Cardputer messenger.
// Copyright (C) 2026 Kamronbek B. See LICENSE for the full text.

// Persistent state for NoiseBox.
//
// SECURITY NOTE (read me before publishing):
//   This file writes the device's long-term X25519 private identity, the
//   Wi-Fi password, the per-device bearer token issued by the relay, and
//   per-peer ratchet keys -- all to NVS in PLAINTEXT. ESP32-S3 flash
//   encryption is OFF by default in this build.
//
//   Threat: anyone with shell access to the device (serial / JTAG) or
//   physical access to the SPI flash chip can extract every secret and
//   impersonate this device against established peers.
//
//   Mitigation when going to production:
//     1. Burn flash encryption eFuse keys ONCE:
//          idf.py -p PORT flash-encryption-enable
//        (this is irreversible; verify on a sacrificial board first.)
//     2. Set CONFIG_NVS_ENCRYPTION=y in sdkconfig.defaults and add a
//        `nvs_keys` partition (type=data, subtype=nvs_keys, flags=encrypted)
//        to partitions.csv. The flash encryption key derives the NVS key.
//   See:
//     https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/security/flash-encryption.html
//     https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-reference/storage/nvs_encryption.html
//
// Until that's done, treat the device like a paper notebook: secret if you
// keep it on your person, public if it's lost.

#include "storage.h"

#include <stdio.h>
#include <string.h>

#include "esp_log.h"
#include "nvs.h"
#include "nvs_flash.h"

static const char *TAG = "storage";
static const char *NS         = "noisebox";
static const char *NS_PEERS   = "peers";
static const char *K_IDENTITY_PRIV = "id_priv";
static const char *K_IDENTITY_PUB  = "id_pub";
static const char *K_DEVICE_TOKEN  = "dev_tok";
static const char *K_RELAY_ID      = "rly_id";
static const char *K_RELAY_HOST    = "rly_host";

int storage_load_identity(uint8_t priv[CP_X25519_KEY_LEN],
                          uint8_t pub [CP_X25519_KEY_LEN]) {
    nvs_handle_t h;
    if (nvs_open(NS, NVS_READONLY, &h) != ESP_OK) return -1;
    size_t lp = CP_X25519_KEY_LEN, lq = CP_X25519_KEY_LEN;
    esp_err_t ep = nvs_get_blob(h, K_IDENTITY_PRIV, priv, &lp);
    esp_err_t eq = nvs_get_blob(h, K_IDENTITY_PUB,  pub,  &lq);
    nvs_close(h);
    if (ep != ESP_OK || eq != ESP_OK
            || lp != CP_X25519_KEY_LEN || lq != CP_X25519_KEY_LEN) {
        return -1;
    }
    return 0;
}

int storage_save_identity(const uint8_t priv[CP_X25519_KEY_LEN],
                          const uint8_t pub [CP_X25519_KEY_LEN]) {
    nvs_handle_t h;
    esp_err_t e = nvs_open(NS, NVS_READWRITE, &h);
    if (e != ESP_OK) { ESP_LOGE(TAG, "nvs_open: %d", e); return -1; }
    e |= nvs_set_blob(h, K_IDENTITY_PRIV, priv, CP_X25519_KEY_LEN);
    e |= nvs_set_blob(h, K_IDENTITY_PUB,  pub,  CP_X25519_KEY_LEN);
    e |= nvs_commit(h);
    nvs_close(h);
    return e == ESP_OK ? 0 : -1;
}

// ---- device bearer token -------------------------------------------------

int storage_load_device_token(char *out, size_t cap) {
    if (!out || cap < 2) return -1;
    nvs_handle_t h;
    if (nvs_open(NS, NVS_READONLY, &h) != ESP_OK) return -1;
    size_t sz = cap;
    esp_err_t e = nvs_get_str(h, K_DEVICE_TOKEN, out, &sz);
    nvs_close(h);
    if (e != ESP_OK) { out[0] = 0; return -2; }
    return 0;
}

int storage_save_device_token(const char *token) {
    nvs_handle_t h;
    if (nvs_open(NS, NVS_READWRITE, &h) != ESP_OK) return -1;
    esp_err_t e = nvs_set_str(h, K_DEVICE_TOKEN, token);
    e |= nvs_commit(h);
    nvs_close(h);
    return e == ESP_OK ? 0 : -2;
}

int storage_clear_device_token(void) {
    nvs_handle_t h;
    if (nvs_open(NS, NVS_READWRITE, &h) != ESP_OK) return -1;
    nvs_erase_key(h, K_DEVICE_TOKEN);
    nvs_commit(h);
    nvs_close(h);
    return 0;
}

// ---- relay configuration (entered on first boot) ------------------------

int storage_load_relay_id(char *out, size_t cap) {
    if (!out || cap < 2) return -1;
    nvs_handle_t h;
    if (nvs_open(NS, NVS_READONLY, &h) != ESP_OK) return -1;
    size_t sz = cap;
    esp_err_t e = nvs_get_str(h, K_RELAY_ID, out, &sz);
    nvs_close(h);
    if (e != ESP_OK) { out[0] = 0; return -2; }
    return 0;
}

int storage_save_relay_id(const char *relay_id) {
    if (!relay_id) return -1;
    nvs_handle_t h;
    if (nvs_open(NS, NVS_READWRITE, &h) != ESP_OK) return -1;
    esp_err_t e = nvs_set_str(h, K_RELAY_ID, relay_id);
    e |= nvs_commit(h);
    nvs_close(h);
    return e == ESP_OK ? 0 : -2;
}

int storage_load_relay_host(char *out, size_t cap) {
    if (!out || cap < 2) return -1;
    nvs_handle_t h;
    if (nvs_open(NS, NVS_READONLY, &h) != ESP_OK) return -1;
    size_t sz = cap;
    esp_err_t e = nvs_get_str(h, K_RELAY_HOST, out, &sz);
    nvs_close(h);
    if (e != ESP_OK) { out[0] = 0; return -2; }
    return 0;
}

int storage_save_relay_host(const char *host) {
    if (!host) return -1;
    nvs_handle_t h;
    if (nvs_open(NS, NVS_READWRITE, &h) != ESP_OK) return -1;
    esp_err_t e = nvs_set_str(h, K_RELAY_HOST, host);
    e |= nvs_commit(h);
    nvs_close(h);
    return e == ESP_OK ? 0 : -2;
}

// ---- per-peer state ------------------------------------------------------
//
// NVS keys are limited to 15 chars. Telegram user_ids are <= 13 digits today.
// We pack them as decimal in a stack buffer.

static void peer_key(int64_t peer_user_id, char out[16]) {
    snprintf(out, 16, "%lld", (long long)peer_user_id);
}

int storage_load_peer(int64_t peer_user_id, peer_state_t *out) {
    nvs_handle_t h;
    if (nvs_open(NS_PEERS, NVS_READONLY, &h) != ESP_OK) return -1;
    char key[16]; peer_key(peer_user_id, key);
    size_t sz = sizeof(*out);
    esp_err_t e = nvs_get_blob(h, key, out, &sz);
    nvs_close(h);
    if (e != ESP_OK || sz != sizeof(*out)) return -2;
    return 0;
}

int storage_save_peer(int64_t peer_user_id, const peer_state_t *in) {
    nvs_handle_t h;
    if (nvs_open(NS_PEERS, NVS_READWRITE, &h) != ESP_OK) return -1;
    char key[16]; peer_key(peer_user_id, key);
    esp_err_t e = nvs_set_blob(h, key, in, sizeof(*in));
    e |= nvs_commit(h);
    nvs_close(h);
    return e == ESP_OK ? 0 : -2;
}

int storage_forget_peer(int64_t peer_user_id) {
    nvs_handle_t h;
    if (nvs_open(NS_PEERS, NVS_READWRITE, &h) != ESP_OK) return -1;
    char key[16]; peer_key(peer_user_id, key);
    nvs_erase_key(h, key);
    nvs_commit(h);
    nvs_close(h);
    return 0;
}

// ---- forget knobs --------------------------------------------------------

int storage_forget_binding(void) {
    nvs_handle_t h;
    if (nvs_open(NS, NVS_READWRITE, &h) != ESP_OK) return -1;
    nvs_erase_key(h, "uid");
    nvs_erase_key(h, K_DEVICE_TOKEN);
    nvs_commit(h);
    nvs_close(h);
    return 0;
}

int storage_forget_all(void) {
    // Erase every namespace we own (identity, binding, all peer state, wifi).
    // We do NOT erase NVS_PART itself - the partition stays formatted.
    nvs_handle_t h;
    if (nvs_open(NS, NVS_READWRITE, &h) == ESP_OK) {
        nvs_erase_all(h); nvs_commit(h); nvs_close(h);
    }
    if (nvs_open(NS_PEERS, NVS_READWRITE, &h) == ESP_OK) {
        nvs_erase_all(h); nvs_commit(h); nvs_close(h);
    }
    if (nvs_open("wifi", NVS_READWRITE, &h) == ESP_OK) {
        nvs_erase_all(h); nvs_commit(h); nvs_close(h);
    }
    return 0;
}
