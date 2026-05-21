// SPDX-License-Identifier: AGPL-3.0-or-later
// NoiseBox -- end-to-end encrypted Cardputer messenger.
// Copyright (C) 2026 Kamronbek B. See LICENSE for the full text.

// Wi-Fi station mode + scan + NVS credential storage.

#include "wifi.h"

#include <stdlib.h>
#include <string.h>

#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/task.h"
#include "nvs.h"

static const char *TAG = "wifi";

#define BIT_GOT_IP   BIT0
#define BIT_FAIL     BIT1

static EventGroupHandle_t s_evt = NULL;
static int                s_retries;
static volatile bool      s_connected;
static bool               s_stack_inited = false;

static void evt_handler(void *arg, esp_event_base_t base, int32_t id, void *data) {
    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
        s_connected = false;
        if (s_retries < 4) {
            s_retries++;
            esp_wifi_connect();
        } else {
            xEventGroupSetBits(s_evt, BIT_FAIL);
        }
    } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *e = (ip_event_got_ip_t *)data;
        ESP_LOGI(TAG, "got IP " IPSTR, IP2STR(&e->ip_info.ip));
        s_retries = 0;
        s_connected = true;
        xEventGroupSetBits(s_evt, BIT_GOT_IP);
    }
}

int wifi_stack_init(void) {
    if (s_stack_inited) return 0;
    s_evt = xEventGroupCreate();

    esp_err_t e = esp_netif_init();
    if (e != ESP_OK) { ESP_LOGE(TAG, "netif_init: %d", e); return -1; }

    e = esp_event_loop_create_default();
    if (e != ESP_OK && e != ESP_ERR_INVALID_STATE) {
        ESP_LOGE(TAG, "event_loop: %d", e); return -2;
    }
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    e = esp_wifi_init(&cfg);
    if (e != ESP_OK) { ESP_LOGE(TAG, "wifi_init: %d", e); return -3; }

    esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID,
                                        &evt_handler, NULL, NULL);
    esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP,
                                        &evt_handler, NULL, NULL);
    e = esp_wifi_set_mode(WIFI_MODE_STA);
    if (e != ESP_OK) { ESP_LOGE(TAG, "set_mode: %d", e); return -4; }

    e = esp_wifi_start();
    if (e != ESP_OK) { ESP_LOGE(TAG, "start: %d", e); return -5; }

    s_stack_inited = true;
    ESP_LOGI(TAG, "stack ready");
    return 0;
}

int wifi_connect(const char *ssid, const char *password, int timeout_ms) {
    if (!s_stack_inited && wifi_stack_init() != 0) return -1;

    wifi_config_t wc = { 0 };
    strncpy((char *)wc.sta.ssid,     ssid,     sizeof(wc.sta.ssid)     - 1);
    strncpy((char *)wc.sta.password, password, sizeof(wc.sta.password) - 1);
    // If we have a password, require at least WPA2-PSK so a rogue OPEN AP
    // spoofing the saved SSID can't lure the device into clear-text Wi-Fi.
    // For known-open networks (no password saved) keep AUTH_OPEN.
    wc.sta.threshold.authmode =
        (password && password[0]) ? WIFI_AUTH_WPA2_PSK : WIFI_AUTH_OPEN;
    s_retries = 0;
    s_connected = false;
    xEventGroupClearBits(s_evt, BIT_GOT_IP | BIT_FAIL);

    esp_err_t e = esp_wifi_set_config(WIFI_IF_STA, &wc);
    if (e != ESP_OK) return -2;
    esp_wifi_disconnect();
    vTaskDelay(pdMS_TO_TICKS(100));
    e = esp_wifi_connect();
    if (e != ESP_OK) return -3;

    EventBits_t bits = xEventGroupWaitBits(s_evt, BIT_GOT_IP | BIT_FAIL,
                                           pdFALSE, pdFALSE,
                                           pdMS_TO_TICKS(timeout_ms));
    if (bits & BIT_GOT_IP) return 0;
    return -4;
}

void wifi_disconnect(void) {
    if (!s_stack_inited) return;
    esp_wifi_disconnect();
    s_connected = false;
}

bool wifi_is_connected(void) { return s_connected; }

int wifi_scan(wifi_ap_t *out, int cap, int timeout_ms) {
    (void)timeout_ms;
    if (!s_stack_inited && wifi_stack_init() != 0) return -1;
    wifi_scan_config_t cfg = {
        .ssid = NULL, .bssid = NULL, .channel = 0, .show_hidden = false,
        .scan_type = WIFI_SCAN_TYPE_ACTIVE,
        .scan_time.active.min = 100, .scan_time.active.max = 300,
    };
    esp_err_t e = esp_wifi_scan_start(&cfg, true);
    if (e != ESP_OK) { ESP_LOGE(TAG, "scan_start: %d", e); return -2; }

    uint16_t count = 0;
    esp_wifi_scan_get_ap_num(&count);
    if (count > cap) count = cap;
    if (count == 0) return 0;

    wifi_ap_record_t *recs = (wifi_ap_record_t *)calloc(count, sizeof(wifi_ap_record_t));
    if (!recs) return -3;
    uint16_t got = count;
    esp_wifi_scan_get_ap_records(&got, recs);

    for (uint16_t i = 0; i < got; i++) {
        memset(&out[i], 0, sizeof(out[i]));
        strncpy(out[i].ssid, (char *)recs[i].ssid, WIFI_SSID_MAX - 1);
        out[i].rssi = recs[i].rssi;
        out[i].authmode = recs[i].authmode;
    }
    free(recs);
    return got;
}

// --- NVS credential storage ---

#define WIFI_NS  "wifi"

int wifi_load_saved(char *ssid_out, size_t ssid_cap,
                    char *pass_out, size_t pass_cap) {
    nvs_handle_t h;
    if (nvs_open(WIFI_NS, NVS_READONLY, &h) != ESP_OK) return -1;
    size_t l1 = ssid_cap, l2 = pass_cap;
    esp_err_t e1 = nvs_get_str(h, "ssid", ssid_out, &l1);
    esp_err_t e2 = nvs_get_str(h, "pass", pass_out, &l2);
    nvs_close(h);
    if (e1 != ESP_OK || e2 != ESP_OK) return -2;
    return 0;
}

int wifi_save(const char *ssid, const char *password) {
    nvs_handle_t h;
    if (nvs_open(WIFI_NS, NVS_READWRITE, &h) != ESP_OK) return -1;
    esp_err_t e = nvs_set_str(h, "ssid", ssid);
    e |= nvs_set_str(h, "pass", password);
    e |= nvs_commit(h);
    nvs_close(h);
    return e == ESP_OK ? 0 : -2;
}

int wifi_clear_saved(void) {
    nvs_handle_t h;
    if (nvs_open(WIFI_NS, NVS_READWRITE, &h) != ESP_OK) return -1;
    nvs_erase_key(h, "ssid");
    nvs_erase_key(h, "pass");
    nvs_commit(h);
    nvs_close(h);
    return 0;
}
