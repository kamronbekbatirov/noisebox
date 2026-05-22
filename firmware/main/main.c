// SPDX-License-Identifier: AGPL-3.0-or-later
// NoiseBox -- end-to-end encrypted Cardputer messenger.
// Copyright (C) 2026 Kamronbek B. See LICENSE for the full text.

// NoiseBox firmware - main FSM.
//
// Boot -> Wi-Fi (saved or picker) -> bind device to Telegram via /pair NNNNNN
// -> peer list -> per-peer X25519 handshake + SAS confirmation -> chat.
//
// All UI uses the framework in ui.h. State persistence: Wi-Fi creds and the
// device's bound user_chat_id live in NVS. Ratchet state is ephemeral - we
// re-handshake each session.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "esp_log.h"
#include "esp_random.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "nvs.h"
#include "nvs_flash.h"

#include "config.h"
#include "display.h"
#include "keyboard.h"
#include "session.h"
#include "storage.h"
#include "transport.h"
#include "ui.h"
#include "wifi.h"

// SAS_ALPHABET lives in sas.c.
extern const char *const SAS_ALPHABET[32];

static const char *TAG = "main";

#define APP_NS  "noisebox"

static int64_t g_user_chat_id = 0;

static int load_user_chat_id(int64_t *out) {
    nvs_handle_t h;
    if (nvs_open(APP_NS, NVS_READONLY, &h) != ESP_OK) return -1;
    int64_t v = 0;
    esp_err_t e = nvs_get_i64(h, "uid", &v);
    nvs_close(h);
    if (e != ESP_OK) return -2;
    *out = v;
    return 0;
}

static int save_user_chat_id(int64_t v) {
    nvs_handle_t h;
    if (nvs_open(APP_NS, NVS_READWRITE, &h) != ESP_OK) return -1;
    esp_err_t e = nvs_set_i64(h, "uid", v);
    e |= nvs_commit(h);
    nvs_close(h);
    return e == ESP_OK ? 0 : -2;
}

static void gen_bind_code(char out[7]) {
    uint32_t v = esp_random() % 1000000;
    snprintf(out, 7, "%06u", (unsigned)v);
}

// ----------------------------------------------------------------- screens --

static int screen_wifi(void) {
    char ssid[WIFI_SSID_MAX] = {0};
    char pass[WIFI_PASS_MAX] = {0};

    // Try saved credentials first.
    if (wifi_load_saved(ssid, sizeof ssid, pass, sizeof pass) == 0) {
        ui_spinner_begin("Wi-Fi", ssid);
        for (int t = 0; t < 30; t++) {
            ui_spinner_tick();
            int rc = wifi_connect(ssid, pass, 1000);
            if (rc == 0) return 0;
            vTaskDelay(pdMS_TO_TICKS(200));
        }
        ui_show_message("Wi-Fi failed",
                        "Could not connect with\nsaved credentials.",
                        "press enter to pick a new network");
    } else if (NOISE_DEFAULT_SSID[0] != 0) {
        ui_spinner_begin("Wi-Fi", NOISE_DEFAULT_SSID);
        if (wifi_connect(NOISE_DEFAULT_SSID, NOISE_DEFAULT_PASS, 15000) == 0) {
            wifi_save(NOISE_DEFAULT_SSID, NOISE_DEFAULT_PASS);
            return 0;
        }
        ui_show_message("Wi-Fi failed", "Default network unavailable",
                        "press enter to scan");
    }

    while (1) {
        ui_spinner_begin("Wi-Fi scan", "looking for networks...");
        wifi_ap_t aps[16];
        int n = wifi_scan(aps, 16, 5000);
        ui_spinner_end();

        if (n <= 0) {
            ui_show_message("Wi-Fi scan", "no networks found", "press enter to retry");
            continue;
        }
        char *labels[16];
        for (int i = 0; i < n; i++) {
            labels[i] = (char *)malloc(40);
            snprintf(labels[i], 40, "%-22s %ddBm", aps[i].ssid, aps[i].rssi);
        }
        int idx = ui_menu("Pick a Wi-Fi", (const char *const *)labels, n,
                          ";=up  .=down  enter=ok  ` =rescan");
        for (int i = 0; i < n; i++) free(labels[i]);
        if (idx < 0) continue;

        strncpy(ssid, aps[idx].ssid, sizeof ssid - 1);
        ssid[sizeof ssid - 1] = 0;

        if (aps[idx].authmode == 0) {
            pass[0] = 0;
        } else {
            if (ui_text_input("Password", pass, sizeof pass,
                              /*masked=*/false,
                              "enter=connect, ` =cancel") != 0) continue;
        }

        ui_spinner_begin("Connecting", ssid);
        ui_spinner_tick();
        if (wifi_connect(ssid, pass, 15000) == 0) {
            wifi_save(ssid, pass);
            return 0;
        }
        ui_show_message("Wi-Fi failed",
                        "wrong password or out of range",
                        "press enter to try again");
    }
}

// Render the whole bind screen with the given 6-digit code.
static void bind_render(const char *code) {
    display_clear(COL_BLACK);
    ui_title("Bind to your account");
    char line1[40], line2[16];
    snprintf(line1, sizeof line1, "Code: %s", code);
    display_center_str(UI_BODY_Y + 8,  line1, COL_NOISEBOX, COL_BLACK);
    display_center_str(UI_BODY_Y + 30, "Open DM with the bot",     COL_PAPER, COL_BLACK);
    display_center_str(UI_BODY_Y + 48, "and type:",                COL_PAPER, COL_BLACK);
    snprintf(line2, sizeof line2, "/pair %s", code);
    display_center_str(UI_BODY_Y + 66, line2, COL_NOISEBOX, COL_BLACK);
    ui_hint("waiting...");
}

static int screen_bind(void) {
    char code[7];
    gen_bind_code(code);
    bind_render(code);

    int64_t uid = 0;
    int tick = 0;
    while (1) {
        key_event_t e;
        if (kbd_poll(&e) && e.kind == KEY_EV_ESC) return -1;

        char dtok[96];
        int rc = tx_bind_poll(code, &uid, dtok, sizeof dtok);
        if (rc == 0) {
            g_user_chat_id = uid;
            save_user_chat_id(uid);
            storage_save_device_token(dtok);
            tx_set_device_token(dtok);
            ui_status("BOUND", COL_GREEN);
            char m[80];
            snprintf(m, sizeof m, "Bound!\nuser_chat_id=%lld", (long long)uid);
            ui_show_message("Device bound", m, "press enter to continue");
            return 0;
        }
        // -2 means the code expired or got claimed by someone else -> regen
        // and redraw the WHOLE screen so users never see two different codes.
        // -3 means we got rate-limited; keep the same code, just back off.
        if (rc == -2) {
            gen_bind_code(code);
            bind_render(code);
        }
        ui_hint((tick++ & 1) ? "waiting..." : "waiting.   ");
        // 2s between polls -> ~3 reqs / 10s, well under the 5/10s rate limit.
        vTaskDelay(pdMS_TO_TICKS(2000));
    }
}

static void screen_settings(void);
static void screen_help(void);

// First-boot config: ask the user for the relay's ID + host, persist
// both to NVS. Returning means both values are saved AND non-empty.
// Caller is responsible for handing them to tx_init() afterwards.
static int screen_relay_setup(char *rid, size_t rid_cap,
                              char *host, size_t host_cap) {
    ui_show_message(
        "Relay setup",
        "First boot.\n"
        "I need the relay's ID\n"
        "+ host to reach the\n"
        "network.",
        "press enter to begin");

    while (1) {
        rid[0] = 0;
        if (ui_text_input("Relay ID", rid, rid_cap,
                          /*masked=*/false,
                          "from your relay; enter=ok") != 0) continue;
        // Trivial sanity: short or whitespacey IDs are typos.
        if (strlen(rid) < 4 || strchr(rid, ' ')) {
            ui_show_message("Relay ID",
                            "looks too short or\nhas whitespace.",
                            "enter to retry");
            continue;
        }

        host[0] = 0;
        if (ui_text_input("Relay host", host, host_cap,
                          /*masked=*/false,
                          "your VPS domain; enter=ok") != 0) continue;
        if (strlen(host) < 4 || strchr(host, ' ')) {
            ui_show_message("Relay host",
                            "domain looks invalid.",
                            "enter to retry");
            continue;
        }

        storage_save_relay_id(rid);
        storage_save_relay_host(host);
        return 0;
    }
}

static const tx_peer_t *screen_peer_list(tx_peer_t *peers, int *out_n) {
    while (1) {
        ui_spinner_begin("Peers", "fetching list...");
        ui_spinner_tick();
        int n = tx_get_peers(peers, TX_MAX_PEERS);
        ui_spinner_end();
        if (n < 0) {
            // Most common cause: relay returned 401 because device_token
            // was wiped server-side, or relay_id / relay_host are wrong.
            // Give the user an escape into Settings instead of looping.
            const char *items[] = {"Retry", "Settings", "Reboot"};
            int idx = ui_menu("Connection failed",
                              items, 3,
                              ";=up .=down enter=ok");
            if (idx == 1) screen_settings();
            else if (idx == 2) esp_restart();
            continue;
        }
        // Top of the menu: Help + Settings. Then peers.
        char *labels[TX_MAX_PEERS + 2];
        labels[0] = (char *)malloc(40);
        labels[1] = (char *)malloc(40);
        snprintf(labels[0], 40, ".. Help");
        snprintf(labels[1], 40, ".. Settings");
        for (int i = 0; i < n; i++) {
            labels[i + 2] = (char *)malloc(40);
            snprintf(labels[i + 2], 40, "%s", peers[i].name);
        }
        int idx = ui_menu(n == 0 ? "No peers yet" : "Pick a peer",
                          (const char *const *)labels, n + 2,
                          ";up  .down  enter");
        for (int i = 0; i < n + 2; i++) free(labels[i]);
        if (idx < 0) continue;       // rescan via backtick
        if (idx == 0) { screen_help();     continue; }
        if (idx == 1) { screen_settings(); continue; }
        if (n == 0) continue;
        *out_n = n;
        return &peers[idx - 2];
    }
}

static void screen_help(void) {
    display_clear(COL_BLACK);
    ui_title("Keys");
    int y = UI_BODY_Y;
    display_draw_str(8,  y,      ";  up         .  down",  COL_PAPER,  COL_BLACK);
    display_draw_str(8,  y + 16, ",  left       /  right", COL_PAPER,  COL_BLACK);
    display_draw_str(8,  y + 32, "enter = send / open",    COL_GREEN,  COL_BLACK);
    display_draw_str(8,  y + 48, "`  back / cancel",       COL_NOISEBOX,COL_BLACK);
    display_draw_str(8,  y + 64, "Aa = caps / @!#",        COL_GRAY,   COL_BLACK);
    ui_hint("press enter to go back");
    while (1) {
        key_event_t e;
        if (kbd_poll(&e)) {
            if (e.kind == KEY_EV_ENTER || e.kind == KEY_EV_ESC) return;
            if (e.kind == KEY_EV_CHAR && e.ch == '`') return;
        }
        vTaskDelay(pdMS_TO_TICKS(20));
    }
}

static void screen_settings(void) {
    while (1) {
        const char *items[] = {
            "Re-setup relay",
            "Forget Wi-Fi",
            "Unbind device",
            "Wipe everything",
            "Back",
        };
        int idx = ui_menu("Settings", items, 5,
                          "; up  . down  enter=ok  ` =back");
        if (idx < 0 || idx == 4) return;
        if (idx == 0) {
            // Wipe the saved relay id + host AND the device binding (the
            // device_token was issued by THAT relay, useless on a new one).
            // Wi-Fi is preserved on purpose.
            storage_save_relay_id("");
            storage_save_relay_host("");
            storage_forget_binding();
            ui_show_message("Relay re-setup",
                            "relay config cleared.\nrebooting to setup...",
                            "enter to reboot");
            esp_restart();
        }
        if (idx == 1) {
            wifi_clear_saved();
            ui_show_message("Wi-Fi", "saved network forgotten.\nrebooting...",
                            "enter to reboot");
            esp_restart();
        }
        if (idx == 2) {
            // Unbind is single-confirm: only loses the bot pairing, not chats.
            storage_forget_binding();
            ui_show_message("Unbind",
                            "device binding cleared.\nNew /pair code on next boot.\nrebooting...",
                            "enter to reboot");
            esp_restart();
        }
        if (idx == 3) {
            // Factory reset is destructive AND silent on the peer side
            // (peers see your identity disappear and a new one show up).
            // Require typed confirmation so a fat finger can't trigger it.
            char confirm[8] = {0};
            int rc = ui_text_input("Wipe everything",
                                   confirm, sizeof confirm, false,
                                   "type WIPE then enter, ` =cancel");
            if (rc != 0) continue;
            if (strcmp(confirm, "WIPE") != 0) {
                ui_show_message("Wipe cancelled",
                                "didn't match 'WIPE'", "enter");
                continue;
            }
            storage_forget_all();
            ui_show_message("Factory reset",
                            "ALL state wiped.\nrebooting...",
                            "enter to reboot");
            esp_restart();
        }
    }
}

static int screen_handshake(int64_t peer_id, const char *peer_name) {
    if (session_begin(peer_id) != 0) {
        ui_show_message("Handshake", "session_begin failed", "");
        return -1;
    }
    ui_spinner_begin("Handshake", peer_name);
    ui_spinner_tick();

    // Skip backlog in the inbox so we only react to the peer's fresh HELLO
    // for THIS handshake (relay keeps old HELLOs from earlier test runs).
    uint32_t after = 0;
    tx_get_head_id(&after);

    char b64[256];
    if (session_make_hello_b64(b64, sizeof b64) != 0) {
        ui_show_message("Handshake", "make_hello failed", "");
        return -2;
    }
    int sr = tx_send(peer_id, b64);
    if (sr != 0) {
        // 401 = bad device_token, 409 = no business_connection / not_a_peer,
        // 502 = telegram error. Show the user something more actionable.
        ui_show_message("Handshake",
                        "Could not send HELLO.\n"
                        "Check: bot has Business\n"
                        "Mode connected, and you\n"
                        "are paired with peer.",
                        "press enter to go back");
        return -3;
    }
    // Wait for the peer's HELLO. Track real wall-clock time via tick
    // counts — naive +200ms per iter is wrong because tx_poll long-polls
    // up to 10 s, which would push the effective timeout into the tens
    // of minutes. 30 s is more than enough for an awake peer; longer
    // than that and the friend almost certainly doesn't have a Cardputer
    // flashed (and they're staring at base64 in Telegram, sorry).
    tx_msg_t in[4];
    const int HANDSHAKE_TIMEOUT_MS = 30000;
    TickType_t start_tick = xTaskGetTickCount();
    while (!session_both_hellos()) {
        ui_spinner_tick();
        int got = tx_poll(&after, in, 4, 5);   // 5-s long-poll, smaller
        if (got > 0) {
            for (int i = 0; i < got; i++) {
                if (in[i].from != peer_id) continue;
                char tmp[16];
                int rc = session_decode_incoming(in[i].text, tmp, sizeof tmp);
                if (rc == 2) ESP_LOGI(TAG, "got peer HELLO");
            }
        }
        key_event_t e;
        if (kbd_poll(&e) && e.kind == KEY_EV_ESC) return -1;
        int elapsed_ms = (int)((xTaskGetTickCount() - start_tick) *
                               portTICK_PERIOD_MS);
        if (elapsed_ms > HANDSHAKE_TIMEOUT_MS) {
            ui_show_message("Handshake",
                            "No reply in 30s.\n"
                            "Friend may not have a\n"
                            "Cardputer flashed, or\n"
                            "they're offline.",
                            "enter to go back");
            return -4;
        }
        vTaskDelay(pdMS_TO_TICKS(200));
    }

    const char *sas[5];
    if (session_finalise(sas) != 0) {
        ui_show_message("Handshake", "finalise failed", "");
        return -5;
    }
    static const char *names[32] = {
        "DOG","CAT","MOUSE","RABBIT","FOX","BEAR","PANDA","LION",
        "TIGER","HORSE","UNICORN","COW","PIG","FROG","OCTO","FISH",
        "CACTUS","TREE","SUN","APPLE","LEMON","STRAW","WATERM","PIZZA",
        "ROCKET","CAR","ANCHOR","KEY","BELL","GUITAR","DIE","STAR",
    };
    const char *sas_text[5];
    for (int i = 0; i < 5; i++) {
        int idx = 0;
        for (int j = 0; j < 32; j++) if (sas[i] == SAS_ALPHABET[j]) { idx = j; break; }
        sas_text[i] = names[idx];
    }

    display_clear(COL_BLACK);
    ui_title("Compare SAS");
    char joined[64];
    snprintf(joined, sizeof joined, "%s %s %s",
             sas_text[0], sas_text[1], sas_text[2]);
    display_center_str(UI_BODY_Y + 12, joined, COL_NOISEBOX, COL_BLACK);
    snprintf(joined, sizeof joined, "%s %s", sas_text[3], sas_text[4]);
    display_center_str(UI_BODY_Y + 36, joined, COL_NOISEBOX, COL_BLACK);
    ui_hint("y = match, n = mismatch");

    while (1) {
        key_event_t e;
        if (kbd_poll(&e)) {
            if (e.kind == KEY_EV_CHAR) {
                if (e.ch == 'y' || e.ch == 'Y') { session_confirm_sas(); return 0; }
                if (e.ch == 'n' || e.ch == 'N') return -6;
            }
            if (e.kind == KEY_EV_ESC) return -6;
        }
        vTaskDelay(pdMS_TO_TICKS(20));
    }
}

#define CHAT_LINES   4
static char s_chat_lines[CHAT_LINES][48];
static int  s_chat_top = 0;

static void chat_clear(void) {
    for (int i = 0; i < CHAT_LINES; i++) s_chat_lines[i][0] = 0;
    s_chat_top = 0;
}

static void chat_push(char marker, const char *text) {
    char *dest = s_chat_lines[s_chat_top % CHAT_LINES];
    snprintf(dest, sizeof s_chat_lines[0], "%c %s", marker, text);
    s_chat_top++;
}

static void chat_render_input(int input_y, const char *typed, int typed_len) {
    display_fill_rect(0, input_y, LCD_W, 18, COL_BLACK);
    display_draw_str(2, input_y, "> ", COL_NOISEBOX, COL_BLACK);
    int max_chars = (LCD_W - 18) / 8;
    int start_x = typed_len > max_chars - 1 ? typed_len - max_chars + 1 : 0;
    display_draw_str(18, input_y, typed + start_x, COL_PAPER, COL_BLACK);
    int caret_chars = typed_len - start_x;
    int cx = 18 + caret_chars * 8;
    if (cx < LCD_W) display_fill_rect(cx, input_y + 14, 7, 2, COL_PAPER);
}

static void chat_render_history(void) {
    display_fill_rect(0, UI_BODY_Y, LCD_W, UI_BODY_H, COL_BLACK);
    int y = UI_BODY_Y;
    int start = s_chat_top - CHAT_LINES;
    if (start < 0) start = 0;
    for (int i = start; i < s_chat_top; i++) {
        const char *l = s_chat_lines[i % CHAT_LINES];
        color_t fg = (l[0] == '>') ? COL_GREEN : COL_PAPER;
        display_draw_str(2, y, l, fg, COL_BLACK);
        y += 16;
    }
}

static void chat_render(int input_y, const char *typed, int typed_len) {
    chat_render_history();
    chat_render_input(input_y, typed, typed_len);
}

// --- chat network task: long-polls the relay in the background ------------

typedef struct {
    int64_t  from;
    uint32_t msg_id;
    char     text[SESSION_MAX_CIPHER];
} chat_inbox_msg_t;

static QueueHandle_t s_chat_q       = NULL;
static TaskHandle_t  s_chat_net_h   = NULL;
static volatile bool s_chat_net_run = false;
static int64_t       s_chat_peer_id = 0;

static void chat_net_task(void *arg) {
    uint32_t after = (uint32_t)(uintptr_t)arg;
    while (s_chat_net_run) {
        tx_msg_t in[4];
        // Long-poll. The HTTP call blocks this task ~25s waiting for the
        // server; FreeRTOS runs the UI task while we wait.
        int got = tx_poll(&after, in, 4, /*timeout_s=*/20);
        if (!s_chat_net_run) break;
        for (int i = 0; i < got; i++) {
            if (in[i].from != s_chat_peer_id) continue;
            chat_inbox_msg_t m;
            m.from   = in[i].from;
            m.msg_id = in[i].id;
            strncpy(m.text, in[i].text, sizeof m.text - 1);
            m.text[sizeof m.text - 1] = 0;
            xQueueSend(s_chat_q, &m, pdMS_TO_TICKS(50));
        }
    }
    s_chat_net_h = NULL;
    vTaskDelete(NULL);
}

static void chat_net_start(int64_t peer_id, uint32_t initial_after) {
    if (!s_chat_q) {
        s_chat_q = xQueueCreate(8, sizeof(chat_inbox_msg_t));
    }
    s_chat_peer_id = peer_id;
    s_chat_net_run = true;
    xTaskCreatePinnedToCore(chat_net_task, "chat_net",
                            8192, (void *)(uintptr_t)initial_after,
                            5, &s_chat_net_h, 0);  // CPU0; UI lives on app_main's core
}

static void chat_net_stop(void) {
    s_chat_net_run = false;
    // Wait for the task to terminate.  tx_poll may block up to ~20s; we
    // give it generous time.  In practice the network goroutine exits
    // promptly once HTTP returns.
    for (int i = 0; i < 50 && s_chat_net_h; i++) {
        vTaskDelay(pdMS_TO_TICKS(100));
    }
    // Drain any leftover queue items.
    if (s_chat_q) {
        chat_inbox_msg_t tmp;
        while (xQueueReceive(s_chat_q, &tmp, 0) == pdTRUE) { /* discard */ }
    }
}

static int screen_chat(int64_t peer_id, const char *peer_name) {
    chat_clear();
    display_clear(COL_BLACK);
    ui_title(peer_name);
    ui_hint("enter=send  ` =back");
    int input_y = UI_HINT_Y - 18;
    char typed[64] = {0};
    int  typed_len = 0;
    chat_render(input_y, typed, typed_len);

    // Start the network task at the last message we already persisted, so
    // any messages the peer sent while we were powered off get delivered
    // and decrypted as soon as we enter chat.
    uint32_t after = session_last_seen(peer_id);
    chat_net_start(peer_id, after);

    uint32_t persisted_last_seen = after;
    while (1) {
        // 1) Drain network-task queue (non-blocking).
        chat_inbox_msg_t inmsg;
        bool got_inbound = false;
        while (xQueueReceive(s_chat_q, &inmsg, 0) == pdTRUE) {
            // A stale net task from a previous chat session may still be
            // running and dropping messages into the queue. Discard
            // anything that isn't from this screen's peer.
            if (inmsg.from != peer_id) continue;
            char pt[SESSION_MAX_PLAINTEXT + 1];
            int rc = session_decode_incoming(inmsg.text, pt, sizeof pt);
            if (rc == 1) {
                chat_push('<', pt);
                got_inbound = true;
                if (inmsg.msg_id > persisted_last_seen) {
                    persisted_last_seen = inmsg.msg_id;
                }
            } else if (rc == -5) {
                // Peer (or attacker) sent a fresh HELLO mid-session.
                // Tell the user; do NOT auto-rekey.
                chat_push('!', "peer reset - re-pair needed");
                got_inbound = true;
            }
        }
        if (got_inbound) {
            chat_render(input_y, typed, typed_len);
            session_persist(peer_id, persisted_last_seen);
        }

        // 2) Keyboard.
        key_event_t e;
        if (kbd_poll(&e)) {
            if (e.kind == KEY_EV_ESC) {
                chat_net_stop();
                session_persist(peer_id, persisted_last_seen);
                return 0;
            }
            if (e.kind == KEY_EV_ENTER) {
                if (typed_len > 0) {
                    char ct[SESSION_MAX_CIPHER];
                    if (session_encrypt_b64(typed, ct, sizeof ct) == 0) {
                        // Persist BEFORE the network send so we never
                        // re-use a ratchet counter on a power glitch.
                        session_persist(peer_id, persisted_last_seen);
                        if (tx_send(peer_id, ct) == 0) {
                            chat_push('>', typed);
                        } else {
                            chat_push('!', "send failed");
                        }
                    } else {
                        chat_push('!', "encrypt failed");
                    }
                    typed_len = 0; typed[0] = 0;
                    chat_render(input_y, typed, typed_len);
                }
            } else if (e.kind == KEY_EV_BACKSPACE) {
                if (typed_len > 0) {
                    typed[--typed_len] = 0;
                    chat_render_input(input_y, typed, typed_len);
                }
            } else if (e.kind == KEY_EV_CHAR || e.kind == KEY_EV_SPACE) {
                // Backtick = back (same convention as menus).
                if (e.ch == '`') {
                    chat_net_stop();
                    session_persist(peer_id, persisted_last_seen);
                    return 0;
                }
                if (typed_len < (int)sizeof typed - 1) {
                    typed[typed_len++] = e.ch;
                    typed[typed_len] = 0;
                    chat_render_input(input_y, typed, typed_len);
                }
            }
            continue;
        }
        vTaskDelay(pdMS_TO_TICKS(15));
    }
}


// --------------------------------------------------------------- top-level --

void app_main(void) {
    vTaskDelay(pdMS_TO_TICKS(1500));

    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ESP_ERROR_CHECK(nvs_flash_init());
    } else {
        ESP_ERROR_CHECK(err);
    }
    ESP_LOGI(TAG, "NoiseBox booting (%s %s)", __DATE__, __TIME__);

    if (display_init() != 0) {
        ESP_LOGE(TAG, "display init failed");
        while (1) vTaskDelay(pdMS_TO_TICKS(1000));
    }
    if (kbd_init() != 0) {
        ui_show_message("Keyboard", "init failed - reboot", "press enter");
    }

    // Boot splash: brand mark + wordmark. User dismisses with enter.
    ui_splash();

    load_user_chat_id(&g_user_chat_id);
    ESP_LOGI(TAG, "user_chat_id loaded: %lld", (long long)g_user_chat_id);

    if (screen_wifi() != 0) {
        ui_show_message("Wi-Fi", "no network", "");
        while (1) vTaskDelay(pdMS_TO_TICKS(1000));
    }

    // Resolve relay configuration. Priority:
    //   1. NVS (set by a previous run of screen_relay_setup), OR
    //   2. compile-time NOISE_RELAY_ID / NOISE_RELAY_HOST defaults from
    //      config.h, if those look like real values (not placeholders), OR
    //   3. show the first-boot setup screen.
    static char s_relay_id[96];
    static char s_relay_host[96];
    if (storage_load_relay_id(s_relay_id, sizeof s_relay_id) != 0
            || s_relay_id[0] == 0) {
        strncpy(s_relay_id, NOISE_RELAY_ID, sizeof s_relay_id - 1);
    }
    if (storage_load_relay_host(s_relay_host, sizeof s_relay_host) != 0
            || s_relay_host[0] == 0) {
        strncpy(s_relay_host, NOISE_RELAY_HOST, sizeof s_relay_host - 1);
    }
    bool id_placeholder   = (s_relay_id[0] == 0)
                          || (strstr(s_relay_id, "XXXX") != NULL);
    bool host_placeholder = (s_relay_host[0] == 0)
                          || (strstr(s_relay_host, "example.com") != NULL);
    if (id_placeholder || host_placeholder) {
        screen_relay_setup(s_relay_id, sizeof s_relay_id,
                           s_relay_host, sizeof s_relay_host);
    }
    ESP_LOGI(TAG, "relay host=%s id=%s", s_relay_host, s_relay_id);
    tx_init(s_relay_host, s_relay_id);

    // Load the per-device bearer token issued by the relay at /pair time.
    // Until this is set, only /bind_poll (authenticated by the public
    // relay_id) is usable.
    char dev_tok[96] = {0};
    if (storage_load_device_token(dev_tok, sizeof dev_tok) == 0) {
        tx_set_device_token(dev_tok);
        ESP_LOGI(TAG, "device token loaded");
    }

    if (g_user_chat_id == 0 || dev_tok[0] == 0) {
        if (screen_bind() != 0) esp_restart();
    }

    tx_peer_t peers[TX_MAX_PEERS];
    int n_peers = 0;
    while (1) {
        const tx_peer_t *sel = screen_peer_list(peers, &n_peers);
        if (!sel) continue;

        // Fast path: if we already paired with this peer in a previous
        // session, resume the saved ratchet state and skip the handshake.
        if (session_resume(sel->user_id) == 0) {
            ESP_LOGI(TAG, "resumed session with peer %lld",
                     (long long)sel->user_id);
            screen_chat(sel->user_id, sel->name);
            continue;
        }

        int rc = screen_handshake(sel->user_id, sel->name);
        if (rc != 0) continue;
        // Fresh handshake just completed - persist baseline state.
        session_persist(sel->user_id, 0);
        screen_chat(sel->user_id, sel->name);
    }
}
