// SPDX-License-Identifier: AGPL-3.0-or-later
// NoiseBox -- end-to-end encrypted Cardputer messenger.
// Copyright (C) 2026 Kamronbek B. See LICENSE for the full text.

#pragma once
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// High-level key event delivered to UI code.
typedef enum {
    KEY_EV_NONE = 0,
    KEY_EV_CHAR,        // printable ASCII char  (data = char)
    KEY_EV_ENTER,
    KEY_EV_BACKSPACE,
    KEY_EV_TAB,
    KEY_EV_ESC,
    KEY_EV_UP,
    KEY_EV_DOWN,
    KEY_EV_LEFT,
    KEY_EV_RIGHT,
    KEY_EV_DELETE,
    KEY_EV_SPACE,
} key_kind_t;

typedef struct {
    key_kind_t kind;
    char ch;            // valid for KEY_EV_CHAR
} key_event_t;

// Initialise I2C and TCA8418. Returns 0 on success.
int  kbd_init(void);

// Drain pending key-down events. Returns 1 if `out` was filled, 0 if none.
// Key-up events are consumed internally and used only to update modifiers.
int  kbd_poll(key_event_t *out);

// Optional: low-level callback if you need raw events (row, col, state) for
// debugging or to capture a custom map.
typedef void (*kbd_raw_cb_t)(uint8_t row, uint8_t col, bool pressed);
void kbd_set_raw_cb(kbd_raw_cb_t cb);

#ifdef __cplusplus
}
#endif
