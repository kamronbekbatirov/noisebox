// SPDX-License-Identifier: AGPL-3.0-or-later
// NoiseBox -- end-to-end encrypted Cardputer messenger.
// Copyright (C) 2026 Kamronbek B. See LICENSE for the full text.

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "display.h"
#include "keyboard.h"

#ifdef __cplusplus
extern "C" {
#endif

// Layout primitives.
//
// Screen is 240x135. We use four standard zones:
//   - title bar       (rows 0..18)        dark blue, brand colour
//   - body            (rows 22..104)
//   - prompt/hint     (rows 104..120)
//   - status bar      (rows 120..134)     gray

#define UI_TITLE_Y      0
#define UI_TITLE_H      20
#define UI_BODY_Y       22
#define UI_BODY_H       82
#define UI_HINT_Y       104
#define UI_HINT_H       16
#define UI_STATUS_Y     120
#define UI_STATUS_H     15

// Paint a title bar with centered text.
void ui_title(const char *text);

// Paint hint line (smaller text, dim gray on black) and status bar.
void ui_hint(const char *text);
void ui_status(const char *text, color_t fg);

// Clear the body region only (preserves title/hint/status).
void ui_clear_body(void);

// One-shot info screen. Blocks until ENTER pressed. `info` may contain
// '\n' line breaks.
void ui_show_message(const char *title, const char *body, const char *hint);

// Modal "spinner": shows title + status text and a small busy indicator.
// Caller must repeatedly call ui_spinner_tick() to animate. ui_spinner_end()
// clears the body.
void ui_spinner_begin(const char *title, const char *status);
void ui_spinner_tick(void);
void ui_spinner_end(void);

// Menu: vertical list of items, navigated with up/down, Enter selects.
// `items[]` is an array of NUL-terminated UTF-8 strings.
// Returns the chosen index, or -1 if user pressed ESC.
int  ui_menu(const char *title, const char *const *items, int n,
             const char *hint);

// Text input: prompt with title, user types, ENTER submits.
// `buf` must have at least `cap` bytes, on success holds NUL-terminated text.
// `masked` shows '*' instead of typed chars.
// Returns 0 on Enter, -1 on Esc.
int  ui_text_input(const char *title, char *buf, size_t cap,
                   bool masked, const char *hint);

// Boot splash: pixel-art NoiseBox mark + wordmark on a clean black canvas,
// waits for ENTER (or backtick) before returning. Use once on cold boot.
void ui_splash(void);

// Draw the noisebox mark at (x0, y0) using cells of `cell` px each.
// Total footprint is 10*cell px wide and 10*cell px tall.
void ui_draw_logo(int x0, int y0, int cell, color_t fg);

#ifdef __cplusplus
}
#endif
