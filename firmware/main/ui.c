// SPDX-License-Identifier: AGPL-3.0-or-later
// NoiseBox -- end-to-end encrypted Cardputer messenger.
// Copyright (C) 2026 Kamronbek B. See LICENSE for the full text.

// Generic UI primitives layered on top of display.* + keyboard.*

#include "ui.h"

#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#define BG          COL_BLACK
#define TITLE_BG    COL_DARKBLUE
#define TITLE_FG    COL_NOISEBOX
#define BODY_FG     COL_WHITE
#define HINT_FG     COL_GRAY
#define STATUS_FG   COL_GRAY

void ui_title(const char *text) {
    display_fill_rect(0, UI_TITLE_Y, LCD_W, UI_TITLE_H, TITLE_BG);
    display_center_str(UI_TITLE_Y + 2, text, TITLE_FG, TITLE_BG);
}

void ui_hint(const char *text) {
    display_fill_rect(0, UI_HINT_Y, LCD_W, UI_HINT_H, BG);
    if (text && text[0]) display_center_str(UI_HINT_Y, text, HINT_FG, BG);
}

void ui_status(const char *text, color_t fg) {
    display_fill_rect(0, UI_STATUS_Y, LCD_W, UI_STATUS_H, BG);
    if (text && text[0]) display_draw_str(2, UI_STATUS_Y, text, fg, BG);
}

void ui_clear_body(void) {
    display_fill_rect(0, UI_BODY_Y, LCD_W, UI_BODY_H, BG);
}

// Block-draw a multi-line string into the body area. Returns last y used.
static int draw_body_lines(const char *body) {
    int y = UI_BODY_Y;
    char line[64];
    const char *p = body;
    while (*p && y + 16 <= UI_BODY_Y + UI_BODY_H) {
        int n = 0;
        while (*p && *p != '\n' && n < (int)sizeof(line) - 1) line[n++] = *p++;
        line[n] = 0;
        display_center_str(y, line, BODY_FG, BG);
        y += 18;
        if (*p == '\n') p++;
    }
    return y;
}

void ui_show_message(const char *title, const char *body, const char *hint) {
    display_clear(BG);
    ui_title(title);
    ui_clear_body();
    if (body) draw_body_lines(body);
    ui_hint(hint && hint[0] ? hint : "press enter");
    while (1) {
        key_event_t e;
        if (kbd_poll(&e)) {
            if (e.kind == KEY_EV_ENTER || e.kind == KEY_EV_SPACE
                    || e.kind == KEY_EV_ESC) return;
        }
        vTaskDelay(pdMS_TO_TICKS(20));
    }
}

static const char *s_spin_title = "";
static const char *s_spin_status = "";
static int s_spin_phase = 0;

void ui_spinner_begin(const char *title, const char *status) {
    s_spin_title = title;
    s_spin_status = status;
    s_spin_phase = 0;
    display_clear(BG);
    ui_title(title);
    ui_hint("");
    ui_status(status, STATUS_FG);
}

void ui_spinner_tick(void) {
    static const char *frames[] = {"|", "/", "-", "\\"};
    ui_clear_body();
    int y = UI_BODY_Y + (UI_BODY_H - 16) / 2;
    int x = (LCD_W - 8) / 2;
    display_draw_str(x, y, frames[s_spin_phase & 3], COL_NOISEBOX, BG);
    s_spin_phase++;
}

void ui_spinner_end(void) {
    ui_clear_body();
}

// --- ui_menu ---

int ui_menu(const char *title, const char *const *items, int n,
            const char *hint) {
    if (n <= 0) return -1;
    int sel = 0;
    int top = 0;          // top item index displayed
    const int rows = UI_BODY_H / 18;  // ~4 rows visible

    display_clear(BG);
    ui_title(title);
    ui_hint(hint ? hint : "up/down + enter");

    while (1) {
        // Adjust scroll window.
        if (sel < top) top = sel;
        if (sel >= top + rows) top = sel - rows + 1;

        ui_clear_body();
        for (int i = 0; i < rows && top + i < n; i++) {
            int idx = top + i;
            int y = UI_BODY_Y + i * 18;
            bool cur = (idx == sel);
            color_t fg = cur ? COL_BLACK : COL_WHITE;
            color_t bg = cur ? COL_NOISEBOX : BG;
            if (cur) display_fill_rect(0, y, LCD_W, 17, bg);
            display_draw_str(8, y + 1, items[idx], fg, bg);
        }

        // Wait for key.  Accept both the proper Fn-arrows and friendly
        // ASCII shortcuts (`;` up, `.` down, `,` left, `/` right, `` ` ``
        // cancel) so the user doesn't have to hold Fn in menus.
        while (1) {
            key_event_t e;
            if (kbd_poll(&e)) {
                if (e.kind == KEY_EV_UP)   { if (sel > 0)   sel--; break; }
                if (e.kind == KEY_EV_DOWN) { if (sel < n-1) sel++; break; }
                if (e.kind == KEY_EV_ENTER) return sel;
                if (e.kind == KEY_EV_ESC)   return -1;
                if (e.kind == KEY_EV_CHAR) {
                    if (e.ch == ';') { if (sel > 0)   sel--; break; }
                    if (e.ch == '.') { if (sel < n-1) sel++; break; }
                    if (e.ch == '`') return -1;
                }
            }
            vTaskDelay(pdMS_TO_TICKS(20));
        }
    }
}

// --- ui_text_input ---

int ui_text_input(const char *title, char *buf, size_t cap, bool masked,
                  const char *hint) {
    if (cap == 0) return -1;
    buf[0] = 0;
    int len = 0;

    display_clear(BG);
    ui_title(title);
    ui_hint(hint ? hint : "type then enter, esc cancels");

    while (1) {
        // Redraw input line.
        ui_clear_body();
        int y = UI_BODY_Y + (UI_BODY_H - 16) / 2;
        display_draw_str(8, y, "> ", COL_GREEN, BG);
        if (masked) {
            char m[32];
            int shown = len < (int)sizeof(m) - 1 ? len : (int)sizeof(m) - 1;
            for (int i = 0; i < shown; i++) m[i] = '*';
            m[shown] = 0;
            display_draw_str(24, y, m, COL_WHITE, BG);
        } else {
            // Scroll horizontally if too long.
            int max_chars = (LCD_W - 24 - 8) / 8;
            int start = 0;
            if (len > max_chars - 1) start = len - max_chars + 1;
            display_draw_str(24, y, buf + start, COL_WHITE, BG);
        }
        // Caret.
        int caret_chars = (len > (LCD_W - 24 - 8) / 8 - 1)
                          ? (LCD_W - 24 - 8) / 8 - 1
                          : len;
        int cx = 24 + caret_chars * 8;
        display_fill_rect(cx, y + 14, 7, 2, COL_WHITE);

        key_event_t e;
        if (!kbd_poll(&e)) {
            vTaskDelay(pdMS_TO_TICKS(20));
            continue;
        }
        if (e.kind == KEY_EV_ESC) return -1;
        if (e.kind == KEY_EV_ENTER) { buf[len] = 0; return 0; }
        if (e.kind == KEY_EV_BACKSPACE) {
            if (len > 0) { len--; buf[len] = 0; }
            continue;
        }
        if (e.kind == KEY_EV_CHAR || e.kind == KEY_EV_SPACE) {
            // Backtick (`) alone cancels - same shortcut as the menu so
            // users don't need to learn the Fn+` combo.
            if (e.ch == '`') return -1;
            if (len < (int)cap - 1) {
                buf[len++] = e.ch;
                buf[len] = 0;
            }
        }
    }
}
