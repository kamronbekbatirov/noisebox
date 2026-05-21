// SPDX-License-Identifier: AGPL-3.0-or-later
// NoiseBox -- end-to-end encrypted Cardputer messenger.
// Copyright (C) 2026 Kamronbek B. See LICENSE for the full text.

// Generic UI primitives layered on top of display.* + keyboard.*

#include "ui.h"

#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#define BG          COL_BLACK
#define TITLE_BG    COL_BLACK
#define TITLE_FG    COL_PAPER
#define BODY_FG     COL_PAPER
#define HINT_FG     COL_DIM
#define STATUS_FG   COL_DIM

void ui_title(const char *text) {
    display_fill_rect(0, UI_TITLE_Y, LCD_W, UI_TITLE_H, TITLE_BG);
    display_center_str(UI_TITLE_Y + 2, text, TITLE_FG, TITLE_BG);
    // Hairline divider under the title — gives a terminal-statusbar feel
    // without the heavy filled bar of the old design.
    display_fill_rect(0, UI_TITLE_Y + UI_TITLE_H - 1, LCD_W, 1, COL_PAPER);
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
    display_draw_str(x, y, frames[s_spin_phase & 3], COL_PAPER, BG);
    s_spin_phase++;
}

void ui_spinner_end(void) {
    ui_clear_body();
}

// --- ui_splash + ui_draw_logo ---
//
// The NoiseBox mark is a 10x10 pixel-art grid. We store it as 10 uint16_t
// rows where bit `c` of row `r` is set iff that cell is "ink". This is the
// exact same shape as docs/brand/noisebox-mark-paper.svg /-mark-ink.svg.

static const uint16_t LOGO_ROWS[10] = {
    0x007F, // row 0: ####### . . .
    0x007F, // row 1: ####### . . .
    0x003F, // row 2: ###### . . . .
    0x007F, // row 3: ####### . . .
    0x013F, // row 4: ###### . . # .
    0x00FF, // row 5: ######## . .
    0x00BF, // row 6: ###### . # . .
    0x01FF, // row 7: ######### .
    0x005F, // row 8: ##### . # . . .
    0x00FF, // row 9: ######## . .
};

void ui_draw_logo(int x0, int y0, int cell, color_t fg) {
    // Leave a 1px gutter inside each cell so adjacent filled cells stay
    // visually distinct — matches the brand SVG's 2-unit-on-20 pixel grid
    // and avoids the "solid blob" look we'd get with a back-to-back fill.
    int block = cell > 2 ? cell - 1 : cell;
    for (int r = 0; r < 10; r++) {
        uint16_t row = LOGO_ROWS[r];
        for (int c = 0; c < 10; c++) {
            if (row & (1u << c)) {
                display_fill_rect(x0 + c * cell, y0 + r * cell,
                                  block, block, fg);
            }
        }
    }
}

void ui_splash(void) {
    display_clear(COL_BLACK);

    // Compact mark: 10 cells × 6 px = 60 px square (5 px block + 1 px
    // gutter per cell). Centred horizontally, leaves room for the
    // wordmark + hint without crowding the 240×135 LCD.
    const int cell = 6;
    const int logo_w = 10 * cell;
    int lx = (LCD_W - logo_w) / 2;
    int ly = 8;
    ui_draw_logo(lx, ly, cell, COL_PAPER);

    // Wordmark — lowercase to match the horizontal banner in the README.
    int ty = ly + logo_w + 8;
    display_center_str(ty, "noisebox", COL_PAPER, COL_BLACK);

    // Subtle hint at the bottom — dim so it doesn't compete with the mark.
    display_center_str(LCD_H - 16, "press enter", COL_DIM, COL_BLACK);

    // Animated "noise" sparks around the right edge of the silhouette.
    // (col, row, phase) — each spark is on for ON_WIDTH frames of a
    // CYCLE-frame cycle, with per-spark phase offset so the crackle
    // looks organic rather than synchronised. None of these cells lie
    // inside the core LOGO_ROWS shape, so toggling them to black never
    // erases part of the mark.
    static const uint8_t SPARKS[][3] = {
        {7, 0, 0}, {8, 1, 2}, {6, 2, 4}, {7, 3, 6},
        {9, 4, 1}, {8, 5, 3}, {8, 6, 5}, {9, 7, 7},
    };
    const int N_SPARKS  = sizeof(SPARKS) / sizeof(SPARKS[0]);
    const int CYCLE     = 12;
    const int ON_WIDTH  = 3;
    const int FRAME_MS  = 180;
    const int POLL_MS   = 20;
    const int TICKS_PER_FRAME = FRAME_MS / POLL_MS;

    int block = cell > 2 ? cell - 1 : cell;
    int frame = 0;
    int ticks = 0;
    while (1) {
        key_event_t e;
        if (kbd_poll(&e)) {
            if (e.kind == KEY_EV_ENTER || e.kind == KEY_EV_SPACE
                    || e.kind == KEY_EV_ESC) return;
            if (e.kind == KEY_EV_CHAR && (e.ch == '`' || e.ch == ' ')) return;
        }
        vTaskDelay(pdMS_TO_TICKS(POLL_MS));
        if (++ticks >= TICKS_PER_FRAME) {
            ticks = 0;
            for (int i = 0; i < N_SPARKS; i++) {
                int c  = SPARKS[i][0];
                int r  = SPARKS[i][1];
                int ph = SPARKS[i][2];
                bool on = ((frame + ph) % CYCLE) < ON_WIDTH;
                color_t col = on ? COL_PAPER : COL_BLACK;
                display_fill_rect(lx + c * cell, ly + r * cell,
                                  block, block, col);
            }
            frame++;
        }
    }
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
            // Selected row: invert (paper fill, ink text). Unselected: paper
            // text on black — keeps the mono "terminal" look.
            color_t fg = cur ? COL_BLACK : COL_PAPER;
            color_t bg = cur ? COL_PAPER : BG;
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
            display_draw_str(24, y, m, COL_PAPER, BG);
        } else {
            // Scroll horizontally if too long.
            int max_chars = (LCD_W - 24 - 8) / 8;
            int start = 0;
            if (len > max_chars - 1) start = len - max_chars + 1;
            display_draw_str(24, y, buf + start, COL_PAPER, BG);
        }
        // Caret.
        int caret_chars = (len > (LCD_W - 24 - 8) / 8 - 1)
                          ? (LCD_W - 24 - 8) / 8 - 1
                          : len;
        int cx = 24 + caret_chars * 8;
        display_fill_rect(cx, y + 14, 7, 2, COL_PAPER);

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
