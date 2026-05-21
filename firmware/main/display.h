// SPDX-License-Identifier: AGPL-3.0-or-later
// NoiseBox -- end-to-end encrypted Cardputer messenger.
// Copyright (C) 2026 Kamronbek B. See LICENSE for the full text.

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "hw_pins.h"  // re-export LCD_W / LCD_H

#ifdef __cplusplus
extern "C" {
#endif

// 16-bit color helpers (RGB565, big-endian as ST7789 expects).
typedef uint16_t color_t;

static inline color_t rgb565(uint8_t r, uint8_t g, uint8_t b) {
    return (color_t)(((r & 0xF8) << 8) | ((g & 0xFC) << 3) | (b >> 3));
}

#define COL_BLACK   0x0000
#define COL_WHITE   0xFFFF
#define COL_RED     0xF800
#define COL_GREEN   0x07E0
#define COL_BLUE    0x001F
#define COL_YELLOW  0xFFE0
#define COL_CYAN    0x07FF
#define COL_MAGENTA 0xF81F
#define COL_GRAY    0x7BEF
#define COL_DARKBLUE  0x0010

// Brand: pixel-art "noisebox" mark — paper (#efece6) on ink (#0b0b0d).
// On the device we use COL_BLACK as ink (pure 0 cheaper than #0b0b0d) and
// COL_PAPER as the highlight / default text color.
#define COL_PAPER     0xEF7C   // RGB565 of #efece6 (warm off-white)
#define COL_INK       0x0841   // RGB565 of #0b0b0d (near-black)
#define COL_DIM       0x528A   // dimmer paper for hints
#define COL_NOISEBOX  COL_PAPER  // kept for backward-compat; now == paper

// Bring up the display: SPI bus, panel reset, backlight on.
// Returns 0 on success.
int  display_init(void);

// Turn the backlight on/off (also gates the RGB LED behind the same rail).
void display_backlight(bool on);

// Fill a rectangle in RGB565 color.
void display_fill_rect(int x, int y, int w, int h, color_t color);

// Clear the entire screen.
void display_clear(color_t color);

// Draw a single 8x16 character at (x, y) in fg over bg.  Characters out
// of the supported ASCII range (32..126) draw a hatched glyph.
void display_draw_char(int x, int y, char c, color_t fg, color_t bg);

// Draw a NUL-terminated string starting at (x, y).  No wrapping.
void display_draw_str(int x, int y, const char *s, color_t fg, color_t bg);

// Same but breaks at the right edge, advancing line by line.
void display_draw_str_wrap(int x, int y, int max_x,
                           const char *s, color_t fg, color_t bg);

// Push a raw RGB565 bitmap to a rectangle. data is in row-major order,
// w*h pixels.  Used by the framebuffer flush path.
void display_blit_rgb565(int x, int y, int w, int h, const color_t *data);

// Convenience: stretch a centered string on a line of height 16 px.
void display_center_str(int y, const char *s, color_t fg, color_t bg);

#ifdef __cplusplus
}
#endif
