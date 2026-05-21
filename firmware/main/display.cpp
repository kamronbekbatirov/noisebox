// SPDX-License-Identifier: AGPL-3.0-or-later
// NoiseBox -- end-to-end encrypted Cardputer messenger.
// Copyright (C) 2026 Kamronbek B. See LICENSE for the full text.

// LCD driver for Cardputer-Adv built on top of M5GFX.
//
// M5GFX is the C++ library M5Stack ships and uses in their official
// CardputerADV firmware - it has the autodetect + panel parameters
// (ST7789V2, 135x240 portrait native, offset 52,40, invert, PWM
// backlight on GPIO 38, 40 MHz SPI) baked in.
//
// We expose a tiny C API (declared in display.h) so the rest of the
// firmware stays C.

#include "display.h"
#include "font8x16.h"

#include <M5GFX.h>
#include <string.h>

#include "esp_log.h"

static const char *TAG = "lcd";
static M5GFX gfx;

extern "C" int display_init(void) {
    if (!gfx.begin()) {
        ESP_LOGE(TAG, "M5GFX begin() failed");
        return -1;
    }
    gfx.setRotation(1);   // 90 deg CW -> 240x135 landscape, USB on right
    gfx.fillScreen(TFT_BLACK);
    gfx.setBrightness(180);
    ESP_LOGI(TAG, "lcd ready: %dx%d", (int)gfx.width(), (int)gfx.height());
    return 0;
}

extern "C" void display_backlight(bool on) {
    gfx.setBrightness(on ? 180 : 0);
}

extern "C" void display_fill_rect(int x, int y, int w, int h, color_t color) {
    gfx.fillRect(x, y, w, h, color);
}

extern "C" void display_clear(color_t color) {
    gfx.fillScreen(color);
}

extern "C" void display_blit_rgb565(int x, int y, int w, int h, const color_t *data) {
    gfx.pushImage(x, y, w, h, data);
}

// We keep using our 8x16 bitmap font (LSB-on-left) so all the layout code
// we wrote earlier renders the same regardless of which underlying driver
// is in use.  M5GFX has nicer fonts, but consistency wins here.
static void draw_glyph(int x, int y, char c, color_t fg, color_t bg) {
    if (c < 32 || c > 126) c = '?';
    const uint8_t *g = font8x16[c - 32];
    // Render to a 8x16 staging buffer then push as one blit (fast).
    uint16_t px[8 * 16];
    for (int row = 0; row < 16; row++) {
        uint8_t bits = g[row];
        for (int col = 0; col < 8; col++) {
            px[row * 8 + col] = (bits & (1 << col)) ? fg : bg;
        }
    }
    gfx.pushImage(x, y, 8, 16, px);
}

extern "C" void display_draw_char(int x, int y, char c, color_t fg, color_t bg) {
    draw_glyph(x, y, c, fg, bg);
}

extern "C" void display_draw_str(int x, int y, const char *s, color_t fg, color_t bg) {
    if (!s) return;
    int cx = x;
    while (*s) {
        if (cx + 8 > LCD_W) break;
        draw_glyph(cx, y, *s++, fg, bg);
        cx += 8;
    }
}

extern "C" void display_draw_str_wrap(int x, int y, int max_x,
                                       const char *s, color_t fg, color_t bg) {
    if (!s) return;
    int cx = x, cy = y;
    while (*s) {
        if (*s == '\n' || cx + 8 > max_x) {
            cx = x; cy += 16;
            if (cy + 16 > LCD_H) return;
            if (*s == '\n') { s++; continue; }
        }
        draw_glyph(cx, cy, *s++, fg, bg);
        cx += 8;
    }
}

extern "C" void display_center_str(int y, const char *s, color_t fg, color_t bg) {
    int n = (int)strlen(s);
    int w = n * 8;
    int x = (LCD_W - w) / 2;
    if (x < 0) x = 0;
    display_draw_str(x, y, s, fg, bg);
}
