// SPDX-License-Identifier: AGPL-3.0-or-later
// NoiseBox -- end-to-end encrypted Cardputer messenger.
// Copyright (C) 2026 Kamronbek B. See LICENSE for the full text.

// Cardputer-Adv keyboard: TCA8418 over I2C.
//
// Hardware: 56 keys (4 rows x 14 cols visual layout), wired through the
// TCA8418 8x10 keypad scanner configured as a 7-row x 8-col matrix.
//
// The raw (raw_row, raw_col) reported by the chip is remapped to the
// visual (row, col) using the same formula as the M5 reference firmware:
//     col_visual = raw_row * 2 + (raw_col > 3 ? 1 : 0)
//     row_visual = (raw_col + 4) % 4
//
// The keymap table is ported verbatim from m5stack/M5Cardputer-UserDemo
// (branch CardputerADV, main/hal/keyboard/keyboard.cpp, MIT licensed).
//
// We expose a simple kbd_poll() returning logical key events with
// modifier-aware character translation (shift, fn).

#include "keyboard.h"

#include <stdio.h>
#include <string.h>

#include "driver/gpio.h"
#include "driver/i2c_master.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "hw_pins.h"

static const char *TAG = "kbd";

// ---- TCA8418 register definitions (subset we use) ----
#define TCA8418_ADDR             0x34
#define REG_CFG                  0x01
#define REG_INT_STAT             0x02
#define REG_KEY_LCK_EC           0x03
#define REG_KEY_EVENT_A          0x04
#define REG_KP_GPIO_1            0x1D
#define REG_KP_GPIO_2            0x1E
#define REG_KP_GPIO_3            0x1F
#define REG_DEBOUNCE_DIS_1       0x29
#define REG_DEBOUNCE_DIS_2       0x2A
#define REG_DEBOUNCE_DIS_3       0x2B

#define CFG_AI                   (1 << 7)  // auto-increment
#define CFG_GPI_E_CFG_LEVEL      (0 << 6)
#define CFG_OVR_FLOW_M           (1 << 5)
#define CFG_INT_CFG              (1 << 4)
#define CFG_GPI_IEN              (1 << 1)
#define CFG_KE_IEN               (1 << 0)

static i2c_master_bus_handle_t s_bus = NULL;
static i2c_master_dev_handle_t s_dev = NULL;
static volatile bool s_int_flag = true;  // start polling once on boot

// ---- low-level I2C ----

static esp_err_t reg_read(uint8_t reg, uint8_t *out, size_t n) {
    return i2c_master_transmit_receive(s_dev, &reg, 1, out, n,
                                       pdMS_TO_TICKS(50));
}
static esp_err_t reg_write(uint8_t reg, uint8_t v) {
    uint8_t b[2] = {reg, v};
    return i2c_master_transmit(s_dev, b, 2, pdMS_TO_TICKS(50));
}

// ---- interrupt ----

static void IRAM_ATTR isr_handler(void *arg) {
    s_int_flag = true;
}

// ---- keymap (ported from m5stack reference) ----

typedef struct {
    const char *firstName;
    const char *secondName;
    const char *fnName;     // NULL = no Fn override
    uint8_t fnExtraShift;   // 1 if Fn implies shift (so letter -> uppercase)
} kv_t;

#define K(a,b,fn,extra) { a, b, fn, extra }

static const kv_t keymap[4][14] = {
    // Row 0 (top): `1234567890-= del
    {
        K("`",  "~",  "esc",  0), K("1","!",NULL,0), K("2","@",NULL,0),
        K("3","#",NULL,0), K("4","$",NULL,0), K("5","%",NULL,0),
        K("6","^",NULL,0), K("7","&",NULL,0), K("8","*",NULL,0),
        K("9","(",NULL,0), K("0",")",NULL,0),
        K("-","_",NULL,0), K("=","+",NULL,0),
        K("del","del","del",0),
    },
    // Row 1: tab QWERTYUIOP [ ] (backslash)
    {
        K("tab","tab",NULL,0),
        K("q","Q","Q",1), K("w","W","W",1), K("e","E","E",1),
        K("r","R","R",1), K("t","T","T",1), K("y","Y","Y",1),
        K("u","U","U",1), K("i","I","I",1), K("o","O","O",1),
        K("p","P","P",1),
        K("[","{",NULL,0), K("]","}",NULL,0),
        K("\\","|",NULL,0),
    },
    // Row 2: fn shift ASDFGHJKL ; ' enter
    {
        K("fn","fn",NULL,0), K("shift","shift",NULL,0),
        K("a","A","A",1), K("s","S","S",1), K("d","D","D",1),
        K("f","F","F",1), K("g","G","G",1), K("h","H","H",1),
        K("j","J","J",1), K("k","K","K",1), K("l","L","L",1),
        K(";",":","up",0),  K("'","\"",NULL,0),
        K("enter","enter",NULL,0),
    },
    // Row 3: ctrl opt alt ZXCVBNM ,./ space
    {
        K("ctrl","ctrl",NULL,0), K("opt","opt",NULL,0), K("alt","alt",NULL,0),
        K("z","Z","Z",1), K("x","X","X",1), K("c","C","C",1),
        K("v","V","V",1), K("b","B","B",1), K("n","N","N",1),
        K("m","M","M",1),
        K(",","<","left",0), K(".",">","down",0), K("/","?","right",0),
        K(" "," ",NULL,0),
    },
};
#undef K

static bool s_shift = false;
static bool s_fn    = false;
static bool s_ctrl  = false;

static kbd_raw_cb_t s_raw_cb = NULL;
void kbd_set_raw_cb(kbd_raw_cb_t cb) { s_raw_cb = cb; }

// ---- init ----

int kbd_init(void) {
    // I2C master bus (shared with IMU, but the IMU isn't initialised yet).
    i2c_master_bus_config_t bcfg = {
        .i2c_port = I2C_NUM_0,
        .sda_io_num = PIN_I2C_SDA,
        .scl_io_num = PIN_I2C_SCL,
        .clk_source = I2C_CLK_SRC_DEFAULT,
        .glitch_ignore_cnt = 7,
        .flags.enable_internal_pullup = true,
    };
    esp_err_t err = i2c_new_master_bus(&bcfg, &s_bus);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "i2c bus: %d", err);
        return -1;
    }
    i2c_device_config_t dcfg = {
        .dev_addr_length = I2C_ADDR_BIT_LEN_7,
        .device_address = TCA8418_ADDR,
        .scl_speed_hz = I2C_FREQ_HZ,
    };
    err = i2c_master_bus_add_device(s_bus, &dcfg, &s_dev);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "i2c add dev: %d", err);
        return -2;
    }

    // Configure TCA8418: 7 rows x 8 cols keypad area. KP_GPIO bits select
    // which pins are in keypad mode (1 = keypad).
    reg_write(REG_KP_GPIO_1, 0xFF);  // rows 0..7 all enabled
    reg_write(REG_KP_GPIO_2, 0xFF);  // cols 0..7 all enabled
    reg_write(REG_KP_GPIO_3, 0x00);  // cols 8..9 unused

    // Disable debounce for all keypad pins (driver in M5 does this too).
    reg_write(REG_DEBOUNCE_DIS_1, 0xFF);
    reg_write(REG_DEBOUNCE_DIS_2, 0xFF);
    reg_write(REG_DEBOUNCE_DIS_3, 0xFF);

    // Enable keypad event interrupts.
    reg_write(REG_CFG, CFG_KE_IEN | CFG_OVR_FLOW_M | CFG_INT_CFG | CFG_AI);

    // Drain any queued events from a previous run.
    uint8_t lck = 0;
    reg_read(REG_KEY_LCK_EC, &lck, 1);
    for (uint8_t i = 0; i < (lck & 0x0F); i++) {
        uint8_t ev = 0;
        reg_read(REG_KEY_EVENT_A, &ev, 1);
    }
    reg_write(REG_INT_STAT, 0x01);

    // GPIO interrupt for KBD_INT line.
    gpio_config_t ioc = {
        .pin_bit_mask = 1ULL << PIN_KBD_INT,
        .mode = GPIO_MODE_INPUT,
        .intr_type = GPIO_INTR_NEGEDGE,
    };
    gpio_config(&ioc);
    gpio_install_isr_service(ESP_INTR_FLAG_IRAM);
    gpio_isr_handler_add(PIN_KBD_INT, isr_handler, NULL);

    ESP_LOGI(TAG, "TCA8418 ready");
    return 0;
}

// Map raw (raw_row, raw_col) from TCA8418 to visual (row, col) per M5 logic.
static void remap_raw(uint8_t raw_row, uint8_t raw_col, uint8_t *out_row, uint8_t *out_col) {
    uint8_t col = raw_row * 2 + (raw_col > 3 ? 1 : 0);
    uint8_t row = (raw_col + 4) % 4;
    *out_row = row;
    *out_col = col;
}

// Read one pending event from TCA8418 if any. Returns 1 if an event was
// produced, 0 otherwise.
static int read_event(uint8_t *out_row, uint8_t *out_col, bool *out_pressed) {
    uint8_t ev = 0;
    if (reg_read(REG_KEY_EVENT_A, &ev, 1) != ESP_OK) return 0;
    if (ev == 0) return 0;  // no event
    bool pressed = (ev & 0x80) != 0;
    uint8_t code = (ev & 0x7F);
    if (code == 0) return 0;
    code -= 1;
    uint8_t raw_row = code / 10;
    uint8_t raw_col = code % 10;
    remap_raw(raw_row, raw_col, out_row, out_col);
    *out_pressed = pressed;
    return 1;
}

int kbd_poll(key_event_t *out) {
    out->kind = KEY_EV_NONE;
    out->ch = 0;

    // Always check, even without interrupt - covers the case where the
    // chip already had events queued and the INT line was already low.
    uint8_t intstat = 0;
    if (reg_read(REG_INT_STAT, &intstat, 1) == ESP_OK) {
        if (intstat & 0x01) {
            s_int_flag = true;
        }
    }
    if (!s_int_flag) return 0;

    for (int i = 0; i < 8; i++) {  // drain a few per call
        uint8_t row, col; bool pressed;
        if (!read_event(&row, &col, &pressed)) {
            // Acknowledge interrupt; if no more events, clear flag.
            reg_write(REG_INT_STAT, 0x01);
            uint8_t s = 0;
            if (reg_read(REG_INT_STAT, &s, 1) == ESP_OK && (s & 0x01) == 0) {
                s_int_flag = false;
            }
            return 0;
        }
        if (row >= 4 || col >= 14) continue;
        if (s_raw_cb) s_raw_cb(row, col, pressed);

        // Modifier tracking.
        if (row == 3 && col == 0) { s_ctrl  = pressed; continue; }
        if (row == 2 && col == 1) { s_shift = pressed; continue; }
        if (row == 2 && col == 0) { s_fn    = pressed; continue; }

        // We only generate events on press.
        if (!pressed) continue;

        const kv_t *kv = &keymap[row][col];
        const char *name;
        bool shift_eff = s_shift;
        if (s_fn && kv->fnName) {
            name = kv->fnName;
            if (kv->fnExtraShift) shift_eff = true;
        } else if (s_shift) {
            name = kv->secondName;
        } else {
            name = kv->firstName;
        }
        if (!name) continue;

        // Translate name -> key_event_t.
        if (strcmp(name, "enter") == 0)  { out->kind = KEY_EV_ENTER;     return 1; }
        if (strcmp(name, "del")   == 0)  { out->kind = KEY_EV_BACKSPACE; return 1; }
        if (strcmp(name, "tab")   == 0)  { out->kind = KEY_EV_TAB;       return 1; }
        if (strcmp(name, "esc")   == 0)  { out->kind = KEY_EV_ESC;       return 1; }
        if (strcmp(name, "up")    == 0)  { out->kind = KEY_EV_UP;        return 1; }
        if (strcmp(name, "down")  == 0)  { out->kind = KEY_EV_DOWN;      return 1; }
        if (strcmp(name, "left")  == 0)  { out->kind = KEY_EV_LEFT;      return 1; }
        if (strcmp(name, "right") == 0)  { out->kind = KEY_EV_RIGHT;     return 1; }
        if (name[0] == ' ' && name[1] == 0) {
            out->kind = KEY_EV_SPACE; out->ch = ' '; return 1;
        }
        // Single-char printable.
        if (name[0] != 0 && name[1] == 0 && name[0] >= 32 && name[0] <= 126) {
            char c = name[0];
            if (shift_eff && c >= 'a' && c <= 'z') c = c - 'a' + 'A';
            out->kind = KEY_EV_CHAR;
            out->ch = c;
            return 1;
        }
        // Two-char shifted "<", ">", "?", etc came through secondName.
        // Skip multi-character names that aren't recognised (modifier names).
    }
    return 0;
}
