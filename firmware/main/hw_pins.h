// SPDX-License-Identifier: AGPL-3.0-or-later
// NoiseBox -- end-to-end encrypted Cardputer messenger.
// Copyright (C) 2026 Kamronbek B. See LICENSE for the full text.

#pragma once
// Cardputer-Adv pin map (Stamp-S3A core).
// From M5Stack official documentation:
// https://docs.m5stack.com/en/core/Cardputer-Adv

// ---- LCD: ST7789V2, 240x135, SPI ----
#define PIN_LCD_BL        38   // backlight (also gates RGB LED power)
#define PIN_LCD_RST       33
#define PIN_LCD_DC        34   // data/command (RS)
#define PIN_LCD_MOSI      35
#define PIN_LCD_SCK       36
#define PIN_LCD_CS        37
#define LCD_W             240
#define LCD_H             135
// ST7789V2 inside is 240x320; the Cardputer-Adv LCD die only exposes a
// 135x240 portrait window at panel-native offset (52, 40), per M5GFX
// autodetect for board_M5CardputerADV (M5GFX.cpp line ~1898).
#define LCD_X_OFFSET      52
#define LCD_Y_OFFSET      40

// ---- I2C (shared by keyboard + IMU + audio codec) ----
#define PIN_I2C_SDA       8
#define PIN_I2C_SCL       9
#define PIN_KBD_INT       11    // TCA8418 INT
#define I2C_FREQ_HZ       400000

// ---- microSD (SPI, separate bus from LCD) ----
#define PIN_SD_CS         12
#define PIN_SD_MOSI       14
#define PIN_SD_SCK        40
#define PIN_SD_MISO       39

// ---- IR ----
#define PIN_IR_TX         44

// ---- Battery ADC ----
#define PIN_BATT_ADC      10
