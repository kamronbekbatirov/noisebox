cmake_minimum_required(VERSION 3.16)

# EXTRA_COMPONENT_DIRS will be added when we vendor M5GFX/LovyanGFX as a
# component (later, during the UI step). For now we only use built-in
# ESP-IDF components.

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(cardputer_messenger C CXX)
