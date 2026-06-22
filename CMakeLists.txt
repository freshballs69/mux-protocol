cmake_minimum_required(VERSION 3.20)
project(mux C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)  # for clangd / IDE

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Debug)
endif()

add_compile_options(-Wall -Wextra -Wconversion -Wsign-conversion)

# Sanitizers on by default for Debug; CI runs unit + fuzz under ASan/UBSan.
option(MUX_SANITIZE "Build with AddressSanitizer + UndefinedBehaviorSanitizer" ON)
if(MUX_SANITIZE AND CMAKE_BUILD_TYPE STREQUAL "Debug")
  add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
  add_link_options(-fsanitize=address,undefined)
endif()

# ---- libmux core ----
add_library(mux STATIC
  libmux/src/frame.c
  libmux/src/session.c
)
target_include_directories(mux PUBLIC libmux/include)

# ---- common: daemon-side helpers (auth, etc.) ----
add_library(muxcommon STATIC
  common/auth.c
)
target_include_directories(muxcommon PUBLIC common)

# ---- tests ----
enable_testing()
add_subdirectory(tests)
