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

# ---- common: daemon-side helpers (auth, net) ----
add_library(muxcommon STATIC
  common/auth.c
  common/net.c
)
target_include_directories(muxcommon PUBLIC common)

# ---- relay engine: shared poll() loop tying sockets to mux streams ----
add_library(muxrelay STATIC
  common/relay.c
)
target_include_directories(muxrelay PUBLIC common)
target_link_libraries(muxrelay PUBLIC mux muxcommon)

# ---- daemons ----
add_executable(edge      edge/main.c)
target_link_libraries(edge PRIVATE muxrelay)

add_executable(edge-peer edge-peer/main.c)
target_link_libraries(edge-peer PRIVATE muxrelay)

# ---- tests ----
enable_testing()
add_subdirectory(tests)
