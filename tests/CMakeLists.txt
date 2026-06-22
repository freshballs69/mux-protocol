# Unit tests. Each test is a standalone binary returning non-zero on failure.

add_executable(test_frame test_frame.c)
target_link_libraries(test_frame PRIVATE mux)
add_test(NAME frame COMMAND test_frame)

add_executable(test_session test_session.c)
target_link_libraries(test_session PRIVATE mux)
add_test(NAME session COMMAND test_session)

# ---- fuzz targets ----
# Prefer real coverage-guided libFuzzer when the toolchain ships it
# (mainline clang / brew llvm). Fall back to the portable standalone driver
# (random-feed + corpus replay under ASan/UBSan) on toolchains without it
# (e.g. Apple clang), so `ctest` still exercises the parser everywhere.
include(CheckCSourceCompiles)
set(CMAKE_REQUIRED_FLAGS "-fsanitize=fuzzer")
check_c_source_compiles(
  "int LLVMFuzzerTestOneInput(const unsigned char*a,unsigned long b){(void)a;(void)b;return 0;}"
  MUX_HAVE_LIBFUZZER)
unset(CMAKE_REQUIRED_FLAGS)

add_executable(fuzz_frame fuzz/fuzz_frame.c)
target_link_libraries(fuzz_frame PRIVATE mux)

if(MUX_HAVE_LIBFUZZER)
  target_compile_options(fuzz_frame PRIVATE -fsanitize=fuzzer)
  target_link_options(fuzz_frame PRIVATE -fsanitize=fuzzer)
  # Quick smoke run in CTest; real campaigns invoke the binary directly.
  add_test(NAME fuzz_frame COMMAND fuzz_frame -runs=100000 -max_len=512)
else()
  target_sources(fuzz_frame PRIVATE fuzz/standalone_main.c)
  add_test(NAME fuzz_frame COMMAND fuzz_frame)
endif()
